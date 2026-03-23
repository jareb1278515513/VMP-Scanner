from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import html
import requests

from scanner.detection.base import DetectionPlugin
from scanner.detection.payloads import PayloadDictionaryManager


class ReflectedXssPlugin(DetectionPlugin):
    def metadata(self) -> dict:
        return {
            "name": "xss_reflected",
            "category": "xss",
            "title": "Potential reflected XSS behavior",
            "severity_hint": "medium",
            "confidence": 0.75,
        }

    def match(self, collection_bundle: dict, mode: str) -> bool:
        return bool(_build_probe_targets(collection_bundle))

    def probe(self, collection_bundle: dict, mode: str) -> list[dict]:
        targets = _build_probe_targets(collection_bundle)
        if not targets:
            return []

        metadata = collection_bundle.get("metadata") or {}
        plugin_options = (metadata.get("detection") or {}).get("xss", {})

        max_targets = int(plugin_options.get("max_targets", 3))
        timeout = float(plugin_options.get("timeout", 3.0))
        marker = str(plugin_options.get("marker", "vmpxssprobe"))

        manager = PayloadDictionaryManager()
        payload_mode = "attack" if mode == "attack" else "test"
        payloads = manager.load_payloads(
            "xss",
            mode=payload_mode,
            include_high_risk=mode == "attack",
            include_disabled=mode == "attack",
        )
        selected = _pick_xss_payload(payloads, mode=mode)
        selected_payload = selected.get("payload") if selected else ""
        selected_payload_id = selected.get("id") if selected else None
        selected_payload_source = selected.get("source") if selected else None
        injection = _build_injection(selected_payload, marker, mode)

        findings: list[dict] = []
        session = requests.Session()
        _apply_session_cookies(session, collection_bundle)

        for target in targets[:max_targets]:
            base_url = target["url"]
            target_param = target["param"]
            method = str(target.get("method") or "GET").upper()
            probe_url = base_url
            request_data = None

            try:
                if method == "POST":
                    request_data = dict(target.get("form_data") or {})
                    request_data[target_param] = injection
                    resp = session.post(base_url, data=request_data, timeout=timeout, allow_redirects=True)
                else:
                    request_data = dict(target.get("form_data") or {})
                    request_data[target_param] = injection
                    probe_url = _with_params(base_url, request_data)
                    resp = session.get(probe_url, timeout=timeout, allow_redirects=True)
            except requests.RequestException:
                continue

            body = resp.text or ""
            marker_l = marker.lower()
            body_l = body.lower()
            escaped_marker_l = html.escape(marker).lower()

            contains_marker = marker_l in body_l
            contains_escaped = escaped_marker_l != marker_l and escaped_marker_l in body_l
            contains_raw = contains_marker

            if mode == "attack":
                executable_pattern = contains_raw and any(
                    pattern in body_l
                    for pattern in ("<script", "onerror", "onload", "javascript:")
                )
                if not executable_pattern:
                    continue
            else:
                executable_pattern = False

            if mode != "attack" and not (contains_raw or contains_escaped):
                continue

            findings.append(
                {
                    "title": "Reflected XSS executable payload echoed" if mode == "attack" else "Potential reflected XSS behavior",
                    "severity_hint": "high" if (contains_raw or executable_pattern) else "medium",
                    "confidence": 0.92 if executable_pattern else (0.88 if contains_raw else 0.7),
                    "location": {
                        "url": base_url,
                        "method": method,
                        "param": target_param,
                    },
                    "raw": {
                        "mode": mode,
                        "request_method": method,
                        "probe_url": probe_url,
                        "request_data": request_data,
                        "status": resp.status_code,
                        "marker": marker,
                        "payload": injection,
                        "payload_id": selected_payload_id,
                        "payload_source": selected_payload_source,
                        "contains_raw": contains_raw,
                        "contains_escaped": contains_escaped,
                        "executable_pattern": executable_pattern,
                    },
                }
            )

        return findings

    def verify(self, candidate: dict, collection_bundle: dict) -> bool:
        raw = candidate.get("raw") or {}
        mode = raw.get("mode", "test")
        if mode == "attack":
            return bool(raw.get("executable_pattern"))
        return bool(raw.get("contains_raw") or raw.get("contains_escaped"))

    def evidence(self, candidate: dict) -> dict:
        return dict(candidate.get("raw") or {})


def _with_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[name] = [value]
    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _with_params(url: str, values: dict[str, str]) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    for key, value in values.items():
        query[str(key)] = [str(value)]
    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _build_probe_targets(collection_bundle: dict) -> list[dict]:
    web_assets = collection_bundle.get("web_assets") or {}

    targets: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for item in web_assets.get("urls", []):
        base_url = str(item.get("url") or "")
        for param in item.get("params") or []:
            key = (base_url, "GET", str(param))
            if not base_url or key in seen:
                continue
            seen.add(key)
            targets.append({"url": base_url, "param": str(param), "method": "GET", "form_data": {}})

    for form in web_assets.get("forms", []):
        method = str(form.get("method") or "GET").upper()
        action = str(form.get("action") or "")
        if method not in {"GET", "POST"} or not action.startswith(("http://", "https://")):
            continue

        fields = form.get("fields") or []
        baseline_data = _build_form_baseline(fields)
        if method == "GET" and not any(
            str(field.get("input_type") or "").lower() in {"submit", "button"}
            and str(field.get("name") or "")
            for field in fields
        ):
            baseline_data.setdefault("Submit", "Submit")

        for field in fields:
            name = str(field.get("name") or "")
            input_type = str(field.get("input_type") or "text").lower()
            if not name or input_type in {"hidden", "submit", "button"}:
                continue
            key = (action, method, name)
            if key in seen:
                continue
            seen.add(key)
            targets.append(
                {
                    "url": action,
                    "param": name,
                    "method": method,
                    "form_data": dict(baseline_data),
                }
            )

    return targets


def _build_form_baseline(fields: list[dict]) -> dict[str, str]:
    data: dict[str, str] = {}
    first_submit: str | None = None

    for field in fields:
        name = str(field.get("name") or "")
        if not name:
            continue

        input_type = str(field.get("input_type") or "text").lower()
        if input_type in {"submit", "button"}:
            if first_submit is None:
                first_submit = name
            continue
        if input_type == "hidden":
            continue
        if input_type in {"checkbox", "radio"}:
            data[name] = "on"
            continue

        data[name] = "vmp"

    if first_submit:
        data[first_submit] = "Submit"

    return data


def _apply_session_cookies(session: requests.Session, collection_bundle: dict) -> None:
    metadata = collection_bundle.get("metadata") or {}
    cookies = metadata.get("session_cookies") or {}
    if isinstance(cookies, dict) and cookies:
        session.cookies.update(cookies)


def _pick_xss_payload(payloads: list[dict], mode: str) -> dict | None:
    for item in payloads:
        payload = str(item.get("payload") or "")
        lowered = payload.lower()
        if mode == "attack":
            if "<script" in lowered or "onerror" in lowered or "onload" in lowered:
                return item
        else:
            if "http://" in lowered or "https://" in lowered:
                continue
            if "fetch(" in lowered:
                continue
            if "document.cookie" in lowered:
                continue
            if "<" in payload and ">" in payload and len(payload) <= 200:
                return item

    return payloads[0] if payloads else None


def _build_injection(payload: str, marker: str, mode: str) -> str:
    if mode == "attack":
        if payload and "<script" in payload.lower() and "</script>" in payload.lower():
            return payload.replace("</script>", f"{marker}</script>", 1)
        return f"<script>console.log('{marker}')</script>"

    if not payload:
        return f"<vmp>{marker}</vmp>"

    if marker in payload:
        return payload

    if mode == "detect" or mode == "test":
        return f"{payload}<!--{marker}-->"

    return f"{payload} {marker}"
