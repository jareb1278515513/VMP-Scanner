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
            probe_url = _with_param(base_url, target_param, injection)

            try:
                resp = session.get(probe_url, timeout=timeout, allow_redirects=True)
            except requests.RequestException:
                continue

            body = resp.text or ""
            marker_l = marker.lower()
            body_l = body.lower()
            escaped_marker_l = html.escape(marker).lower()

            contains_marker = marker_l in body_l
            contains_escaped = escaped_marker_l in body_l
            contains_raw = contains_marker and not contains_escaped

            if mode == "attack":
                executable_pattern = "<script>" in body and marker in body
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
                        "method": "GET",
                        "param": target_param,
                    },
                    "raw": {
                        "mode": mode,
                        "probe_url": probe_url,
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


def _build_probe_targets(collection_bundle: dict) -> list[dict]:
    web_assets = collection_bundle.get("web_assets") or {}

    targets: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for item in web_assets.get("urls", []):
        base_url = str(item.get("url") or "")
        for param in item.get("params") or []:
            key = (base_url, str(param))
            if not base_url or key in seen:
                continue
            seen.add(key)
            targets.append({"url": base_url, "param": str(param)})

    for form in web_assets.get("forms", []):
        method = str(form.get("method") or "GET").upper()
        action = str(form.get("action") or "")
        if method != "GET" or not action.startswith(("http://", "https://")):
            continue

        for field in form.get("fields") or []:
            name = str(field.get("name") or "")
            input_type = str(field.get("input_type") or "text").lower()
            if not name or input_type in {"hidden", "submit", "button"}:
                continue
            key = (action, name)
            if key in seen:
                continue
            seen.add(key)
            targets.append({"url": action, "param": name})
            break

    return targets


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
    if not payload:
        return f"<script>console.log('{marker}')</script>" if mode == "attack" else f"<vmp>{marker}</vmp>"

    if marker in payload:
        return payload

    if mode == "attack" and "<script" in payload.lower() and "</script>" in payload.lower():
        return payload.replace("</script>", f"/*{marker}*/</script>", 1)

    if mode == "detect" or mode == "test":
        return f"{payload}<!--{marker}-->"

    return f"{payload} {marker}"
