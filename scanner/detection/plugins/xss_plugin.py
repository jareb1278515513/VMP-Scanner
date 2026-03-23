from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import html
import requests

from scanner.detection.base import DetectionPlugin


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
        injection = f"<vmp>{marker}</vmp>"

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
            contains_raw = injection in body
            escaped_injection = html.escape(injection)
            contains_escaped = escaped_injection in body

            if not (contains_raw or contains_escaped):
                continue

            findings.append(
                {
                    "title": "Potential reflected XSS behavior",
                    "severity_hint": "high" if contains_raw else "medium",
                    "confidence": 0.88 if contains_raw else 0.7,
                    "location": {
                        "url": base_url,
                        "method": "GET",
                        "param": target_param,
                    },
                    "raw": {
                        "probe_url": probe_url,
                        "status": resp.status_code,
                        "marker": marker,
                        "contains_raw": contains_raw,
                        "contains_escaped": contains_escaped,
                    },
                }
            )

        return findings

    def verify(self, candidate: dict, collection_bundle: dict) -> bool:
        raw = candidate.get("raw") or {}
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
