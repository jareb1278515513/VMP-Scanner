from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from scanner.detection.base import DetectionPlugin
from scanner.detection.payloads import PayloadDictionaryManager

SQL_ERROR_MARKERS = (
    "sql syntax",
    "mysql",
    "postgres",
    "sqlite",
    "odbc",
    "sqlstate",
    "you have an error in your sql syntax",
)


class SqlInjectionPlugin(DetectionPlugin):
    def metadata(self) -> dict:
        return {
            "name": "sqli_basic",
            "category": "sqli",
            "title": "Potential SQL injection behavior",
            "severity_hint": "high",
            "confidence": 0.82,
        }

    def match(self, collection_bundle: dict, mode: str) -> bool:
        return bool(_build_probe_targets(collection_bundle))

    def probe(self, collection_bundle: dict, mode: str) -> list[dict]:
        targets = _build_probe_targets(collection_bundle)
        if not targets:
            return []

        manager = PayloadDictionaryManager()
        payloads = manager.load_payloads("sqli", mode="test")
        true_payload, false_payload = _pick_boolean_pair(payloads)

        metadata = collection_bundle.get("metadata") or {}
        plugin_options = (metadata.get("detection") or {}).get("sqli", {})
        max_targets = int(plugin_options.get("max_targets", 3))
        timeout = float(plugin_options.get("timeout", 3.0))
        min_len_diff = int(plugin_options.get("min_length_diff", 40))

        findings: list[dict] = []
        session = requests.Session()
        _apply_session_cookies(session, collection_bundle)

        for target in targets[:max_targets]:
            base_url = target["url"]
            target_param = target["param"]
            try:
                true_url = _with_param(base_url, target_param, f"1 {true_payload}")
                false_url = _with_param(base_url, target_param, f"1 {false_payload}")

                true_resp = session.get(true_url, timeout=timeout, allow_redirects=True)
                false_resp = session.get(false_url, timeout=timeout, allow_redirects=True)
            except requests.RequestException:
                continue

            true_text = (true_resp.text or "").lower()
            false_text = (false_resp.text or "").lower()
            error_marker = next((marker for marker in SQL_ERROR_MARKERS if marker in true_text), None)

            len_true = len(true_resp.text or "")
            len_false = len(false_resp.text or "")
            bool_diff = true_resp.status_code == false_resp.status_code and abs(len_true - len_false) >= min_len_diff

            if not error_marker and not bool_diff:
                continue

            confidence = 0.9 if error_marker else 0.78
            findings.append(
                {
                    "title": "Potential SQL injection behavior",
                    "severity_hint": "high" if error_marker else "medium",
                    "confidence": confidence,
                    "location": {
                        "url": base_url,
                        "method": "GET",
                        "param": target_param,
                    },
                    "raw": {
                        "true_probe_url": true_url,
                        "false_probe_url": false_url,
                        "true_status": true_resp.status_code,
                        "false_status": false_resp.status_code,
                        "true_length": len_true,
                        "false_length": len_false,
                        "error_marker": error_marker,
                        "boolean_diff": bool_diff,
                        "used_payloads": {
                            "true": true_payload,
                            "false": false_payload,
                        },
                    },
                }
            )

        return findings

    def verify(self, candidate: dict, collection_bundle: dict) -> bool:
        raw = candidate.get("raw") or {}
        return bool(raw.get("error_marker") or raw.get("boolean_diff"))

    def evidence(self, candidate: dict) -> dict:
        return dict(candidate.get("raw") or {})


def _pick_boolean_pair(payloads: list[dict]) -> tuple[str, str]:
    true_payload = "' OR '1'='1' --"
    false_payload = "' AND '1'='2' --"

    for item in payloads:
        text = str(item.get("payload") or "")
        lowered = text.lower()
        if "or 1=1" in lowered and "true" in lowered:
            true_payload = text
        if "and 1=2" in lowered and "false" in lowered:
            false_payload = text

    return true_payload, false_payload


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
