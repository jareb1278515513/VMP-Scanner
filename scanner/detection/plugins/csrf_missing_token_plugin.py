from __future__ import annotations

from scanner.detection.base import DetectionPlugin


class CsrfMissingTokenPlugin(DetectionPlugin):
    def metadata(self) -> dict:
        return {
            "name": "csrf_missing_token",
            "category": "csrf",
            "title": "Form may miss CSRF token",
            "severity_hint": "medium",
            "confidence": 0.7,
        }

    def match(self, collection_bundle: dict, mode: str) -> bool:
        web_assets = collection_bundle.get("web_assets") or {}
        return bool(web_assets.get("forms"))

    def probe(self, collection_bundle: dict, mode: str) -> list[dict]:
        web_assets = collection_bundle.get("web_assets") or {}
        findings: list[dict] = []
        for form in web_assets.get("forms", []):
            method = str(form.get("method", "GET")).upper()
            has_csrf = bool(form.get("has_csrf_token", False))
            if method == "POST" and not has_csrf:
                findings.append(
                    {
                        "title": "Form may miss CSRF token",
                        "severity_hint": "medium",
                        "confidence": 0.7,
                        "location": {
                            "url": form.get("page_url"),
                            "method": method,
                            "param": "csrf_token",
                        },
                        "raw": form,
                    }
                )
        return findings

    def verify(self, candidate: dict, collection_bundle: dict) -> bool:
        location = candidate.get("location") or {}
        return bool(location.get("url"))

    def evidence(self, candidate: dict) -> dict:
        raw = candidate.get("raw") or {}
        return {
            "form_action": raw.get("action"),
            "form_method": raw.get("method"),
            "fields": raw.get("fields", []),
            "has_csrf_token": raw.get("has_csrf_token"),
        }
