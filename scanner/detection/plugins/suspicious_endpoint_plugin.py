from __future__ import annotations

from scanner.detection.base import DetectionPlugin


class SuspiciousEndpointPlugin(DetectionPlugin):
    def metadata(self) -> dict:
        return {
            "name": "suspicious_endpoint",
            "category": "surface-anomaly",
            "title": "Suspicious endpoint discovered",
            "severity_hint": "medium",
            "confidence": 0.75,
        }

    def match(self, collection_bundle: dict, mode: str) -> bool:
        web_assets = collection_bundle.get("web_assets") or {}
        return bool(web_assets.get("suspicious_endpoints"))

    def probe(self, collection_bundle: dict, mode: str) -> list[dict]:
        web_assets = collection_bundle.get("web_assets") or {}
        findings: list[dict] = []
        for item in web_assets.get("suspicious_endpoints", []):
            findings.append(
                {
                    "title": "Suspicious endpoint discovered",
                    "severity_hint": "medium",
                    "confidence": 0.75,
                    "location": {
                        "url": item.get("url"),
                        "method": "GET",
                    },
                    "raw": item,
                }
            )
        return findings

    def verify(self, candidate: dict, collection_bundle: dict) -> bool:
        location = candidate.get("location") or {}
        return bool(location.get("url"))

    def evidence(self, candidate: dict) -> dict:
        raw = candidate.get("raw") or {}
        return {
            "reason": raw.get("reason"),
            "evidence": raw.get("evidence"),
            "depth": raw.get("depth"),
        }
