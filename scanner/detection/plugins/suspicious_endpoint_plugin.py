from __future__ import annotations

from scanner.detection.base import DetectionPlugin


class SuspiciousEndpointPlugin(DetectionPlugin):
    """将爬虫可疑端点转换为检测发现的插件。"""

    def metadata(self) -> dict:
        """返回插件元数据。"""

        return {
            "name": "suspicious_endpoint",
            "category": "surface-anomaly",
            "title": "Suspicious endpoint discovered",
            "severity_hint": "medium",
            "confidence": 0.75,
        }

    def match(self, collection_bundle: dict, mode: str) -> bool:
        """判断是否存在可疑端点输入。"""

        web_assets = collection_bundle.get("web_assets") or {}
        return bool(web_assets.get("suspicious_endpoints"))

    def probe(self, collection_bundle: dict, mode: str) -> list[dict]:
        """构建可疑端点候选发现。"""

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
        """校验候选项位置字段。"""

        location = candidate.get("location") or {}
        return bool(location.get("url"))

    def evidence(self, candidate: dict) -> dict:
        """提取候选项证据。"""

        raw = candidate.get("raw") or {}
        return {
            "reason": raw.get("reason"),
            "evidence": raw.get("evidence"),
            "depth": raw.get("depth"),
        }
