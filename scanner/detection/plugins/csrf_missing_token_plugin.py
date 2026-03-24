from __future__ import annotations

from scanner.detection.base import DetectionPlugin
from scanner.detection.payloads import PayloadDictionaryManager


class CsrfMissingTokenPlugin(DetectionPlugin):
    """检测表单缺失 CSRF Token 的插件。"""

    def metadata(self) -> dict:
        """返回插件元数据。"""

        return {
            "name": "csrf_missing_token",
            "category": "csrf",
            "title": "Form may miss CSRF token",
            "severity_hint": "medium",
            "confidence": 0.7,
        }

    def match(self, collection_bundle: dict, mode: str) -> bool:
        """判断输入中是否存在可检测表单。"""

        web_assets = collection_bundle.get("web_assets") or {}
        return bool(web_assets.get("forms"))

    def probe(self, collection_bundle: dict, mode: str) -> list[dict]:
        """生成缺失 CSRF Token 的候选发现。"""

        web_assets = collection_bundle.get("web_assets") or {}
        manager = PayloadDictionaryManager()
        payloads = manager.load_payloads(
            "csrf",
            mode="attack" if mode == "attack" else "test",
            include_high_risk=mode == "attack",
            include_disabled=mode == "attack",
        )
        payload_samples = [str(item.get("payload") or "") for item in payloads[:3]]
        payload_ids = [str(item.get("id") or "") for item in payloads[:3] if str(item.get("id") or "")]

        findings: list[dict] = []
        for form in web_assets.get("forms", []):
            method = str(form.get("method", "GET")).upper()
            has_csrf = bool(form.get("has_csrf_token", False))
            if method == "POST" and not has_csrf:
                field_names = [
                    str(item.get("name") or "")
                    for item in form.get("fields", [])
                    if str(item.get("name") or "")
                ]
                forged_post = {name: "ATTACK_PLACEHOLDER" for name in field_names}
                findings.append(
                    {
                        "title": "CSRF attack may be forgeable" if mode == "attack" else "Form may miss CSRF token",
                        "severity_hint": "high" if mode == "attack" else "medium",
                        "confidence": 0.85 if mode == "attack" else 0.7,
                        "location": {
                            "url": form.get("page_url"),
                            "method": method,
                            "param": "csrf_token",
                        },
                        "raw": {
                            "mode": mode,
                            "form": form,
                            "attack_poc": {
                                "target": form.get("action") or form.get("page_url"),
                                "method": method,
                                "forged_post": forged_post,
                                "payload_samples": payload_samples,
                                "payload_ids": payload_ids,
                            },
                            "payload_samples": payload_samples,
                            "payload_ids": payload_ids,
                        },
                    }
                )
        return findings

    def verify(self, candidate: dict, collection_bundle: dict) -> bool:
        """校验候选项位置字段完整性。"""

        location = candidate.get("location") or {}
        return bool(location.get("url"))

    def evidence(self, candidate: dict) -> dict:
        """提取证据数据。"""

        raw = candidate.get("raw") or {}
        form = raw.get("form") or {}
        return {
            "mode": raw.get("mode"),
            "form_action": form.get("action"),
            "form_method": form.get("method"),
            "fields": form.get("fields", []),
            "has_csrf_token": form.get("has_csrf_token"),
            "payload_ids": raw.get("payload_ids", []),
            "payload_samples": raw.get("payload_samples", []),
            "attack_poc": raw.get("attack_poc"),
        }
