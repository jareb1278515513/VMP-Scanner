from __future__ import annotations

from urllib.parse import urljoin

import requests

from scanner.detection.base import DetectionPlugin
from scanner.detection.payloads import PayloadDictionaryManager

SENSITIVE_PATH_HINTS = (
    "/admin/",
    "/admin.php",
    "/phpinfo.php",
    "/.git/config",
    "/.env",
    "/backup.zip",
    "/server-status",
)


class SensitivePathPlugin(DetectionPlugin):
    """敏感路径暴露检测插件。"""

    def metadata(self) -> dict:
        """返回插件元数据。"""

        return {
            "name": "sensitive_path",
            "category": "path_traversal",
            "title": "Sensitive path is exposed",
            "severity_hint": "medium",
            "confidence": 0.72,
        }

    def match(self, collection_bundle: dict, mode: str) -> bool:
        """判断是否存在可用于探测的站点目标。"""

        target = str(collection_bundle.get("target") or "")
        web_assets = collection_bundle.get("web_assets") or {}
        return target.startswith(("http://", "https://")) or bool(web_assets.get("start_url"))

    def probe(self, collection_bundle: dict, mode: str) -> list[dict]:
        """探测常见敏感路径并生成候选发现。"""

        target = str(collection_bundle.get("target") or "")
        web_assets = collection_bundle.get("web_assets") or {}
        base_url = str(web_assets.get("start_url") or target)
        if not base_url.startswith(("http://", "https://")):
            return []

        metadata = collection_bundle.get("metadata") or {}
        plugin_options = (metadata.get("detection") or {}).get("sensitive_path", {})
        timeout = float(plugin_options.get("timeout", 3.0))
        max_paths = int(plugin_options.get("max_paths", 20))

        manager = PayloadDictionaryManager()
        payloads = manager.load_payloads(
            "path_traversal",
            mode="attack" if mode == "attack" else "test",
            include_high_risk=mode == "attack",
            include_disabled=mode == "attack",
        )

        candidates = list(SENSITIVE_PATH_HINTS)
        candidates.extend(_extract_path_candidates(payloads))
        candidates.extend(plugin_options.get("custom_paths", []))

        deduped: list[str] = []
        seen: set[str] = set()
        for path in candidates:
            normalized = _normalize_path(path)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            deduped.append(normalized)
            if len(deduped) >= max_paths:
                break

        findings: list[dict] = []
        session = requests.Session()
        _apply_session_cookies(session, collection_bundle)

        for path in deduped:
            probe_url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
            try:
                resp = session.get(probe_url, timeout=timeout, allow_redirects=False)
            except requests.RequestException:
                continue

            if resp.status_code not in (200, 401, 403):
                continue

            body = (resp.text or "").lower()
            if resp.status_code == 200 and "not found" in body[:300]:
                continue

            attack_feature = _extract_sensitive_feature(resp.text or "") if mode == "attack" else None

            findings.append(
                {
                    "title": "Sensitive path disclosure confirmed" if mode == "attack" else "Sensitive path is exposed",
                    "severity_hint": "high" if resp.status_code == 200 else "medium",
                    "confidence": 0.92 if attack_feature else (0.85 if resp.status_code == 200 else 0.68),
                    "location": {
                        "url": probe_url,
                        "method": "GET",
                    },
                    "raw": {
                        "mode": mode,
                        "status": resp.status_code,
                        "path": path,
                        "attack_feature": attack_feature,
                        "content_preview": (resp.text or "")[:200],
                    },
                }
            )

        return findings

    def verify(self, candidate: dict, collection_bundle: dict) -> bool:
        """校验候选状态码是否在可接受范围。"""

        raw = candidate.get("raw") or {}
        return int(raw.get("status", 0)) in (200, 401, 403)

    def evidence(self, candidate: dict) -> dict:
        """提取候选项证据。"""

        return dict(candidate.get("raw") or {})


def _extract_path_candidates(payloads: list[dict]) -> list[str]:
    """从 payload 字典中提取路径候选。"""

    result: list[str] = []
    for item in payloads:
        text = str(item.get("payload") or "").strip()
        if not text:
            continue
        if "{{BaseURL}}" in text:
            suffix = text.split("{{BaseURL}}", 1)[-1]
            if suffix.startswith("/") and " " not in suffix and len(suffix) < 120:
                result.append(suffix)
        elif text.startswith("/") and " " not in text and len(text) < 80:
            result.append(text)
    return result


def _normalize_path(path: str) -> str:
    """规范化路径字符串。"""

    normalized = path.strip()
    if not normalized:
        return ""
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized


def _extract_sensitive_feature(body: str) -> str | None:
    """提取响应中的敏感信息特征。"""

    lowered = body.lower()
    markers = (
        "root:x:0:0",
        "[extensions]",
        "db_password",
        "api_key",
        "phpinfo",
    )
    for marker in markers:
        if marker in lowered:
            return marker
    return None


def _apply_session_cookies(session: requests.Session, collection_bundle: dict) -> None:
    """将采集层会话 Cookie 注入请求会话。"""

    metadata = collection_bundle.get("metadata") or {}
    cookies = metadata.get("session_cookies") or {}
    if isinstance(cookies, dict) and cookies:
        session.cookies.update(cookies)
