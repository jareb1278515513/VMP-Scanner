from __future__ import annotations

import time

import requests

from scanner.detection.base import DetectionPlugin


class WeakPasswordPolicyPlugin(DetectionPlugin):
    """检测弱口令与防自动化策略不足的插件。"""

    def metadata(self) -> dict:
        """返回插件元数据。"""

        return {
            "name": "weak_password_policy",
            "category": "weak-credential",
            "title": "Weak password control may be insufficient",
            "severity_hint": "medium",
            "confidence": 0.65,
        }

    def match(self, collection_bundle: dict, mode: str) -> bool:
        """判断采集结果中是否存在登录表单。"""

        web_assets = collection_bundle.get("web_assets") or {}
        forms = web_assets.get("forms") or []
        return any(_is_login_form(form) for form in forms)

    def probe(self, collection_bundle: dict, mode: str) -> list[dict]:
        """生成弱口令策略候选发现。"""

        web_assets = collection_bundle.get("web_assets") or {}
        forms = web_assets.get("forms") or []
        metadata = collection_bundle.get("metadata") or {}
        plugin_options = (metadata.get("detection") or {}).get("weak_password", {})
        active_probe_enabled = bool(plugin_options.get("enable_active_probe", mode == "attack"))

        max_attempts = int(plugin_options.get("max_attempts", 2 if mode == "attack" else 1))
        interval_seconds = float(plugin_options.get("interval_seconds", 0.5))
        timeout = float(plugin_options.get("timeout", 3.0))
        candidates = plugin_options.get(
            "credentials",
            [
                {"username": "admin", "password": "admin"},
                {"username": "admin", "password": "password"},
            ],
        )
        success_keywords = [item.lower() for item in plugin_options.get("success_keywords", ["logout", "welcome"])]

        findings: list[dict] = []
        session = requests.Session()
        _apply_session_cookies(session, collection_bundle)

        for form in forms:
            if not _is_login_form(form):
                continue

            fields = form.get("fields") or []
            field_names = [str(item.get("name") or "") for item in fields]
            has_rate_limit_hints = any(
                keyword in " ".join(field_names).lower() for keyword in ("captcha", "otp", "2fa")
            )

            if not has_rate_limit_hints:
                findings.append(
                    {
                        "title": "Weak password control may be insufficient",
                        "severity_hint": "medium",
                        "confidence": 0.6,
                        "location": {
                            "url": form.get("action") or form.get("page_url"),
                            "method": str(form.get("method", "POST")).upper(),
                        },
                        "raw": {
                            "mode": mode,
                            "assessment": "login_form_without_anti_automation_hint",
                            "field_names": field_names,
                        },
                    }
                )

            if not active_probe_enabled:
                continue

            action = str(form.get("action") or "")
            if not action.startswith(("http://", "https://")):
                continue

            username_field = _find_field_name(field_names, ("user", "email", "login"), "username")
            password_field = _find_field_name(field_names, ("pass",), "password")
            if not username_field or not password_field:
                continue

            for cred in candidates[:max_attempts]:
                data = {
                    username_field: cred.get("username", "admin"),
                    password_field: cred.get("password", "admin"),
                }
                try:
                    resp = session.post(action, data=data, timeout=timeout, allow_redirects=True)
                except requests.RequestException:
                    time.sleep(interval_seconds)
                    continue

                body = (resp.text or "").lower()
                matched = next((kw for kw in success_keywords if kw and kw in body), None)
                if matched:
                    findings.append(
                        {
                            "title": "Potential weak credential accepted",
                            "severity_hint": "high",
                            "confidence": 0.92,
                            "location": {
                                "url": action,
                                "method": "POST",
                                "param": username_field,
                            },
                            "raw": {
                                "mode": mode,
                                "credential": cred,
                                "success_keyword": matched,
                                "status": resp.status_code,
                                "rate_limited_interval_seconds": interval_seconds,
                                "attempt_budget": max_attempts,
                            },
                        }
                    )
                    break

                time.sleep(interval_seconds)

        return findings

    def verify(self, candidate: dict, collection_bundle: dict) -> bool:
        """校验候选项基础有效性。"""

        location = candidate.get("location") or {}
        return bool(location.get("url"))

    def evidence(self, candidate: dict) -> dict:
        """提取候选项证据。"""

        return dict(candidate.get("raw") or {})


def _is_login_form(form: dict) -> bool:
    """判断表单是否疑似登录表单。"""

    fields = form.get("fields") or []
    names = [str(item.get("name") or "").lower() for item in fields]
    return any("pass" in name for name in names)


def _find_field_name(field_names: list[str], keywords: tuple[str, ...], fallback: str) -> str:
    """按关键字匹配字段名，匹配失败时返回回退值。"""

    for name in field_names:
        lowered = name.lower()
        if any(keyword in lowered for keyword in keywords):
            return name
    return fallback


def _apply_session_cookies(session: requests.Session, collection_bundle: dict) -> None:
    """将采集层会话 Cookie 注入请求会话。"""

    metadata = collection_bundle.get("metadata") or {}
    cookies = metadata.get("session_cookies") or {}
    if isinstance(cookies, dict) and cookies:
        session.cookies.update(cookies)
