from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from scanner.detection import DetectionExecutor


def test_detection_executor_consumes_collection_bundle(monkeypatch) -> None:
    collection_bundle = {
        "schema_version": "1.0",
        "target": "http://example.com/",
        "network_assets": [],
        "web_assets": {
            "start_url": "http://example.com/",
            "urls": [
                {
                    "url": "http://example.com/search?q=book",
                    "method": "GET",
                    "params": ["q"],
                    "source_url": "http://example.com/",
                    "depth": 1,
                    "status_code": 200,
                }
            ],
            "forms": [
                {
                    "page_url": "http://example.com/login",
                    "action": "http://example.com/login.php",
                    "method": "POST",
                    "fields": [
                        {"name": "username", "input_type": "text", "required": False},
                        {"name": "password", "input_type": "password", "required": False},
                    ],
                    "has_csrf_token": False,
                    "depth": 1,
                }
            ],
            "suspicious_endpoints": [
                {
                    "url": "http://example.com/admin",
                    "reason": "suspicious_path",
                    "evidence": "path contains marker: admin",
                    "depth": 1,
                }
            ],
            "errors": [],
        },
        "metadata": {
            "detection": {
                "sqli": {"max_targets": 1, "timeout": 1.0, "min_length_diff": 10},
                "xss": {"max_targets": 1, "timeout": 1.0, "marker": "vmpxssprobe"},
                "sensitive_path": {"max_paths": 5, "timeout": 1.0, "custom_paths": ["/admin/"]},
                "weak_password": {
                    "max_attempts": 1,
                    "interval_seconds": 0.0,
                    "timeout": 1.0,
                    "credentials": [{"username": "admin", "password": "admin"}],
                    "success_keywords": ["logout"],
                },
            }
        },
        "errors": [],
    }

    class FakeResponse:
        def __init__(self, status_code: int, text: str) -> None:
            self.status_code = status_code
            self.text = text

    class FakeSession:
        def get(self, url: str, timeout: float = 1.0, allow_redirects: bool = True):
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            if parsed.path == "/search":
                q_value = query.get("q", [""])[0].lower()
                if "or 1=1" in q_value:
                    return FakeResponse(200, "SQL syntax error near '1=1'" + "A" * 120)
                if "and 1=2" in q_value:
                    return FakeResponse(200, "normal page")
                if "vmpxssprobe" in q_value:
                    return FakeResponse(200, "echo: <vmp>vmpxssprobe</vmp>")
                return FakeResponse(200, "search ok")
            if parsed.path == "/admin/":
                return FakeResponse(200, "admin dashboard")
            return FakeResponse(404, "not found")

        def post(self, url: str, data: dict | None = None, timeout: float = 1.0, allow_redirects: bool = True):
            if url.endswith("/login.php") and data and data.get("username") == "admin" and data.get("password") == "admin":
                return FakeResponse(200, "Welcome, logout")
            return FakeResponse(200, "login failed")

    import scanner.detection.plugins.sensitive_path_plugin as sensitive_path_plugin
    import scanner.detection.plugins.sqli_plugin as sqli_plugin
    import scanner.detection.plugins.weak_password_policy_plugin as weak_password_policy_plugin
    import scanner.detection.plugins.xss_plugin as xss_plugin

    monkeypatch.setattr(sqli_plugin.requests, "Session", lambda: FakeSession())
    monkeypatch.setattr(xss_plugin.requests, "Session", lambda: FakeSession())
    monkeypatch.setattr(sensitive_path_plugin.requests, "Session", lambda: FakeSession())
    monkeypatch.setattr(weak_password_policy_plugin.requests, "Session", lambda: FakeSession())
    monkeypatch.setattr(weak_password_policy_plugin.time, "sleep", lambda _: None)

    executor = DetectionExecutor()
    result = executor.run(collection_bundle, mode="test")

    assert result["schema_version"] == "1.0"
    assert result["target"] == "http://example.com/"
    assert result["plugin_stats"]["total"] == 6
    assert result["plugin_stats"]["failed"] == 0
    assert len(result["findings"]) >= 5

    categories = {item["category"] for item in result["findings"]}
    assert "sqli" in categories
    assert "xss" in categories
    assert "path_traversal" in categories
    assert "csrf" in categories
    assert "surface-anomaly" in categories
    assert "weak-credential" in categories

    assert all(isinstance(item.get("evidence"), dict) and item["evidence"] for item in result["findings"])


def test_detection_executor_isolates_plugin_errors() -> None:
    collection_bundle = {
        "schema_version": "1.0",
        "target": "http://example.com/",
        "network_assets": [],
        "web_assets": {"urls": [], "forms": [], "suspicious_endpoints": [], "errors": []},
        "errors": [],
    }

    executor = DetectionExecutor()

    class BrokenPlugin:
        def metadata(self) -> dict:
            return {"name": "broken", "category": "test"}

        def match(self, collection_bundle: dict, mode: str) -> bool:
            return True

        def probe(self, collection_bundle: dict, mode: str) -> list[dict]:
            raise RuntimeError("boom")

        def verify(self, candidate: dict, collection_bundle: dict) -> bool:
            return True

        def evidence(self, candidate: dict) -> dict:
            return {}

    executor.registry.register(BrokenPlugin())
    result = executor.run(collection_bundle, enabled_plugins=["broken"])

    assert result["plugin_stats"]["total"] == 1
    assert result["plugin_stats"]["failed"] == 1
    assert any(item.startswith("plugin_failed:broken:") for item in result["errors"])
