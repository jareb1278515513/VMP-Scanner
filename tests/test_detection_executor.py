from __future__ import annotations

from scanner.detection import DetectionExecutor


def test_detection_executor_consumes_collection_bundle() -> None:
    collection_bundle = {
        "schema_version": "1.0",
        "target": "http://example.com/",
        "network_assets": [],
        "web_assets": {
            "urls": [{"url": "http://example.com/"}],
            "forms": [
                {
                    "page_url": "http://example.com/login",
                    "action": "http://example.com/login",
                    "method": "POST",
                    "fields": [{"name": "username", "input_type": "text", "required": False}],
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
        "errors": [],
    }

    executor = DetectionExecutor()
    result = executor.run(collection_bundle, mode="test")

    assert result["schema_version"] == "1.0"
    assert result["target"] == "http://example.com/"
    assert result["plugin_stats"]["total"] == 2
    assert result["plugin_stats"]["failed"] == 0
    assert len(result["findings"]) >= 2

    categories = {item["category"] for item in result["findings"]}
    assert "csrf" in categories
    assert "surface-anomaly" in categories


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
