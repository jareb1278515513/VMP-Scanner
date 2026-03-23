from __future__ import annotations

import pytest

from scanner.detection.service import DetectionService


class _FakePlugin:
    def __init__(self, name: str) -> None:
        self._name = name

    def metadata(self) -> dict:
        return {"name": self._name}


class _FakeRegistry:
    def list_plugins(self) -> list[_FakePlugin]:
        return [_FakePlugin("alpha"), _FakePlugin("beta")]


class _FakeExecutor:
    def __init__(self) -> None:
        self.registry = _FakeRegistry()
        self.last_args: dict | None = None

    def run(self, collection_bundle: dict, mode: str, enabled_plugins: list[str] | None = None) -> dict:
        self.last_args = {
            "collection_bundle": collection_bundle,
            "mode": mode,
            "enabled_plugins": enabled_plugins,
        }
        return {
            "schema_version": "1.0",
            "target": collection_bundle.get("target", "unknown"),
            "findings": [],
            "plugin_stats": {"total": 0, "success": 0, "failed": 0, "skipped": 0},
            "errors": [],
        }


def test_detection_service_detect_routes_request_to_executor() -> None:
    fake_executor = _FakeExecutor()
    service = DetectionService(executor=fake_executor)  # type: ignore[arg-type]

    request = {
        "mode": "detect",
        "collection": {"target": "http://example.com/"},
        "plugin_policy": {"enabled_plugins": ["alpha"]},
    }

    result = service.detect(request)

    assert result["schema_version"] == "1.0"
    assert fake_executor.last_args is not None
    assert fake_executor.last_args["mode"] == "test"
    assert fake_executor.last_args["enabled_plugins"] == ["alpha"]


def test_detection_service_lists_plugins_from_registry() -> None:
    service = DetectionService(executor=_FakeExecutor())  # type: ignore[arg-type]
    assert service.list_available_plugins() == ["alpha", "beta"]


def test_detection_service_requires_collection() -> None:
    service = DetectionService(executor=_FakeExecutor())  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="collection"):
        service.detect({"mode": "test"})


def test_detection_service_rejects_unknown_mode() -> None:
    service = DetectionService(executor=_FakeExecutor())  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="Unsupported detection mode"):
        service.detect({"mode": "unsafe", "collection": {"target": "http://example.com"}})
