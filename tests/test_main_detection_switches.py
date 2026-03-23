from __future__ import annotations

from main import build_detection_metadata, resolve_enabled_plugins


def test_build_detection_metadata_supports_global_and_per_plugin_overrides() -> None:
    runtime_config = {
        "mode": "test",
        "detection_plugin_timeout": 2.5,
        "detection_plugin_max_targets": 4,
        "plugin_timeout": ["xss_reflected=1.2", "sqli=3.3"],
        "plugin_max_targets": ["sensitive_path=6", "weak_password=2"],
    }

    metadata = build_detection_metadata(runtime_config)

    assert metadata["sqli_basic"]["timeout"] == 3.3
    assert metadata["xss_reflected"]["timeout"] == 1.2
    assert metadata["xss"]["timeout"] == 1.2

    assert metadata["sqli"]["max_targets"] == 4
    assert metadata["xss"]["max_targets"] == 4
    assert metadata["sensitive_path"]["max_paths"] == 6
    assert metadata["weak_password"]["max_attempts"] == 2
    assert metadata["weak_password"]["enable_active_probe"] is False


def test_resolve_enabled_plugins_with_enable_and_disable() -> None:
    available = [
        "suspicious_endpoint",
        "sqli_basic",
        "xss_reflected",
        "sensitive_path",
        "csrf_missing_token",
    ]

    runtime_config = {
        "enable_plugins": ["sqli_basic", "xss_reflected", "csrf_missing_token"],
        "disable_plugins": ["csrf_missing_token"],
    }

    resolved = resolve_enabled_plugins(runtime_config, available)
    assert resolved == ["sqli_basic", "xss_reflected"]


def test_resolve_enabled_plugins_returns_none_when_not_configured() -> None:
    available = ["a", "b"]
    runtime_config = {}
    assert resolve_enabled_plugins(runtime_config, available) is None
