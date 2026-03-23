from __future__ import annotations

import argparse

from main import build_detection_metadata, load_runtime_config, resolve_enabled_plugins


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


def test_load_runtime_config_normalizes_detect_mode_alias() -> None:
    args = argparse.Namespace(
        target=None,
        mode="detect",
        max_depth=None,
        concurrency=None,
        timeout=None,
        ports=None,
        port_range=None,
        allowed_domains=None,
        cookie=None,
        auto_login=False,
        auth_login_url=None,
        auth_username="admin",
        auth_password="password",
        auth_username_field="username",
        auth_password_field="password",
        auth_csrf_field="user_token",
        auth_submit_field=None,
        auth_submit_value=None,
        auth_success_keyword=None,
        auth_extra=None,
        sync_payloads=False,
        payload_sync_ref="master",
        payload_sync_max_per_category=200,
        payload_sync_timeout=20.0,
        payload_sync_incremental=False,
        enable_plugins=None,
        disable_plugins=None,
        detection_plugin_timeout=None,
        detection_plugin_max_targets=None,
        plugin_timeout=None,
        plugin_max_targets=None,
        crawler_output_json=None,
        report_json=None,
        report_markdown=None,
        report_html=None,
        grab_banner=False,
    )

    config = load_runtime_config(args)
    assert config["mode"] == "test"
