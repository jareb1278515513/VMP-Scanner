from __future__ import annotations

from scanner.detection.payloads import PayloadDictionaryManager, load_payloads


def test_payload_manager_categories_and_version() -> None:
    manager = PayloadDictionaryManager()
    categories = manager.list_categories()

    assert "sqli" in categories
    assert "xss" in categories
    assert "csrf" in categories
    assert "path_traversal" in categories
    assert manager.get_dictionary_version()
    assert len(manager.get_changelog()) >= 1


def test_high_risk_payload_disabled_by_default() -> None:
    manager = PayloadDictionaryManager()

    attack_default = manager.load_payloads("sqli", mode="attack")
    attack_explicit = manager.load_payloads(
        "sqli",
        mode="attack",
        include_high_risk=True,
        include_disabled=True,
    )

    assert attack_default == []
    assert len(attack_explicit) >= 1
    assert all(item["risk_level"] == "high" for item in attack_explicit)


def test_load_payload_bundle_for_plugins() -> None:
    manager = PayloadDictionaryManager()
    bundle = manager.load_payload_bundle(["xss", "csrf"], mode="test")

    assert "xss" in bundle
    assert "csrf" in bundle
    assert len(bundle["xss"]) >= 1
    assert len(bundle["csrf"]) >= 1


def test_helper_function_load_payloads() -> None:
    xss_payloads = load_payloads("xss", mode="test")
    assert len(xss_payloads) >= 1
    assert all(item["mode"] == "test" for item in xss_payloads)
