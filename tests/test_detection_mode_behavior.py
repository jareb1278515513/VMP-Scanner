from __future__ import annotations

from scanner.detection.plugins.csrf_missing_token_plugin import CsrfMissingTokenPlugin
from scanner.detection.plugins.weak_password_policy_plugin import WeakPasswordPolicyPlugin


def test_csrf_plugin_supports_detect_and_attack_modes() -> None:
    plugin = CsrfMissingTokenPlugin()
    bundle = {
        "web_assets": {
            "forms": [
                {
                    "page_url": "http://example.com/profile",
                    "action": "http://example.com/profile",
                    "method": "POST",
                    "fields": [{"name": "email", "input_type": "text", "required": False}],
                    "has_csrf_token": False,
                }
            ]
        }
    }

    detect_candidates = plugin.probe(bundle, mode="test")
    attack_candidates = plugin.probe(bundle, mode="attack")

    assert len(detect_candidates) == 1
    assert len(attack_candidates) == 1
    assert detect_candidates[0]["title"] == "Form may miss CSRF token"
    assert attack_candidates[0]["title"] == "CSRF attack may be forgeable"

    evidence = plugin.evidence(attack_candidates[0])
    assert evidence["mode"] == "attack"
    assert evidence["attack_poc"]["method"] == "POST"
    assert "email" in evidence["attack_poc"]["forged_post"]


def test_weak_password_plugin_attack_mode_enables_active_probe(monkeypatch) -> None:
    plugin = WeakPasswordPolicyPlugin()

    class FakeResponse:
        def __init__(self, text: str) -> None:
            self.text = text
            self.status_code = 200

    class FakeSession:
        def __init__(self) -> None:
            self.calls = 0

        def post(self, url: str, data: dict | None = None, timeout: float = 1.0, allow_redirects: bool = True):
            self.calls += 1
            return FakeResponse("welcome logout")

    fake_session = FakeSession()
    monkeypatch.setattr("scanner.detection.plugins.weak_password_policy_plugin.requests.Session", lambda: fake_session)
    monkeypatch.setattr("scanner.detection.plugins.weak_password_policy_plugin.time.sleep", lambda _: None)

    bundle = {
        "web_assets": {
            "forms": [
                {
                    "page_url": "http://example.com/login",
                    "action": "http://example.com/login",
                    "method": "POST",
                    "fields": [
                        {"name": "username", "input_type": "text", "required": False},
                        {"name": "password", "input_type": "password", "required": False},
                    ],
                    "has_csrf_token": True,
                }
            ]
        },
        "metadata": {"detection": {"weak_password": {"max_attempts": 1, "interval_seconds": 0}}},
    }

    test_mode = plugin.probe(bundle, mode="test")
    attack_mode = plugin.probe(bundle, mode="attack")

    assert any(item["title"] == "Weak password control may be insufficient" for item in test_mode)
    assert any(item["title"] == "Potential weak credential accepted" for item in attack_mode)
    assert fake_session.calls >= 1
