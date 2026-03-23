from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from scanner.detection.plugins.xss_plugin import ReflectedXssPlugin


def _collection_with_get_form() -> dict:
    return {
        "web_assets": {
            "urls": [],
            "forms": [
                {
                    "action": "http://localhost/vulnerabilities/xss_r/",
                    "method": "GET",
                    "fields": [
                        {"name": "name", "input_type": "text", "required": False},
                    ],
                }
            ],
        },
        "metadata": {"detection": {"xss": {"max_targets": 3, "timeout": 1.0, "marker": "vmpxssprobe"}}},
    }


def _collection_with_post_form() -> dict:
    return {
        "web_assets": {
            "urls": [],
            "forms": [
                {
                    "action": "http://localhost/vulnerabilities/xss_s/",
                    "method": "POST",
                    "fields": [
                        {"name": "txtName", "input_type": "text", "required": False},
                        {"name": "mtxMessage", "input_type": "textarea", "required": False},
                        {"name": "btnSign", "input_type": "submit", "required": False},
                    ],
                }
            ],
        },
        "metadata": {"detection": {"xss": {"max_targets": 3, "timeout": 1.0, "marker": "vmpxssprobe"}}},
    }


def test_xss_attack_mode_detects_onerror_reflection(monkeypatch) -> None:
    seen_urls: list[str] = []

    class FakeResponse:
        def __init__(self, text: str) -> None:
            self.status_code = 200
            self.text = text

    class FakeSession:
        def get(self, url: str, timeout: float = 1.0, allow_redirects: bool = True):
            seen_urls.append(url)
            return FakeResponse("echo: <img src=x onerror='alert(1)'> vmpxssprobe")

        def post(self, url: str, data: dict | None = None, timeout: float = 1.0, allow_redirects: bool = True):
            return FakeResponse("not-used")

    import scanner.detection.plugins.xss_plugin as xss_plugin

    monkeypatch.setattr(xss_plugin.requests, "Session", lambda: FakeSession())

    plugin = ReflectedXssPlugin()
    candidates = plugin.probe(_collection_with_get_form(), mode="attack")

    assert candidates
    assert plugin.verify(candidates[0], _collection_with_get_form())
    assert candidates[0]["location"]["method"] == "GET"
    assert seen_urls

    parsed = parse_qs(urlparse(seen_urls[0]).query)
    assert parsed.get("Submit") == ["Submit"]


def test_xss_plugin_probes_post_form_targets(monkeypatch) -> None:
    calls: list[dict] = []

    class FakeResponse:
        def __init__(self, text: str) -> None:
            self.status_code = 200
            self.text = text

    class FakeSession:
        def get(self, url: str, timeout: float = 1.0, allow_redirects: bool = True):
            return FakeResponse("not-used")

        def post(self, url: str, data: dict | None = None, timeout: float = 1.0, allow_redirects: bool = True):
            payload_value = ""
            if data:
                calls.append(dict(data))
                payload_value = next((str(v) for v in data.values() if "vmpxssprobe" in str(v)), "")
            return FakeResponse(f"saved: {payload_value}")

    import scanner.detection.plugins.xss_plugin as xss_plugin

    monkeypatch.setattr(xss_plugin.requests, "Session", lambda: FakeSession())

    plugin = ReflectedXssPlugin()
    candidates = plugin.probe(_collection_with_post_form(), mode="attack")

    assert calls
    assert any("btnSign" in item for item in calls)
    assert candidates
    assert candidates[0]["location"]["method"] == "POST"
    assert candidates[0]["raw"]["request_data"] is not None
