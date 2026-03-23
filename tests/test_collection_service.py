from __future__ import annotations

from scanner.collection.service import CollectionService


def test_collection_service_returns_bundle_with_network_and_web_assets(monkeypatch) -> None:
    def fake_normalize_target_host(target: str) -> str:
        return "example.com"

    def fake_parse_ports(port_list: str | None, port_range: str | None) -> list[int]:
        return [80, 443]

    def fake_scan_host_ports(
        host: str,
        ports: list[int],
        timeout: float,
        concurrency: int,
        grab_banner: bool,
    ) -> list[dict]:
        return [{"host": host, "port": 80, "status": "open", "service_guess": "http"}]

    def fake_build_form_login_session(**kwargs):
        return object()

    def fake_crawl_web_state(
        start_url: str,
        max_depth: int,
        timeout: float,
        allowed_domains: list[str] | None,
        cookies: dict[str, str],
        session,
    ) -> dict:
        return {
            "start_url": start_url,
            "max_depth": max_depth,
            "visited_count": 1,
            "status_code_stats": {200: 1},
            "redirect_chains": [],
            "urls": [
                {
                    "url": "http://example.com/",
                    "method": "GET",
                    "params": [],
                    "source_url": None,
                    "depth": 0,
                    "status_code": 200,
                }
            ],
            "forms": [],
            "suspicious_endpoints": [],
            "errors": [],
        }

    monkeypatch.setattr("scanner.collection.service.normalize_target_host", fake_normalize_target_host)
    monkeypatch.setattr("scanner.collection.service.parse_ports", fake_parse_ports)
    monkeypatch.setattr("scanner.collection.service.scan_host_ports", fake_scan_host_ports)
    monkeypatch.setattr("scanner.collection.service.build_form_login_session", fake_build_form_login_session)
    monkeypatch.setattr("scanner.collection.service.crawl_web_state", fake_crawl_web_state)

    service = CollectionService()
    bundle = service.collect(
        {
            "target": "http://example.com/",
            "timeout": 2,
            "concurrency": 5,
            "network": {"ports": "80,443", "grab_banner": False},
            "crawler": {
                "enabled": True,
                "max_depth": 1,
                "allowed_domains": ["example.com"],
                "cookie_header": "session=abc",
                "auth": {
                    "enabled": True,
                    "username": "user",
                    "password": "pass",
                    "extra_fields": ["tenant=dev"],
                },
            },
            "metadata": {"request_id": "abc"},
        }
    )

    assert bundle["schema_version"] == "1.0"
    assert bundle["target"] == "http://example.com/"
    assert bundle["network_assets"][0]["status"] == "open"
    assert bundle["web_assets"]["visited_count"] == 1
    assert bundle["errors"] == []
    assert bundle["metadata"]["request_id"] == "abc"


def test_collection_service_captures_crawler_error_without_crashing(monkeypatch) -> None:
    monkeypatch.setattr("scanner.collection.service.normalize_target_host", lambda target: "127.0.0.1")
    monkeypatch.setattr("scanner.collection.service.parse_ports", lambda port_list, port_range: [80])
    monkeypatch.setattr(
        "scanner.collection.service.scan_host_ports",
        lambda host, ports, timeout, concurrency, grab_banner: [
            {"host": host, "port": 80, "status": "open", "service_guess": "http"}
        ],
    )

    def raise_in_crawler(**kwargs):
        raise ValueError("crawler boom")

    monkeypatch.setattr("scanner.collection.service.crawl_web_state", raise_in_crawler)

    service = CollectionService()
    bundle = service.collect(
        {
            "target": "http://127.0.0.1/",
            "crawler": {"enabled": True, "max_depth": 1},
        }
    )

    assert bundle["network_assets"][0]["port"] == 80
    assert bundle["web_assets"]["visited_count"] == 0
    assert any(msg.startswith("crawler_collection_failed:") for msg in bundle["errors"])
