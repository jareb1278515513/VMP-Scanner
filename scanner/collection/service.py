from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from urllib.parse import urlparse

from scanner.collection.contracts import (
    AuthOptions,
    CollectionBundle,
    CollectionRequest,
    CrawlerCollectionOptions,
    NetworkCollectionOptions,
)
from scanner.collection.crawler import (
    build_form_login_session,
    crawl_web_state,
    parse_cookie_header,
    parse_key_value_pairs,
)
from scanner.collection.network.scanner import normalize_target_host, parse_ports, scan_host_ports


class CollectionService:
    schema_version = "1.0"

    def collect(self, request: CollectionRequest | dict) -> dict:
        normalized_request = _coerce_request(request)
        started_at = _utc_now_iso()

        bundle = CollectionBundle(
            schema_version=self.schema_version,
            target=normalized_request.target,
            started_at=started_at,
            finished_at=started_at,
            metadata=normalized_request.metadata,
        )

        try:
            target_host = normalize_target_host(normalized_request.target)
            port_list = parse_ports(
                normalized_request.network.ports,
                normalized_request.network.port_range,
            )
            bundle.network_assets = scan_host_ports(
                host=target_host,
                ports=port_list,
                timeout=normalized_request.timeout,
                concurrency=normalized_request.concurrency,
                grab_banner=normalized_request.network.grab_banner,
            )
        except Exception as exc:
            bundle.errors.append(f"network_collection_failed: {exc}")
            bundle.network_assets = []

        parsed_target = urlparse(normalized_request.target)
        if normalized_request.crawler.enabled and parsed_target.scheme in ("http", "https"):
            try:
                crawl_session = None
                if normalized_request.crawler.auth.enabled:
                    auth = normalized_request.crawler.auth
                    crawl_session = build_form_login_session(
                        base_url=normalized_request.target,
                        login_url=auth.login_url,
                        username=auth.username,
                        password=auth.password,
                        timeout=normalized_request.timeout,
                        username_field=auth.username_field,
                        password_field=auth.password_field,
                        csrf_field=auth.csrf_field,
                        submit_field=auth.submit_field,
                        submit_value=auth.submit_value,
                        success_keyword=auth.success_keyword,
                        extra_form_fields=parse_key_value_pairs(auth.extra_fields),
                    )

                bundle.web_assets = crawl_web_state(
                    start_url=normalized_request.target,
                    max_depth=normalized_request.crawler.max_depth,
                    timeout=normalized_request.timeout,
                    allowed_domains=normalized_request.crawler.allowed_domains,
                    cookies=parse_cookie_header(normalized_request.crawler.cookie_header),
                    session=crawl_session,
                )
            except Exception as exc:
                bundle.errors.append(f"crawler_collection_failed: {exc}")
                bundle.web_assets = {
                    "start_url": normalized_request.target,
                    "max_depth": normalized_request.crawler.max_depth,
                    "visited_count": 0,
                    "status_code_stats": {},
                    "redirect_chains": [],
                    "urls": [],
                    "forms": [],
                    "suspicious_endpoints": [],
                    "errors": [str(exc)],
                }

        bundle.finished_at = _utc_now_iso()
        return bundle.to_dict()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _coerce_request(request: CollectionRequest | dict) -> CollectionRequest:
    if isinstance(request, CollectionRequest):
        return request

    if not isinstance(request, dict):
        raise ValueError("CollectionService.collect request must be CollectionRequest or dict.")

    target = request.get("target")
    if not target:
        raise ValueError("Collection request missing required field: target")

    network_raw = request.get("network") or {}
    crawler_raw = request.get("crawler") or {}
    auth_raw = crawler_raw.get("auth") or {}

    network = NetworkCollectionOptions(
        ports=network_raw.get("ports", "80,443,8080,3306"),
        port_range=network_raw.get("port_range"),
        grab_banner=bool(network_raw.get("grab_banner", False)),
    )

    auth = AuthOptions(
        enabled=bool(auth_raw.get("enabled", False)),
        login_url=auth_raw.get("login_url"),
        username=auth_raw.get("username", "admin"),
        password=auth_raw.get("password", "password"),
        username_field=auth_raw.get("username_field", "username"),
        password_field=auth_raw.get("password_field", "password"),
        csrf_field=auth_raw.get("csrf_field", "user_token"),
        submit_field=auth_raw.get("submit_field"),
        submit_value=auth_raw.get("submit_value"),
        success_keyword=auth_raw.get("success_keyword"),
        extra_fields=auth_raw.get("extra_fields"),
    )

    crawler = CrawlerCollectionOptions(
        enabled=bool(crawler_raw.get("enabled", True)),
        max_depth=int(crawler_raw.get("max_depth", 2)),
        allowed_domains=crawler_raw.get("allowed_domains"),
        cookie_header=crawler_raw.get("cookie_header"),
        auth=auth,
    )

    return CollectionRequest(
        target=target,
        mode=request.get("mode", "test"),
        timeout=float(request.get("timeout", 1.0)),
        concurrency=int(request.get("concurrency", 20)),
        network=network,
        crawler=crawler,
        metadata=request.get("metadata") or {},
    )
