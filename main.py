import argparse
import json
import logging
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from scanner.assessment import AssessmentService
from scanner.collection import CollectionService
from scanner.detection import DetectionService
from scanner.detection.payloads import sync_from_open_source
from scanner.presentation import PresentationService


TOOL_VERSION = "0.1.0"


@dataclass(frozen=True)
class DefaultConfig:
    target: str = "127.0.0.1"
    mode: str = "detect"
    max_depth: int = 2
    concurrency: int = 20
    timeout: float = 1.0
    ports: str = "80,443,8080,3306"
    port_range: str | None = None
    allowed_domains: list[str] | None = None
    cookie: str | None = None
    auto_login: bool = False
    auth_login_url: str | None = None
    auth_username: str = "admin"
    auth_password: str = "password"
    auth_username_field: str = "username"
    auth_password_field: str = "password"
    auth_csrf_field: str = "user_token"
    auth_submit_field: str | None = None
    auth_submit_value: str | None = None
    auth_success_keyword: str | None = None
    auth_extra: list[str] | None = None
    sync_payloads: bool = False
    payload_sync_ref: str = "master"
    payload_sync_max_per_category: int = 200
    payload_sync_timeout: float = 20.0
    payload_sync_incremental: bool = False
    enable_plugins: list[str] | None = None
    disable_plugins: list[str] | None = None
    detection_plugin_timeout: float | None = None
    detection_plugin_max_targets: int | None = None
    plugin_timeout: list[str] | None = None
    plugin_max_targets: list[str] | None = None
    crawler_output_json: str | None = None
    report_json: str | None = None
    report_markdown: str | None = None
    grab_banner: bool = False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vmp-scanner",
        description="VMP-Scanner CLI entrypoint",
    )
    parser.add_argument("--target", help="Target host or URL")
    parser.add_argument(
        "--mode",
        choices=("detect", "test", "attack"),
        help="Run mode: detect/test (vulnerability detection) or attack (active exploitation)",
    )
    parser.add_argument("--max-depth", type=int, help="Crawler max depth")
    parser.add_argument("--concurrency", type=int, help="Worker concurrency")
    parser.add_argument("--timeout", type=float, help="Network timeout in seconds")
    parser.add_argument("--ports", help="Comma-separated ports, for example 80,443,3306")
    parser.add_argument("--port-range", help="Port range, for example 1-1024")
    parser.add_argument(
        "--allowed-domain",
        action="append",
        dest="allowed_domains",
        help="Allow crawling this domain (repeatable), defaults to target host",
    )
    parser.add_argument(
        "--cookie",
        help="Cookie header value for authenticated crawling, example: PHPSESSID=abc; security=low",
    )
    parser.add_argument(
        "--auto-login",
        action="store_true",
        help="Auto login with a generic form before crawling",
    )
    parser.add_argument(
        "--auth-login-url",
        help="Login form URL (relative or absolute). Defaults to --target",
    )
    parser.add_argument(
        "--auth-username",
        default="admin",
        help="Username for --auto-login",
    )
    parser.add_argument(
        "--auth-password",
        default="password",
        help="Password for --auto-login",
    )
    parser.add_argument(
        "--auth-username-field",
        default="username",
        help="Username field name in login form",
    )
    parser.add_argument(
        "--auth-password-field",
        default="password",
        help="Password field name in login form",
    )
    parser.add_argument(
        "--auth-csrf-field",
        default="user_token",
        help="CSRF hidden field name if present",
    )
    parser.add_argument(
        "--auth-submit-field",
        help="Submit button field name if required",
    )
    parser.add_argument(
        "--auth-submit-value",
        help="Submit button field value if required",
    )
    parser.add_argument(
        "--auth-success-keyword",
        help="Keyword to confirm login success in response HTML",
    )
    parser.add_argument(
        "--auth-extra",
        action="append",
        help="Additional login form value in key=value format (repeatable)",
    )
    parser.add_argument(
        "--sync-payloads",
        action="store_true",
        help="Sync payload dictionaries from open-source repository before scanning",
    )
    parser.add_argument(
        "--payload-sync-ref",
        default="master",
        help="Git ref (branch/tag/commit) used when syncing payload dictionaries",
    )
    parser.add_argument(
        "--payload-sync-max-per-category",
        type=int,
        default=200,
        help="Maximum payload entries imported per category during sync",
    )
    parser.add_argument(
        "--payload-sync-timeout",
        type=float,
        default=20.0,
        help="HTTP timeout in seconds for payload sync",
    )
    parser.add_argument(
        "--payload-sync-incremental",
        action="store_true",
        help="Use incremental merge strategy when syncing payload dictionaries",
    )
    parser.add_argument(
        "--enable-plugin",
        action="append",
        dest="enable_plugins",
        help="Enable only specified detection plugin(s), repeatable",
    )
    parser.add_argument(
        "--disable-plugin",
        action="append",
        dest="disable_plugins",
        help="Disable specified detection plugin(s), repeatable",
    )
    parser.add_argument(
        "--detection-plugin-timeout",
        type=float,
        help="Default timeout in seconds for detection plugins",
    )
    parser.add_argument(
        "--detection-plugin-max-targets",
        type=int,
        help="Default target limit for detection plugins",
    )
    parser.add_argument(
        "--plugin-timeout",
        action="append",
        help="Per-plugin timeout override in plugin=seconds format (repeatable)",
    )
    parser.add_argument(
        "--plugin-max-targets",
        action="append",
        help="Per-plugin target limit override in plugin=count format (repeatable)",
    )
    parser.add_argument(
        "--crawler-output-json",
        help="Write crawler report JSON to this path",
    )
    parser.add_argument(
        "--report-json",
        help="Write full risk report JSON to this path",
    )
    parser.add_argument(
        "--report-markdown",
        help="Write full risk report Markdown to this path",
    )
    parser.add_argument(
        "--grab-banner",
        action="store_true",
        help="Attempt to read lightweight service banners from open ports",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        help="Logging verbosity",
    )
    return parser


def load_runtime_config(args: argparse.Namespace) -> dict:
    config = asdict(DefaultConfig())

    if args.target:
        config["target"] = args.target
    if args.mode:
        config["mode"] = "test" if args.mode == "detect" else args.mode
    if args.max_depth is not None:
        config["max_depth"] = args.max_depth
    if args.concurrency is not None:
        config["concurrency"] = args.concurrency
    if args.timeout is not None:
        config["timeout"] = args.timeout
    if args.ports is not None:
        config["ports"] = args.ports
    if args.port_range is not None:
        config["port_range"] = args.port_range
        config["ports"] = None
    if args.allowed_domains is not None:
        config["allowed_domains"] = args.allowed_domains
    if args.cookie is not None:
        config["cookie"] = args.cookie
    if args.auto_login:
        config["auto_login"] = True
    if args.auth_login_url is not None:
        config["auth_login_url"] = args.auth_login_url
    if args.auth_username is not None:
        config["auth_username"] = args.auth_username
    if args.auth_password is not None:
        config["auth_password"] = args.auth_password
    if args.auth_username_field is not None:
        config["auth_username_field"] = args.auth_username_field
    if args.auth_password_field is not None:
        config["auth_password_field"] = args.auth_password_field
    if args.auth_csrf_field is not None:
        config["auth_csrf_field"] = args.auth_csrf_field
    if args.auth_submit_field is not None:
        config["auth_submit_field"] = args.auth_submit_field
    if args.auth_submit_value is not None:
        config["auth_submit_value"] = args.auth_submit_value
    if args.auth_success_keyword is not None:
        config["auth_success_keyword"] = args.auth_success_keyword
    if args.auth_extra is not None:
        config["auth_extra"] = args.auth_extra
    if args.sync_payloads:
        config["sync_payloads"] = True
    if args.payload_sync_ref is not None:
        config["payload_sync_ref"] = args.payload_sync_ref
    if args.payload_sync_max_per_category is not None:
        config["payload_sync_max_per_category"] = args.payload_sync_max_per_category
    if args.payload_sync_timeout is not None:
        config["payload_sync_timeout"] = args.payload_sync_timeout
    if args.payload_sync_incremental:
        config["payload_sync_incremental"] = True
    if args.enable_plugins is not None:
        config["enable_plugins"] = args.enable_plugins
    if args.disable_plugins is not None:
        config["disable_plugins"] = args.disable_plugins
    if args.detection_plugin_timeout is not None:
        config["detection_plugin_timeout"] = args.detection_plugin_timeout
    if args.detection_plugin_max_targets is not None:
        config["detection_plugin_max_targets"] = args.detection_plugin_max_targets
    if args.plugin_timeout is not None:
        config["plugin_timeout"] = args.plugin_timeout
    if args.plugin_max_targets is not None:
        config["plugin_max_targets"] = args.plugin_max_targets
    if args.crawler_output_json is not None:
        config["crawler_output_json"] = args.crawler_output_json
    if getattr(args, "report_json", None) is not None:
        config["report_json"] = args.report_json
    if getattr(args, "report_markdown", None) is not None:
        config["report_markdown"] = args.report_markdown
    if args.grab_banner:
        config["grab_banner"] = True

    return config


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)s | %(message)s",
    )


PLUGIN_OPTION_ALIASES = {
    "sqli_basic": "sqli",
    "xss_reflected": "xss",
    "sensitive_path": "sensitive_path",
    "weak_password_policy": "weak_password",
    "csrf_missing_token": "csrf_missing_token",
    "suspicious_endpoint": "suspicious_endpoint",
}


def _parse_plugin_value_pairs(items: list[str] | None, cast):
    result: dict[str, int | float] = {}
    if not items:
        return result

    for item in items:
        if "=" not in item:
            raise ValueError(f"Invalid plugin override format: {item}, expected plugin=value")
        name, value = item.split("=", 1)
        plugin_name = name.strip().lower()
        if not plugin_name:
            raise ValueError(f"Invalid plugin name in override: {item}")
        result[plugin_name] = cast(value.strip())
    return result


def build_detection_metadata(runtime_config: dict) -> dict:
    defaults_timeout = runtime_config.get("detection_plugin_timeout")
    defaults_max_targets = runtime_config.get("detection_plugin_max_targets")
    timeout_overrides = _parse_plugin_value_pairs(runtime_config.get("plugin_timeout"), float)
    max_target_overrides = _parse_plugin_value_pairs(runtime_config.get("plugin_max_targets"), int)

    detection: dict[str, dict] = {}
    for plugin_name, alias in PLUGIN_OPTION_ALIASES.items():
        options: dict[str, int | float | bool] = {}

        timeout_value = timeout_overrides.get(plugin_name)
        if timeout_value is None:
            timeout_value = timeout_overrides.get(alias)
        if timeout_value is None:
            timeout_value = defaults_timeout
        if timeout_value is not None:
            options["timeout"] = float(timeout_value)

        max_targets_value = max_target_overrides.get(plugin_name)
        if max_targets_value is None:
            max_targets_value = max_target_overrides.get(alias)
        if max_targets_value is None:
            max_targets_value = defaults_max_targets

        if max_targets_value is not None:
            normalized_limit = int(max_targets_value)
            if alias == "sensitive_path":
                options["max_paths"] = normalized_limit
            elif alias == "weak_password":
                options["max_attempts"] = normalized_limit
            else:
                options["max_targets"] = normalized_limit

        if alias == "weak_password":
            options["enable_active_probe"] = runtime_config.get("mode") == "attack"

        if options:
            detection[plugin_name] = dict(options)
            if alias != plugin_name:
                detection[alias] = dict(options)

    return detection


def resolve_enabled_plugins(runtime_config: dict, available_plugins: list[str]) -> list[str] | None:
    available_set = {name.lower() for name in available_plugins}

    enabled = runtime_config.get("enable_plugins") or []
    disabled = runtime_config.get("disable_plugins") or []

    if not enabled and not disabled:
        return None

    if enabled:
        selected = {item.strip().lower() for item in enabled if item and item.strip()}
    else:
        selected = set(available_set)

    for item in disabled:
        if not item:
            continue
        selected.discard(item.strip().lower())

    resolved = sorted(name for name in available_plugins if name.lower() in selected)
    return resolved


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    configure_logging(args.log_level)

    start = time.perf_counter()
    logging.info("Task started")

    try:
        runtime_config = load_runtime_config(args)
        logging.info("Runtime config: %s", json.dumps(runtime_config, ensure_ascii=False))

        if runtime_config.get("sync_payloads"):
            counts = sync_from_open_source(
                base_dir=Path("scanner") / "detection" / "payloads",
                repo_ref=runtime_config["payload_sync_ref"],
                timeout=runtime_config["payload_sync_timeout"],
                max_per_category=runtime_config["payload_sync_max_per_category"],
                incremental=runtime_config["payload_sync_incremental"],
            )
            logging.info(
                "Payload sync completed: ref=%s, incremental=%s, counts=%s",
                runtime_config["payload_sync_ref"],
                runtime_config["payload_sync_incremental"],
                counts,
            )

        collection_service = CollectionService()
        detection_metadata = build_detection_metadata(runtime_config)
        collection_bundle = collection_service.collect(
            {
                "target": runtime_config["target"],
                "mode": runtime_config["mode"],
                "timeout": runtime_config["timeout"],
                "concurrency": runtime_config["concurrency"],
                "network": {
                    "ports": runtime_config.get("ports"),
                    "port_range": runtime_config.get("port_range"),
                    "grab_banner": runtime_config["grab_banner"],
                },
                "crawler": {
                    "enabled": True,
                    "max_depth": runtime_config["max_depth"],
                    "allowed_domains": runtime_config.get("allowed_domains"),
                    "cookie_header": runtime_config.get("cookie"),
                    "auth": {
                        "enabled": runtime_config.get("auto_login", False),
                        "login_url": runtime_config.get("auth_login_url"),
                        "username": runtime_config.get("auth_username"),
                        "password": runtime_config.get("auth_password"),
                        "username_field": runtime_config.get("auth_username_field"),
                        "password_field": runtime_config.get("auth_password_field"),
                        "csrf_field": runtime_config.get("auth_csrf_field"),
                        "submit_field": runtime_config.get("auth_submit_field"),
                        "submit_value": runtime_config.get("auth_submit_value"),
                        "success_keyword": runtime_config.get("auth_success_keyword"),
                        "extra_fields": runtime_config.get("auth_extra"),
                    },
                },
                "metadata": {
                    "tool": "vmp-scanner",
                    "tool_version": TOOL_VERSION,
                    "entrypoint": "main.py",
                    "detection": detection_metadata,
                },
            }
        )

        scan_results = collection_bundle.get("network_assets", [])

        open_ports = [item for item in scan_results if item["status"] == "open"]
        logging.info(
            "Network scan completed: total=%d, open=%d, target=%s",
            len(scan_results),
            len(open_ports),
            runtime_config["target"],
        )
        if open_ports:
            open_port_text = ", ".join(
                (
                    f"{item['port']}/{item['service_guess']}"
                    f"(v={item['service_version'] or '-'},conf={item['confidence']})"
                )
                for item in open_ports
            )
            logging.info("Open ports: %s", open_port_text)
        else:
            logging.info("Open ports: none")
        logging.debug("Network scan results: %s", json.dumps(scan_results, ensure_ascii=False))

        crawl_report = collection_bundle.get("web_assets")
        if crawl_report is not None:
            logging.info(
                "Crawler completed: visited=%d, urls=%d, forms=%d, suspicious=%d",
                crawl_report["visited_count"],
                len(crawl_report["urls"]),
                len(crawl_report["forms"]),
                len(crawl_report["suspicious_endpoints"]),
            )
            logging.debug("Crawler report: %s", json.dumps(crawl_report, ensure_ascii=False))

            if runtime_config.get("crawler_output_json"):
                output_path = Path(runtime_config["crawler_output_json"])
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(
                    json.dumps(crawl_report, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                logging.info("Crawler report written to: %s", output_path)

        if collection_bundle.get("errors"):
            logging.warning("Collection layer warnings: %s", collection_bundle["errors"])
        logging.debug("Collection bundle: %s", json.dumps(collection_bundle, ensure_ascii=False))

        detection_service = DetectionService()
        available_plugins = detection_service.list_available_plugins()
        enabled_plugins = resolve_enabled_plugins(runtime_config, available_plugins)
        if enabled_plugins is not None:
            logging.info("Enabled detection plugins: %s", enabled_plugins)

        finding_bundle = detection_service.detect(
            {
                "mode": runtime_config["mode"],
                "collection": collection_bundle,
                "plugin_policy": {
                    "enabled_plugins": enabled_plugins,
                },
            }
        )
        logging.info(
            "Detection completed: findings=%d, plugins(total=%d, success=%d, failed=%d, skipped=%d)",
            len(finding_bundle["findings"]),
            finding_bundle["plugin_stats"]["total"],
            finding_bundle["plugin_stats"]["success"],
            finding_bundle["plugin_stats"]["failed"],
            finding_bundle["plugin_stats"]["skipped"],
        )
        if finding_bundle.get("errors"):
            logging.warning("Detection layer warnings: %s", finding_bundle["errors"])
        logging.debug("Finding bundle: %s", json.dumps(finding_bundle, ensure_ascii=False))

        assessment_service = AssessmentService()
        risk_bundle = assessment_service.assess(
            {
                "findings": finding_bundle,
            }
        )
        summary = risk_bundle["summary"]
        logging.info(
            "Assessment completed: risks=%d, critical=%d, high=%d, medium=%d, low=%d",
            len(risk_bundle["risk_items"]),
            summary["critical"],
            summary["high"],
            summary["medium"],
            summary["low"],
        )
        if risk_bundle.get("errors"):
            logging.warning("Assessment layer warnings: %s", risk_bundle["errors"])
        logging.debug("Risk bundle: %s", json.dumps(risk_bundle, ensure_ascii=False))

        if runtime_config.get("report_json") or runtime_config.get("report_markdown"):
            presentation_service = PresentationService()
            render_result = presentation_service.render(
                {
                    "collection": collection_bundle,
                    "findings": finding_bundle,
                    "risks": risk_bundle,
                    "output": {
                        "json_path": runtime_config.get("report_json"),
                        "markdown_path": runtime_config.get("report_markdown"),
                    },
                    "metadata": {
                        "mode": runtime_config["mode"],
                        "tool_version": TOOL_VERSION,
                        "args": runtime_config,
                    },
                }
            )
            if render_result.get("json_path"):
                logging.info("Risk JSON report written to: %s", render_result["json_path"])
            if render_result.get("markdown_path"):
                logging.info("Risk Markdown report written to: %s", render_result["markdown_path"])

        return 0
    except Exception as exc:
        logging.exception("Task failed: %s", exc)
        return 1
    finally:
        elapsed = time.perf_counter() - start
        logging.info("Task finished in %.3fs", elapsed)


if __name__ == "__main__":
    raise SystemExit(main())
