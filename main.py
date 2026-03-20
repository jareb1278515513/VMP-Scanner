import argparse
import json
import logging
import time
from dataclasses import asdict, dataclass

from scanner.collection.network.scanner import normalize_target_host, parse_ports, scan_host_ports


@dataclass(frozen=True)
class DefaultConfig:
    target: str = "127.0.0.1"
    mode: str = "test"
    max_depth: int = 2
    concurrency: int = 20
    timeout: float = 1.0
    ports: str = "80,443,8080,3306"
    port_range: str | None = None
    grab_banner: bool = False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vmp-scanner",
        description="VMP-Scanner CLI entrypoint",
    )
    parser.add_argument("--target", help="Target host or URL")
    parser.add_argument(
        "--mode",
        choices=("test", "attack"),
        help="Run mode: test (safe) or attack (aggressive)",
    )
    parser.add_argument("--max-depth", type=int, help="Crawler max depth")
    parser.add_argument("--concurrency", type=int, help="Worker concurrency")
    parser.add_argument("--timeout", type=float, help="Network timeout in seconds")
    parser.add_argument("--ports", help="Comma-separated ports, for example 80,443,3306")
    parser.add_argument("--port-range", help="Port range, for example 1-1024")
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
        config["mode"] = args.mode
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
    if args.grab_banner:
        config["grab_banner"] = True

    return config


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)s | %(message)s",
    )


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    configure_logging(args.log_level)

    start = time.perf_counter()
    logging.info("Task started")

    try:
        runtime_config = load_runtime_config(args)
        logging.info("Runtime config: %s", json.dumps(runtime_config, ensure_ascii=False))

        target_host = normalize_target_host(runtime_config["target"])
        port_list = parse_ports(runtime_config.get("ports"), runtime_config.get("port_range"))
        scan_results = scan_host_ports(
            host=target_host,
            ports=port_list,
            timeout=runtime_config["timeout"],
            concurrency=runtime_config["concurrency"],
            grab_banner=runtime_config["grab_banner"],
        )

        open_ports = [item for item in scan_results if item["status"] == "open"]
        logging.info(
            "Network scan completed: total=%d, open=%d, target=%s",
            len(scan_results),
            len(open_ports),
            target_host,
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
        return 0
    except Exception as exc:
        logging.exception("Task failed: %s", exc)
        return 1
    finally:
        elapsed = time.perf_counter() - start
        logging.info("Task finished in %.3fs", elapsed)


if __name__ == "__main__":
    raise SystemExit(main())
