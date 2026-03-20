import argparse
import json
import logging
import time
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class DefaultConfig:
    target: str = "127.0.0.1"
    mode: str = "test"
    max_depth: int = 2
    concurrency: int = 20
    timeout: float = 1.0


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

        # Placeholder for future pipeline orchestration.
        logging.info("Initialization completed")
        return 0
    except Exception as exc:
        logging.exception("Task failed: %s", exc)
        return 1
    finally:
        elapsed = time.perf_counter() - start
        logging.info("Task finished in %.3fs", elapsed)


if __name__ == "__main__":
    raise SystemExit(main())
