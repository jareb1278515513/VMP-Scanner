from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow direct script execution: `python tools/sync_payloads.py`
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.detection.payloads import sync_from_open_source


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sync payload dictionaries from open-source repositories")
    parser.add_argument(
        "--payload-dir",
        default="scanner/detection/payloads",
        help="Payload dictionary directory",
    )
    parser.add_argument(
        "--max-per-category",
        type=int,
        default=200,
        help="Maximum payload entries imported per category",
    )
    parser.add_argument(
        "--repo-ref",
        default="master",
        help="Git ref (branch/tag/commit) of PayloadsAllTheThings to sync from",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=20.0,
        help="HTTP timeout in seconds",
    )
    parser.add_argument(
        "--incremental",
        action="store_true",
        help="Merge imported payloads with local dictionaries instead of full overwrite",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    payload_dir = Path(args.payload_dir)

    counts = sync_from_open_source(
        base_dir=payload_dir,
        repo_ref=args.repo_ref,
        timeout=args.timeout,
        max_per_category=args.max_per_category,
        incremental=args.incremental,
    )

    print("Payload sync completed")
    for category, count in sorted(counts.items()):
        print(f"- {category}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
