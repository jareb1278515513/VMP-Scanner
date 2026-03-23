from __future__ import annotations

import json
from pathlib import Path

VALID_CATEGORIES = {"sqli", "xss", "csrf", "path_traversal"}
VALID_MODES = {"test", "attack"}
VALID_RISK_LEVELS = {"low", "medium", "high"}


class PayloadDictionaryManager:
    def __init__(self, base_dir: str | Path | None = None) -> None:
        self.base_dir = Path(base_dir) if base_dir else Path(__file__).resolve().parent
        self.catalog = self._load_json(self.base_dir / "catalog.json")

    def get_dictionary_version(self) -> str:
        return str(self.catalog.get("dictionary_version", "unknown"))

    def get_changelog(self) -> list[dict]:
        return list(self.catalog.get("changelog", []))

    def list_categories(self) -> list[str]:
        categories = self.catalog.get("categories", {})
        return sorted(categories.keys())

    def load_payloads(
        self,
        category: str,
        mode: str = "test",
        include_high_risk: bool = False,
        include_disabled: bool = False,
    ) -> list[dict]:
        category = category.strip().lower()
        mode = mode.strip().lower()

        if category not in VALID_CATEGORIES:
            raise ValueError(f"Unsupported payload category: {category}")
        if mode not in VALID_MODES:
            raise ValueError(f"Unsupported payload mode: {mode}")

        categories = self.catalog.get("categories", {})
        rel_path = categories.get(category)
        if not rel_path:
            raise ValueError(f"Category not found in catalog: {category}")

        records = self._load_json(self.base_dir / rel_path)
        if not isinstance(records, list):
            raise ValueError(f"Payload dictionary must be a list: {rel_path}")

        filtered: list[dict] = []
        for record in records:
            self._validate_record(record, category)

            if record["mode"] != mode:
                continue
            if not include_high_risk and record["risk_level"] == "high":
                continue
            if not include_disabled and not bool(record["enabled_by_default"]):
                continue
            filtered.append(record)

        return filtered

    def load_payload_bundle(
        self,
        categories: list[str],
        mode: str = "test",
        include_high_risk: bool = False,
        include_disabled: bool = False,
    ) -> dict[str, list[dict]]:
        result: dict[str, list[dict]] = {}
        for category in categories:
            result[category] = self.load_payloads(
                category=category,
                mode=mode,
                include_high_risk=include_high_risk,
                include_disabled=include_disabled,
            )
        return result

    def _validate_record(self, record: dict, category: str) -> None:
        required = {
            "id",
            "payload",
            "mode",
            "risk_level",
            "enabled_by_default",
            "purpose",
            "expected_feature",
            "source",
        }
        missing = required.difference(record.keys())
        if missing:
            raise ValueError(f"Payload record missing keys {sorted(missing)} in {category}")

        if record["mode"] not in VALID_MODES:
            raise ValueError(f"Invalid mode in payload {record.get('id')}: {record['mode']}")
        if record["risk_level"] not in VALID_RISK_LEVELS:
            raise ValueError(
                f"Invalid risk level in payload {record.get('id')}: {record['risk_level']}"
            )

    @staticmethod
    def _load_json(path: Path):
        with path.open("r", encoding="utf-8") as fp:
            return json.load(fp)
