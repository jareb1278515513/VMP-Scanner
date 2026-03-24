from __future__ import annotations

import json
from pathlib import Path

VALID_CATEGORIES = {"sqli", "xss", "csrf", "path_traversal"}
VALID_MODES = {"test", "attack"}
VALID_RISK_LEVELS = {"low", "medium", "high"}


class PayloadDictionaryManager:
    """Payload 字典管理器。"""

    def __init__(self, base_dir: str | Path | None = None) -> None:
        """初始化字典根目录并加载目录索引。

        Args:
            base_dir: payload 目录路径；为空时使用当前模块目录。
        """

        self.base_dir = Path(base_dir) if base_dir else Path(__file__).resolve().parent
        self.catalog = self._load_json(self.base_dir / "catalog.json")

    def get_dictionary_version(self) -> str:
        """返回字典版本号。"""

        return str(self.catalog.get("dictionary_version", "unknown"))

    def get_changelog(self) -> list[dict]:
        """返回字典变更记录。"""

        return list(self.catalog.get("changelog", []))

    def list_categories(self) -> list[str]:
        """返回已配置的 payload 分类。"""

        categories = self.catalog.get("categories", {})
        return sorted(categories.keys())

    def load_payloads(
        self,
        category: str,
        mode: str = "test",
        include_high_risk: bool = False,
        include_disabled: bool = False,
    ) -> list[dict]:
        """按分类与模式加载 payload。

        Args:
            category: payload 分类名。
            mode: 使用模式（``test`` 或 ``attack``）。
            include_high_risk: 是否包含高风险 payload。
            include_disabled: 是否包含默认禁用 payload。

        Returns:
            list[dict]: 过滤后的 payload 列表。

        Raises:
            ValueError: 分类、模式或字典格式非法时抛出。
        """

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
        """批量加载多个分类的 payload。"""

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
        """校验单条 payload 记录结构与枚举值。"""

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
        """读取 JSON 文件。"""

        with path.open("r", encoding="utf-8") as fp:
            return json.load(fp)
