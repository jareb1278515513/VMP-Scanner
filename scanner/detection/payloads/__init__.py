"""Payload dictionaries and metadata."""

from scanner.detection.payloads.manager import PayloadDictionaryManager
from scanner.detection.payloads.sync import sync_from_open_source


def load_payloads(
	category: str,
	mode: str = "test",
	include_high_risk: bool = False,
	include_disabled: bool = False,
) -> list[dict]:
	"""加载指定分类的 payload 列表。

	Args:
		category: payload 分类。
		mode: 使用模式（``test`` 或 ``attack``）。
		include_high_risk: 是否包含高风险 payload。
		include_disabled: 是否包含默认禁用 payload。

	Returns:
		list[dict]: payload 条目列表。
	"""

	manager = PayloadDictionaryManager()
	return manager.load_payloads(
		category=category,
		mode=mode,
		include_high_risk=include_high_risk,
		include_disabled=include_disabled,
	)


__all__ = [
	"PayloadDictionaryManager",
	"load_payloads",
	"sync_from_open_source",
]
