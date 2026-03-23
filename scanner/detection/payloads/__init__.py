"""Payload dictionaries and metadata."""

from scanner.detection.payloads.manager import PayloadDictionaryManager
from scanner.detection.payloads.sync import sync_from_open_source


def load_payloads(
	category: str,
	mode: str = "test",
	include_high_risk: bool = False,
	include_disabled: bool = False,
) -> list[dict]:
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
