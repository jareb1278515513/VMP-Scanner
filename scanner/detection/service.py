from __future__ import annotations

from dataclasses import dataclass, field

from scanner.detection.executor import DetectionExecutor


@dataclass(frozen=True)
class DetectionRequest:
    collection: dict
    mode: str = "test"
    plugin_policy: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)


class DetectionService:
    def __init__(self, executor: DetectionExecutor | None = None) -> None:
        self.executor = executor or DetectionExecutor()

    def detect(self, request: DetectionRequest | dict) -> dict:
        normalized = _coerce_request(request)

        mode = normalized.mode
        if mode == "detect":
            mode = "test"

        enabled_plugins = (normalized.plugin_policy or {}).get("enabled_plugins")
        return self.executor.run(
            collection_bundle=normalized.collection,
            mode=mode,
            enabled_plugins=enabled_plugins,
        )

    def list_available_plugins(self) -> list[str]:
        return [
            plugin.metadata().get("name", plugin.__class__.__name__)
            for plugin in self.executor.registry.list_plugins()
        ]


def _coerce_request(request: DetectionRequest | dict) -> DetectionRequest:
    if isinstance(request, DetectionRequest):
        return request

    if not isinstance(request, dict):
        raise ValueError("DetectionService.detect request must be DetectionRequest or dict.")

    collection = request.get("collection")
    if not isinstance(collection, dict) or not collection:
        raise ValueError("Detection request missing required field: collection")

    mode = str(request.get("mode", "test")).strip().lower()
    if mode not in {"detect", "test", "attack"}:
        raise ValueError(f"Unsupported detection mode: {mode}")

    plugin_policy = request.get("plugin_policy") or {}
    metadata = request.get("metadata") or {}

    if not isinstance(plugin_policy, dict):
        raise ValueError("Detection request field plugin_policy must be dict")
    if not isinstance(metadata, dict):
        raise ValueError("Detection request field metadata must be dict")

    return DetectionRequest(
        collection=collection,
        mode=mode,
        plugin_policy=plugin_policy,
        metadata=metadata,
    )
