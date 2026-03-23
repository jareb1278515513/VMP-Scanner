from __future__ import annotations

from scanner.detection.base import DetectionPlugin


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, DetectionPlugin] = {}

    def register(self, plugin: DetectionPlugin) -> None:
        name = plugin.metadata().get("name")
        if not name:
            raise ValueError("Plugin metadata must include name.")
        self._plugins[name] = plugin

    def list_plugins(self) -> list[DetectionPlugin]:
        return list(self._plugins.values())

    def get_plugins(self, names: list[str] | None = None) -> list[DetectionPlugin]:
        if not names:
            return self.list_plugins()
        return [plugin for name, plugin in self._plugins.items() if name in names]
