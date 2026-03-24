from __future__ import annotations

from scanner.detection.base import DetectionPlugin


class PluginRegistry:
    """检测插件注册表。"""

    def __init__(self) -> None:
        """初始化空插件映射。"""

        self._plugins: dict[str, DetectionPlugin] = {}

    def register(self, plugin: DetectionPlugin) -> None:
        """注册插件实例。

        Args:
            plugin: 待注册插件。

        Raises:
            ValueError: 插件元数据中缺少名称时抛出。
        """

        name = plugin.metadata().get("name")
        if not name:
            raise ValueError("Plugin metadata must include name.")
        self._plugins[name] = plugin

    def list_plugins(self) -> list[DetectionPlugin]:
        """返回全部插件实例列表。"""

        return list(self._plugins.values())

    def get_plugins(self, names: list[str] | None = None) -> list[DetectionPlugin]:
        """按名称筛选插件。

        Args:
            names: 插件名称列表；为空时返回全部。

        Returns:
            list[DetectionPlugin]: 过滤后的插件实例列表。
        """

        if not names:
            return self.list_plugins()
        return [plugin for name, plugin in self._plugins.items() if name in names]
