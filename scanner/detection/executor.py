from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from scanner.detection.contracts import Finding, FindingBundle
from scanner.detection.plugins import load_default_plugins
from scanner.detection.registry import PluginRegistry


class DetectionExecutor:
    """检测执行器。

    负责遍历插件并将候选结果归并为 ``FindingBundle``。
    """

    schema_version = "1.0"

    def __init__(self, registry: PluginRegistry | None = None) -> None:
        """初始化插件注册表并装载默认插件。

        Args:
            registry: 可选插件注册表；为空时自动创建。
        """

        self.registry = registry or PluginRegistry()
        for plugin in load_default_plugins():
            self.registry.register(plugin)

    def run(
        self,
        collection_bundle: dict,
        mode: str = "test",
        enabled_plugins: list[str] | None = None,
    ) -> dict:
        """执行插件检测流程。

        Args:
            collection_bundle: 采集层输出。
            mode: 执行模式（``test`` 或 ``attack``）。
            enabled_plugins: 可选插件白名单。

        Returns:
            dict: 标准化 finding bundle。
        """

        target = collection_bundle.get("target") or "unknown"
        bundle = FindingBundle(schema_version=self.schema_version, target=target)

        plugins = self.registry.get_plugins(enabled_plugins)
        bundle.plugin_stats["total"] = len(plugins)

        for plugin in plugins:
            metadata = plugin.metadata()
            plugin_name = metadata.get("name", plugin.__class__.__name__)

            try:
                if not plugin.match(collection_bundle, mode):
                    bundle.plugin_stats["skipped"] += 1
                    continue

                candidates = plugin.probe(collection_bundle, mode)
                accepted_count = 0
                for candidate in candidates:
                    if not plugin.verify(candidate, collection_bundle):
                        continue

                    finding = Finding(
                        id=f"finding-{uuid4().hex[:12]}",
                        plugin=plugin_name,
                        category=metadata.get("category", "unknown"),
                        title=candidate.get("title", metadata.get("title", plugin_name)),
                        severity_hint=candidate.get(
                            "severity_hint",
                            metadata.get("severity_hint", "low"),
                        ),
                        confidence=float(candidate.get("confidence", metadata.get("confidence", 0.5))),
                        location=candidate.get("location", {}),
                        evidence=plugin.evidence(candidate),
                        created_at=_utc_now_iso(),
                    )
                    bundle.findings.append(finding)
                    accepted_count += 1

                bundle.plugin_stats["success"] += 1
                if accepted_count == 0:
                    bundle.errors.append(f"plugin_no_findings:{plugin_name}")
            except Exception as exc:
                bundle.plugin_stats["failed"] += 1
                bundle.errors.append(f"plugin_failed:{plugin_name}:{exc}")

        return bundle.to_dict()


def _utc_now_iso() -> str:
    """获取 UTC ISO8601 时间字符串。"""

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
