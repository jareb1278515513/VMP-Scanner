from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class Finding:
    """单条漏洞发现模型。"""

    id: str
    plugin: str
    category: str
    title: str
    severity_hint: str
    confidence: float
    location: dict
    evidence: dict
    created_at: str

    def to_dict(self) -> dict:
        """序列化为字典。"""

        return asdict(self)


@dataclass
class FindingBundle:
    """检测结果集合模型。"""

    schema_version: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    plugin_stats: dict = field(
        default_factory=lambda: {
            "total": 0,
            "success": 0,
            "failed": 0,
            "skipped": 0,
        }
    )
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """序列化为字典。"""

        return {
            "schema_version": self.schema_version,
            "target": self.target,
            "findings": [item.to_dict() for item in self.findings],
            "plugin_stats": self.plugin_stats,
            "errors": self.errors,
        }
