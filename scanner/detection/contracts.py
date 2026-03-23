from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class Finding:
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
        return asdict(self)


@dataclass
class FindingBundle:
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
        return {
            "schema_version": self.schema_version,
            "target": self.target,
            "findings": [item.to_dict() for item in self.findings],
            "plugin_stats": self.plugin_stats,
            "errors": self.errors,
        }
