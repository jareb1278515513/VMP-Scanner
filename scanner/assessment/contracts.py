from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class AssessmentRequest:
    findings: dict
    weights: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)


@dataclass(frozen=True)
class RiskItem:
    finding_id: str
    plugin: str
    category: str
    title: str
    score: float
    level: str
    impact: int
    likelihood: int
    confidence: float
    exposure_weight: float
    recommendation: str
    retest: str
    location: dict
    evidence: dict

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RiskBundle:
    schema_version: str
    target: str
    risk_items: list[RiskItem] = field(default_factory=list)
    summary: dict = field(
        default_factory=lambda: {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
    )
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "target": self.target,
            "risk_items": [item.to_dict() for item in self.risk_items],
            "summary": self.summary,
            "errors": self.errors,
        }
