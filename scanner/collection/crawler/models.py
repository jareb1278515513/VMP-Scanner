from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class DiscoveredUrl:
    """爬虫发现的 URL 记录。"""

    url: str
    method: str
    params: list[str]
    source_url: str | None
    depth: int
    status_code: int | None

    def to_dict(self) -> dict:
        """序列化为字典。"""

        return asdict(self)


@dataclass(frozen=True)
class FormField:
    """表单字段描述。"""

    name: str
    input_type: str
    required: bool


@dataclass(frozen=True)
class DiscoveredForm:
    """爬虫发现的表单信息。"""

    page_url: str
    action: str
    method: str
    fields: list[FormField]
    has_csrf_token: bool
    depth: int

    def to_dict(self) -> dict:
        """序列化为字典。"""

        payload = asdict(self)
        payload["fields"] = [asdict(field) for field in self.fields]
        return payload


@dataclass(frozen=True)
class SuspiciousEndpoint:
    """可疑端点记录。"""

    url: str
    reason: str
    evidence: str
    depth: int

    def to_dict(self) -> dict:
        """序列化为字典。"""

        return asdict(self)


@dataclass
class CrawlReport:
    """爬取结果聚合模型。"""

    start_url: str
    max_depth: int
    visited_count: int = 0
    status_code_stats: dict[int, int] = field(default_factory=dict)
    redirect_chains: list[list[str]] = field(default_factory=list)
    urls: list[DiscoveredUrl] = field(default_factory=list)
    forms: list[DiscoveredForm] = field(default_factory=list)
    suspicious_endpoints: list[SuspiciousEndpoint] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """序列化为字典。"""

        return {
            "start_url": self.start_url,
            "max_depth": self.max_depth,
            "visited_count": self.visited_count,
            "status_code_stats": self.status_code_stats,
            "redirect_chains": self.redirect_chains,
            "urls": [item.to_dict() for item in self.urls],
            "forms": [item.to_dict() for item in self.forms],
            "suspicious_endpoints": [item.to_dict() for item in self.suspicious_endpoints],
            "errors": self.errors,
        }
