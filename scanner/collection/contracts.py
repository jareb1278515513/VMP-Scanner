from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class NetworkCollectionOptions:
    ports: str | None = "80,443,8080,3306"
    port_range: str | None = None
    grab_banner: bool = False


@dataclass(frozen=True)
class AuthOptions:
    enabled: bool = False
    login_url: str | None = None
    username: str = "admin"
    password: str = "password"
    username_field: str = "username"
    password_field: str = "password"
    csrf_field: str = "user_token"
    submit_field: str | None = None
    submit_value: str | None = None
    success_keyword: str | None = None
    extra_fields: list[str] | None = None


@dataclass(frozen=True)
class CrawlerCollectionOptions:
    enabled: bool = True
    max_depth: int = 2
    allowed_domains: list[str] | None = None
    cookie_header: str | None = None
    auth: AuthOptions = field(default_factory=AuthOptions)


@dataclass(frozen=True)
class CollectionRequest:
    target: str
    mode: str = "test"
    timeout: float = 1.0
    concurrency: int = 20
    network: NetworkCollectionOptions = field(default_factory=NetworkCollectionOptions)
    crawler: CrawlerCollectionOptions = field(default_factory=CrawlerCollectionOptions)
    metadata: dict = field(default_factory=dict)


@dataclass
class CollectionBundle:
    schema_version: str
    target: str
    started_at: str
    finished_at: str
    network_assets: list[dict] = field(default_factory=list)
    web_assets: dict | None = None
    errors: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)
