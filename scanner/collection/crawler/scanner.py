from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup

from .models import CrawlReport, DiscoveredForm, DiscoveredUrl, FormField, SuspiciousEndpoint

DEFAULT_HEADERS = {
    "User-Agent": "vmp-scanner-crawler/0.1",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

SUSPICIOUS_PATH_MARKERS = (
    "admin",
    "backup",
    ".git",
    "debug",
    "config",
    "phpinfo",
)

SUSPICIOUS_RESPONSE_MARKERS = (
    "sql syntax",
    "traceback",
    "stack trace",
    "exception",
    "warning:",
)


@dataclass(frozen=True)
class CrawlConfig:
    """爬虫运行配置。"""

    start_url: str
    max_depth: int = 2
    timeout: float = 5.0
    allowed_domains: set[str] | None = None
    cookies: dict[str, str] | None = None
    verify_tls: bool = False


def normalize_url(raw_url: str, base_url: str | None = None) -> str:
    """标准化 URL（补全、排序参数、移除片段）。

    Args:
        raw_url: 原始 URL 或相对路径。
        base_url: 可选基准 URL。

    Returns:
        str: 标准化后的绝对 URL。

    Raises:
        ValueError: URL 非法或协议不支持时抛出。
    """

    candidate = (raw_url or "").strip()
    if not candidate:
        raise ValueError("Empty URL is not supported.")

    if base_url:
        candidate = urljoin(base_url, candidate)

    parsed = urlparse(candidate)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme or '<none>'}")

    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("URL host is required.")

    is_default_port = (parsed.scheme == "http" and parsed.port == 80) or (
        parsed.scheme == "https" and parsed.port == 443
    )
    netloc = host
    if parsed.port and not is_default_port:
        netloc = f"{host}:{parsed.port}"

    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path[:-1]

    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    query = urlencode(sorted(query_items), doseq=True)

    return urlunparse((parsed.scheme.lower(), netloc, path, "", query, ""))


def parse_cookie_header(cookie_header: str | None) -> dict[str, str]:
    """解析 ``Cookie`` 请求头为键值对。

    Args:
        cookie_header: 原始 Cookie 字符串。

    Returns:
        dict[str, str]: Cookie 映射。
    """

    if not cookie_header:
        return {}

    cookies: dict[str, str] = {}
    for chunk in cookie_header.split(";"):
        item = chunk.strip()
        if not item:
            continue
        if "=" not in item:
            continue
        key, value = item.split("=", maxsplit=1)
        cookies[key.strip()] = value.strip()
    return cookies


def build_form_login_session(
    base_url: str,
    username: str,
    password: str,
    timeout: float,
    login_url: str | None = None,
    username_field: str = "username",
    password_field: str = "password",
    csrf_field: str = "user_token",
    submit_field: str | None = None,
    submit_value: str | None = None,
    extra_form_fields: dict[str, str] | None = None,
    success_keyword: str | None = None,
    session: requests.Session | None = None,
) -> requests.Session:
    """通过登录表单建立已认证会话。

    Args:
        base_url: 目标站点基地址。
        username: 用户名。
        password: 密码。
        timeout: HTTP 超时时间（秒）。
        login_url: 可选登录页面 URL。
        username_field: 用户名字段名。
        password_field: 密码字段名。
        csrf_field: CSRF 字段名。
        submit_field: 提交按钮字段名。
        submit_value: 提交按钮字段值。
        extra_form_fields: 额外表单字段。
        success_keyword: 判定登录成功的关键字。
        session: 可选外部会话。

    Returns:
        requests.Session: 已登录会话对象。

    Raises:
        ValueError: 登录失败或请求异常时抛出。
    """

    normalized_base = normalize_url(base_url)
    actual_login_url = normalize_url(login_url, base_url=normalized_base) if login_url else normalized_base

    local_session = session or requests.Session()
    local_session.headers.update(DEFAULT_HEADERS)

    try:
        login_page = local_session.get(
            actual_login_url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
        )
        csrf_token = _extract_hidden_input_value(login_page.text, csrf_field)

        login_payload: dict[str, str] = {
            username_field: username,
            password_field: password,
        }
        if submit_field:
            login_payload[submit_field] = submit_value or "Submit"
        if csrf_token:
            login_payload[csrf_field] = csrf_token
        if extra_form_fields:
            login_payload.update(extra_form_fields)

        login_result = local_session.post(
            actual_login_url,
            data=login_payload,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
        )

        if not _is_login_success(login_result, actual_login_url, success_keyword):
            raise ValueError(
                "Form login failed: please verify credentials, login URL, field names, and success keyword."
            )
        return local_session
    except requests.RequestException as exc:
        raise ValueError(f"Form login request failed: {exc}") from exc


def crawl_web_state(
    start_url: str,
    max_depth: int,
    timeout: float,
    allowed_domains: Iterable[str] | None = None,
    cookies: dict[str, str] | None = None,
    session: requests.Session | None = None,
) -> dict:
    """执行页面爬取并提取 URL、表单和可疑端点。

    Args:
        start_url: 起始 URL。
        max_depth: 最大深度。
        timeout: 请求超时。
        allowed_domains: 允许爬取域名集合。
        cookies: 初始 Cookie。
        session: 可复用会话。

    Returns:
        dict: 爬虫报告字典。
    """

    normalized_start = normalize_url(start_url)
    parsed_start = urlparse(normalized_start)

    domain_allowlist = {item.lower().strip() for item in (allowed_domains or []) if item.strip()}
    if not domain_allowlist:
        domain_allowlist = {parsed_start.hostname or ""}

    config = CrawlConfig(
        start_url=normalized_start,
        max_depth=max(0, max_depth),
        timeout=timeout,
        allowed_domains=domain_allowlist,
        cookies=cookies or {},
    )

    local_session = session or requests.Session()
    local_session.headers.update(DEFAULT_HEADERS)
    if config.cookies:
        local_session.cookies.update(config.cookies)

    report = CrawlReport(start_url=config.start_url, max_depth=config.max_depth)
    visited: set[str] = set()
    enqueued: set[str] = {config.start_url}
    url_seen: set[tuple[str, str]] = set()
    form_seen: set[tuple[str, str, str, tuple[tuple[str, str], ...]]] = set()
    suspicious_seen: set[tuple[str, str]] = set()

    queue: deque[tuple[str, int, str | None]] = deque([(config.start_url, 0, None)])

    while queue:
        current_url, depth, source_url = queue.popleft()
        if current_url in visited:
            continue

        visited.add(current_url)
        report.visited_count = len(visited)

        try:
            response = local_session.get(
                current_url,
                timeout=config.timeout,
                allow_redirects=True,
                verify=config.verify_tls,
            )
        except requests.RequestException as exc:
            report.errors.append(f"GET {current_url} failed: {exc}")
            continue

        report.status_code_stats[response.status_code] = (
            report.status_code_stats.get(response.status_code, 0) + 1
        )
        redirect_chain = [item.url for item in response.history] + [response.url]
        if len(redirect_chain) > 1:
            report.redirect_chains.append(redirect_chain)

        normalized_current = normalize_url(response.url)
        current_query_params = [key for key, _ in parse_qsl(urlparse(normalized_current).query)]
        _append_discovered_url(
            report=report,
            url_seen=url_seen,
            url=normalized_current,
            method="GET",
            params=current_query_params,
            source_url=source_url,
            depth=depth,
            status_code=response.status_code,
        )

        if not _is_html_response(response):
            _collect_suspicious_from_response(
                report=report,
                suspicious_seen=suspicious_seen,
                url=normalized_current,
                text=response.text,
                depth=depth,
            )
            continue

        soup = BeautifulSoup(response.text, "html.parser")
        _extract_forms(
            soup=soup,
            page_url=normalized_current,
            depth=depth,
            report=report,
            form_seen=form_seen,
        )

        _collect_suspicious_from_response(
            report=report,
            suspicious_seen=suspicious_seen,
            url=normalized_current,
            text=response.text,
            depth=depth,
        )

        if depth >= config.max_depth:
            continue

        for link in _extract_link_candidates(soup):
            try:
                next_url = normalize_url(link, base_url=normalized_current)
            except ValueError:
                continue

            parsed_next = urlparse(next_url)
            if not _is_domain_allowed(parsed_next.hostname or "", config.allowed_domains):
                continue

            _append_discovered_url(
                report=report,
                url_seen=url_seen,
                url=next_url,
                method="GET",
                params=[key for key, _ in parse_qsl(parsed_next.query)],
                source_url=normalized_current,
                depth=depth + 1,
                status_code=None,
            )

            if next_url not in visited and next_url not in enqueued:
                enqueued.add(next_url)
                queue.append((next_url, depth + 1, normalized_current))

            _collect_suspicious_from_url(
                report=report,
                suspicious_seen=suspicious_seen,
                url=next_url,
                depth=depth + 1,
            )

    return report.to_dict()


def _is_html_response(response: requests.Response) -> bool:
    """判断响应是否为 HTML 内容。"""

    content_type = (response.headers.get("Content-Type") or "").lower()
    if "text/html" in content_type or "application/xhtml+xml" in content_type:
        return True
    return "<html" in response.text[:512].lower()


def _extract_link_candidates(soup: BeautifulSoup) -> list[str]:
    """从文档中提取后续可访问的链接候选。"""

    candidates: list[str] = []

    for tag in soup.select("a[href]"):
        href = (tag.get("href") or "").strip()
        if href and not href.startswith("#"):
            candidates.append(href)

    for tag in soup.select("script[src]"):
        src = (tag.get("src") or "").strip()
        if src:
            candidates.append(src)

    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        if action:
            candidates.append(action)

    return candidates


def _extract_forms(
    soup: BeautifulSoup,
    page_url: str,
    depth: int,
    report: CrawlReport,
    form_seen: set[tuple[str, str, str, tuple[tuple[str, str], ...]]],
) -> None:
    """提取页面表单并写入报告。"""

    for form in soup.find_all("form"):
        raw_action = (form.get("action") or "").strip() or page_url
        try:
            action_url = normalize_url(raw_action, base_url=page_url)
        except ValueError:
            action_url = page_url

        method = (form.get("method") or "GET").upper()
        fields: list[FormField] = []
        has_csrf_token = False

        for field in form.find_all(["input", "textarea", "select"]):
            name = (field.get("name") or "").strip()
            if not name:
                continue
            input_type = (field.get("type") or field.name or "text").lower()
            required = bool(field.has_attr("required"))
            fields.append(FormField(name=name, input_type=input_type, required=required))

            lower_name = name.lower()
            if "csrf" in lower_name or "token" in lower_name:
                has_csrf_token = True

        signature = tuple(sorted((item.name, item.input_type) for item in fields))
        dedup_key = (page_url, action_url, method, signature)
        if dedup_key in form_seen:
            continue
        form_seen.add(dedup_key)

        report.forms.append(
            DiscoveredForm(
                page_url=page_url,
                action=action_url,
                method=method,
                fields=fields,
                has_csrf_token=has_csrf_token,
                depth=depth,
            )
        )


def _append_discovered_url(
    report: CrawlReport,
    url_seen: set[tuple[str, str]],
    url: str,
    method: str,
    params: list[str],
    source_url: str | None,
    depth: int,
    status_code: int | None,
) -> None:
    """将新 URL 记录写入报告并去重。"""

    dedup_key = (url, method.upper())
    if dedup_key in url_seen:
        return
    url_seen.add(dedup_key)

    report.urls.append(
        DiscoveredUrl(
            url=url,
            method=method.upper(),
            params=sorted(set(params)),
            source_url=source_url,
            depth=depth,
            status_code=status_code,
        )
    )


def _is_domain_allowed(hostname: str, allowlist: set[str] | None) -> bool:
    """判断域名是否在允许列表内。"""

    if not allowlist:
        return True

    host = hostname.lower()
    for domain in allowlist:
        normalized_domain = domain.lower().lstrip(".")
        if host == normalized_domain or host.endswith(f".{normalized_domain}"):
            return True
    return False


def _collect_suspicious_from_url(
    report: CrawlReport,
    suspicious_seen: set[tuple[str, str]],
    url: str,
    depth: int,
) -> None:
    """从 URL 文本中提取可疑路径迹象。"""

    low = url.lower()
    for marker in SUSPICIOUS_PATH_MARKERS:
        if marker in low:
            key = (url, marker)
            if key in suspicious_seen:
                return
            suspicious_seen.add(key)
            report.suspicious_endpoints.append(
                SuspiciousEndpoint(
                    url=url,
                    reason="suspicious_path",
                    evidence=f"path contains marker: {marker}",
                    depth=depth,
                )
            )
            return


def _collect_suspicious_from_response(
    report: CrawlReport,
    suspicious_seen: set[tuple[str, str]],
    url: str,
    text: str,
    depth: int,
) -> None:
    """从响应正文中提取可疑回显迹象。"""

    low = text.lower()
    for marker in SUSPICIOUS_RESPONSE_MARKERS:
        if marker in low:
            key = (url, marker)
            if key in suspicious_seen:
                return
            suspicious_seen.add(key)
            report.suspicious_endpoints.append(
                SuspiciousEndpoint(
                    url=url,
                    reason="suspicious_response",
                    evidence=f"response contains marker: {marker}",
                    depth=depth,
                )
            )
            return


def _extract_hidden_input_value(html: str, field_name: str) -> str | None:
    """提取指定隐藏字段的值。"""

    soup = BeautifulSoup(html, "html.parser")
    target = soup.find("input", attrs={"name": field_name})
    if not target:
        return None
    value = target.get("value")
    if value is None:
        return None
    return str(value)


def _is_login_success(
    response: requests.Response,
    login_url: str,
    success_keyword: str | None,
) -> bool:
    """判断登录请求是否成功。"""

    if success_keyword:
        return success_keyword.lower() in response.text.lower()

    normalized_login_url = normalize_url(login_url)
    normalized_current_url = normalize_url(response.url)
    if normalized_current_url != normalized_login_url:
        return True

    fail_markers = ("invalid", "incorrect", "error", "failed")
    low_text = response.text.lower()
    return not any(marker in low_text for marker in fail_markers)


def parse_key_value_pairs(items: Iterable[str] | None) -> dict[str, str]:
    """解析 ``key=value`` 列表。

    Args:
        items: 输入键值串列表。

    Returns:
        dict[str, str]: 解析结果。

    Raises:
        ValueError: 任一项不满足 ``key=value`` 约定时抛出。
    """

    result: dict[str, str] = {}
    for item in items or []:
        raw = item.strip()
        if not raw:
            continue
        if "=" not in raw:
            raise ValueError(f"Invalid key-value format: {item}. Use key=value.")
        key, value = raw.split("=", maxsplit=1)
        result[key.strip()] = value.strip()
    return result
