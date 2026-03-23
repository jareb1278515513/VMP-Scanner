from __future__ import annotations

from dataclasses import dataclass

import requests

from scanner.collection.crawler.scanner import (
    build_form_login_session,
    crawl_web_state,
    normalize_url,
    parse_key_value_pairs,
    parse_cookie_header,
)


@dataclass
class FakeResponse:
    url: str
    status_code: int
    text: str
    headers: dict[str, str]
    history: list["FakeResponse"] | None = None


class FakeSession:
    def __init__(self, mapping: dict[str, FakeResponse]) -> None:
        self.mapping = mapping
        self.headers: dict[str, str] = {}
        self.cookies = requests.cookies.RequestsCookieJar()

    def get(
        self,
        url: str,
        timeout: float,
        allow_redirects: bool,
        verify: bool,
    ) -> FakeResponse:
        if url not in self.mapping:
            raise requests.RequestException(f"No fake route for {url}")
        return self.mapping[url]


class FakeLoginSession:
    def __init__(self) -> None:
        self.headers: dict[str, str] = {}
        self.cookies = requests.cookies.RequestsCookieJar()
        self.calls: list[tuple[str, str]] = []

    def get(self, url: str, timeout: float, allow_redirects: bool, verify: bool) -> FakeResponse:
        self.calls.append(("GET", url))
        if url.endswith("/login.php"):
            return FakeResponse(
                url=url,
                status_code=200,
                text='<form><input name="user_token" value="token-login"></form>',
                headers={"Content-Type": "text/html"},
                history=[],
            )
        raise requests.RequestException(f"Unexpected GET: {url}")

    def post(
        self,
        url: str,
        data: dict[str, str],
        timeout: float,
        allow_redirects: bool,
        verify: bool,
    ) -> FakeResponse:
        self.calls.append(("POST", url))
        if url.endswith("/login.php"):
            return FakeResponse(
                url="http://127.0.0.1/dvwa/index.php",
                status_code=200,
                text="<a href=\"logout.php\">Logout</a>",
                headers={"Content-Type": "text/html"},
                history=[],
            )
        raise requests.RequestException(f"Unexpected POST: {url}")


def test_normalize_url_sorts_query_and_removes_fragment() -> None:
    normalized = normalize_url("http://Example.com/path/?b=2&a=1#frag")
    assert normalized == "http://example.com/path?a=1&b=2"


def test_parse_cookie_header() -> None:
    cookies = parse_cookie_header("PHPSESSID=abc; security=low; invalid")
    assert cookies == {"PHPSESSID": "abc", "security": "low"}


def test_crawl_extracts_urls_forms_and_suspicious() -> None:
    index_html = """
    <html>
      <body>
        <a href="/login.php?b=2&a=1">login</a>
        <a href="http://external.test/out">out</a>
        <form action="/submit.php" method="post">
          <input name="username" type="text" required>
          <input name="csrf_token" type="hidden" value="x">
        </form>
      </body>
    </html>
    """
    login_html = "<html><body>Warning: SQL syntax error near ...</body></html>"

    fake_session = FakeSession(
        {
            "http://example.com/": FakeResponse(
                url="http://example.com/",
                status_code=200,
                text=index_html,
                headers={"Content-Type": "text/html"},
                history=[],
            ),
            "http://example.com/login.php?a=1&b=2": FakeResponse(
                url="http://example.com/login.php?a=1&b=2",
                status_code=200,
                text=login_html,
                headers={"Content-Type": "text/html"},
                history=[],
            ),
            "http://example.com/submit.php": FakeResponse(
                url="http://example.com/submit.php",
                status_code=200,
                text="ok",
                headers={"Content-Type": "text/html"},
                history=[],
            ),
        }
    )

    result = crawl_web_state(
        start_url="http://example.com/",
        max_depth=1,
        timeout=1,
        allowed_domains=["example.com"],
        session=fake_session,
    )

    urls = {item["url"] for item in result["urls"]}
    assert "http://example.com/" in urls
    assert "http://example.com/login.php?a=1&b=2" in urls
    assert "http://external.test/out" not in urls

    assert len(result["forms"]) == 1
    form = result["forms"][0]
    assert form["action"] == "http://example.com/submit.php"
    assert form["method"] == "POST"
    assert form["has_csrf_token"] is True

    suspicious_reasons = {item["reason"] for item in result["suspicious_endpoints"]}
    assert "suspicious_response" in suspicious_reasons


def test_build_form_login_session_success() -> None:
    fake_session = FakeLoginSession()

    session = build_form_login_session(
        base_url="http://127.0.0.1/dvwa/",
        login_url="/dvwa/login.php",
        username="admin",
        password="password",
        timeout=2,
        submit_field="Login",
        submit_value="Login",
        success_keyword="logout.php",
        extra_form_fields={"security": "low"},
        session=fake_session,
    )

    assert session is fake_session
    assert ("GET", "http://127.0.0.1/dvwa/login.php") in fake_session.calls
    assert ("POST", "http://127.0.0.1/dvwa/login.php") in fake_session.calls


def test_parse_key_value_pairs() -> None:
    data = parse_key_value_pairs(["a=1", "b=hello"])
    assert data == {"a": "1", "b": "hello"}
