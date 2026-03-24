from __future__ import annotations

import json
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from pathlib import Path
from dataclasses import asdict, dataclass
from typing import Iterable
from urllib.parse import urlparse


CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"

PROBE_FUNCTIONS = {
    "http": "_probe_http",
    "https": "_probe_https",
    "ssh": "_probe_ssh",
    "mysql": "_probe_mysql",
    "redis": "_probe_redis",
    "smtp": "_probe_smtp",
    "database_banner": "_probe_database_banner",
}


@dataclass(frozen=True)
class ServiceDetection:
    """服务识别结果。"""

    service: str
    version: str | None
    confidence: str


@dataclass(frozen=True)
class PortScanResult:
    """单端口扫描结果。"""

    host: str
    port: int
    status: str
    service_guess: str
    service_version: str | None
    confidence: str
    response_time_ms: float
    banner: str | None = None

    def to_dict(self) -> dict:
        """序列化为字典。"""

        return asdict(self)


def normalize_target_host(target: str) -> str:
    """从主机或 URL 中提取目标主机名。"""

    parsed = urlparse(target)
    if parsed.scheme:
        return parsed.hostname or target
    return target


def parse_ports(port_list: str | None, port_range: str | None) -> list[int]:
    """解析端口参数。

    Args:
        port_list: 逗号分隔端口列表。
        port_range: 范围表达式（如 ``1-1024``）。

    Returns:
        list[int]: 排序后的端口列表。

    Raises:
        ValueError: 输入冲突或格式非法时抛出。
    """

    if port_list and port_range:
        raise ValueError("Use either port_list or port_range, not both.")

    if port_list:
        ports = {int(item.strip()) for item in port_list.split(",") if item.strip()}
        return sorted(_validate_ports(ports))

    if port_range:
        start, end = _parse_port_range(port_range)
        return list(range(start, end + 1))

    return [80, 443, 8080, 3306]


def scan_host_ports(
    host: str,
    ports: Iterable[int],
    timeout: float,
    concurrency: int,
    grab_banner: bool = False,
) -> list[dict]:
    """并发扫描目标主机端口。

    Args:
        host: 目标主机。
        ports: 待扫描端口集合。
        timeout: 单次连接超时（秒）。
        concurrency: 并发线程数。
        grab_banner: 是否尝试读取服务 banner。

    Returns:
        list[dict]: 端口扫描结果列表。
    """

    results: list[PortScanResult] = []

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as executor:
        futures = {
            executor.submit(_scan_single_port, host, port, timeout, grab_banner): port
            for port in ports
        }
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda item: item.port)
    return [item.to_dict() for item in results]


def _scan_single_port(host: str, port: int, timeout: float, grab_banner: bool) -> PortScanResult:
    """扫描单个端口并尝试识别服务。"""

    t0 = time.perf_counter()
    status = "closed"
    banner = None

    try:
        addr_info = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        family, socktype, proto, _, sockaddr = addr_info[0]
        with socket.socket(family, socktype, proto) as sock:
            sock.settimeout(timeout)
            code = sock.connect_ex(sockaddr)
            if code == 0:
                status = "open"
                if grab_banner:
                    banner = _read_banner(sock)
            else:
                status = "closed"
    except TimeoutError:
        status = "filtered"
    except OSError:
        status = "filtered"

    elapsed_ms = (time.perf_counter() - t0) * 1000
    if status == "open":
        detection = _identify_service(host, port, timeout, banner)
    else:
        detection = ServiceDetection("unknown", None, CONFIDENCE_LOW)

    return PortScanResult(
        host=host,
        port=port,
        status=status,
        service_guess=detection.service,
        service_version=detection.version,
        confidence=detection.confidence,
        response_time_ms=round(elapsed_ms, 3),
        banner=banner,
    )


def _read_banner(sock: socket.socket) -> str | None:
    """从已建立连接的 socket 读取轻量 banner。"""

    try:
        sock.sendall(b"\r\n")
        data = sock.recv(256)
        if not data:
            return None
        return data.decode("utf-8", errors="replace").strip() or None
    except OSError:
        return None


def _identify_service(host: str, port: int, timeout: float, banner: str | None) -> ServiceDetection:
    """通过 banner 与主动探测识别服务类型和版本。"""

    rules = _load_fingerprint_rules()

    from_banner = _guess_from_banner(banner)
    if from_banner:
        return from_banner

    for probe in _probe_order_for_port(port, rules):
        detected = probe(host, port, timeout)
        if detected:
            return detected

    from_port = _guess_service_by_port(port, rules)
    if from_port:
        return from_port
    return ServiceDetection("unknown", None, CONFIDENCE_LOW)


def _guess_from_banner(banner: str | None) -> ServiceDetection | None:
    """基于 banner 关键字进行服务猜测。"""

    if not banner:
        return None

    rules = _load_fingerprint_rules()
    low = banner.lower()
    for hint in rules["service_hints"]:
        marker = hint.get("marker", "").lower()
        service = hint.get("service", "unknown")
        version_regex = hint.get("version_regex")
        if marker in low:
            version = _extract_version_from_text(banner, version_regex)
            return ServiceDetection(service, version, CONFIDENCE_HIGH)
    return None


def _probe_order_for_port(port: int, rules: dict) -> list:
    """根据端口返回探测函数顺序。"""

    probe_order_cfg = rules["probe_order"]
    names = probe_order_cfg.get(str(port), probe_order_cfg.get("default", []))

    functions: list = []
    for name in names:
        fn_name = PROBE_FUNCTIONS.get(name)
        if fn_name and fn_name in globals():
            functions.append(globals()[fn_name])
    return functions


def _probe_http(host: str, port: int, timeout: float) -> ServiceDetection | None:
    """HTTP 主动探测。"""

    payload = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
    data = _send_and_recv_tcp(host, port, timeout, payload)
    if data.startswith(b"HTTP/") or b"Server:" in data:
        text = data.decode("utf-8", errors="replace")
        version = _extract_version_from_http_header(text)
        return ServiceDetection("http", version, CONFIDENCE_HIGH)
    return None


def _probe_https(host: str, port: int, timeout: float) -> ServiceDetection | None:
    """HTTPS/TLS 主动探测。"""

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                payload = (
                    f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
                )
                tls_sock.settimeout(timeout)
                tls_sock.sendall(payload)
                data = tls_sock.recv(256)
                if data.startswith(b"HTTP/") or b"Server:" in data:
                    text = data.decode("utf-8", errors="replace")
                    version = _extract_version_from_http_header(text)
                    return ServiceDetection("https", version, CONFIDENCE_HIGH)
                return ServiceDetection("tls", None, CONFIDENCE_MEDIUM)
    except OSError:
        return None


def _probe_ssh(host: str, port: int, timeout: float) -> ServiceDetection | None:
    """SSH 协议探测。"""

    data = _send_and_recv_tcp(host, port, timeout, b"", recv_first=True)
    if data.startswith(b"SSH-"):
        text = data.decode("utf-8", errors="replace")
        version = _extract_version_from_text(text, r"SSH-[\d.]+-([^\s]+)")
        return ServiceDetection("ssh", version, CONFIDENCE_HIGH)
    return None


def _probe_mysql(host: str, port: int, timeout: float) -> ServiceDetection | None:
    """MySQL 协议探测。"""

    data = _send_and_recv_tcp(host, port, timeout, b"", recv_first=True)
    if len(data) > 5 and data[4] == 0x0A:
        text = data.decode("utf-8", errors="replace")
        version = _extract_version_from_text(text, r"(\d+\.\d+(?:\.\d+)*)")
        return ServiceDetection("mysql", version, CONFIDENCE_HIGH)
    if b"mysql" in data.lower():
        return ServiceDetection("mysql", None, CONFIDENCE_MEDIUM)
    return None


def _probe_redis(host: str, port: int, timeout: float) -> ServiceDetection | None:
    """Redis 协议探测。"""

    data = _send_and_recv_tcp(host, port, timeout, b"*1\r\n$4\r\nPING\r\n")
    if data.startswith(b"+PONG") or b"redis" in data.lower():
        return ServiceDetection("redis", None, CONFIDENCE_HIGH)
    return None


def _probe_smtp(host: str, port: int, timeout: float) -> ServiceDetection | None:
    """SMTP 协议探测。"""

    data = _send_and_recv_tcp(host, port, timeout, b"EHLO scanner\r\n", recv_first=True)
    if data.startswith(b"220") or b"smtp" in data.lower():
        text = data.decode("utf-8", errors="replace")
        version = _extract_version_from_text(text, r"(?:ESMTP|SMTP)\s+([^\s]+)")
        return ServiceDetection("smtp", version, CONFIDENCE_HIGH)
    return None


def _probe_database_banner(host: str, port: int, timeout: float) -> ServiceDetection | None:
    """通用数据库 banner 探测。"""

    data = _send_and_recv_tcp(host, port, timeout, b"", recv_first=True)
    low = data.lower()
    if b"postgres" in low:
        return ServiceDetection("postgresql", None, CONFIDENCE_MEDIUM)
    if b"oracle" in low:
        return ServiceDetection("oracle", None, CONFIDENCE_MEDIUM)
    if b"sql server" in low or b"mssql" in low:
        return ServiceDetection("mssql", None, CONFIDENCE_MEDIUM)
    return None


def _send_and_recv_tcp(
    host: str,
    port: int,
    timeout: float,
    payload: bytes,
    recv_first: bool = False,
) -> bytes:
    """建立 TCP 连接并进行一次收发。"""

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if recv_first:
                first = sock.recv(256)
                if first:
                    return first
            if payload:
                sock.sendall(payload)
            return sock.recv(256)
    except OSError:
        return b""


def _guess_service_by_port(port: int, rules: dict) -> ServiceDetection | None:
    """在主动探测失败时按端口号回退猜测服务。"""

    common_ports = rules["common_service_ports"]
    if str(port) in common_ports:
        return ServiceDetection(common_ports[str(port)], None, CONFIDENCE_LOW)
    try:
        name = socket.getservbyport(port, "tcp")
        return ServiceDetection(name, None, CONFIDENCE_LOW)
    except OSError:
        return None


def _extract_version_from_http_header(text: str) -> str | None:
    """从 HTTP 头中提取服务版本。"""

    return _extract_version_from_text(text, r"Server:\s*[^/]+/([\w.\-]+)")


def _extract_version_from_text(text: str, pattern: str | None) -> str | None:
    """按正则模式从文本中提取版本号。"""

    if not pattern:
        return None
    match = re.search(pattern, text, flags=re.IGNORECASE)
    if match:
        return match.group(1)
    return None


@lru_cache(maxsize=1)
def _load_fingerprint_rules() -> dict:
    """加载端口服务指纹规则。"""

    config_path = Path(__file__).with_name("service_fingerprints.json")
    with config_path.open("r", encoding="utf-8") as fp:
        return json.load(fp)


def _parse_port_range(raw: str) -> tuple[int, int]:
    """解析端口范围字符串。"""

    parts = raw.split("-", maxsplit=1)
    if len(parts) != 2:
        raise ValueError("Port range must be in start-end format, for example 1-1024.")

    start = int(parts[0].strip())
    end = int(parts[1].strip())
    if start > end:
        raise ValueError("Port range start cannot be greater than end.")

    _validate_ports({start, end})
    return start, end


def _validate_ports(ports: set[int]) -> set[int]:
    """校验端口范围合法性。"""

    for port in ports:
        if port < 1 or port > 65535:
            raise ValueError(f"Invalid port: {port}. Valid range is 1-65535.")
    return ports