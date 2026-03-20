from __future__ import annotations

import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Iterable
from urllib.parse import urlparse


COMMON_SERVICE_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    465: "smtps",
    587: "smtp",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",
    8080: "http",
    8443: "https",
}

SERVICE_HINTS: dict[str, str] = {
    "server: nginx": "http",
    "server: apache": "http",
    "server: iis": "http",
    "http/1.": "http",
    "http/2": "http",
    "ssh-": "ssh",
    "mysql": "mysql",
    "postgres": "postgresql",
    "redis": "redis",
    "smtp": "smtp",
    "ftp": "ftp",
}


@dataclass(frozen=True)
class PortScanResult:
    host: str
    port: int
    status: str
    service_guess: str
    response_time_ms: float
    banner: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def normalize_target_host(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme:
        return parsed.hostname or target
    return target


def parse_ports(port_list: str | None, port_range: str | None) -> list[int]:
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
        service_guess = _identify_service(host, port, timeout, banner)
    else:
        service_guess = "unknown"

    return PortScanResult(
        host=host,
        port=port,
        status=status,
        service_guess=service_guess,
        response_time_ms=round(elapsed_ms, 3),
        banner=banner,
    )


def _read_banner(sock: socket.socket) -> str | None:
    try:
        sock.sendall(b"\r\n")
        data = sock.recv(256)
        if not data:
            return None
        return data.decode("utf-8", errors="replace").strip() or None
    except OSError:
        return None


def _identify_service(host: str, port: int, timeout: float, banner: str | None) -> str:
    from_banner = _guess_from_banner(banner)
    if from_banner:
        return from_banner

    for probe in _probe_order_for_port(port):
        detected = probe(host, port, timeout)
        if detected:
            return detected

    from_port = _guess_service_by_port(port)
    if from_port:
        return from_port
    return "unknown"


def _guess_from_banner(banner: str | None) -> str | None:
    if not banner:
        return None
    low = banner.lower()
    for marker, service in SERVICE_HINTS.items():
        if marker in low:
            return service
    return None


def _probe_order_for_port(port: int) -> list:
    if port in {80, 8080, 8000, 5000, 3000}:
        return [_probe_http, _probe_https, _probe_ssh]
    if port in {443, 8443}:
        return [_probe_https, _probe_http]
    if port == 22:
        return [_probe_ssh]
    if port == 3306:
        return [_probe_mysql, _probe_http]
    if port == 6379:
        return [_probe_redis]
    if port in {25, 465, 587}:
        return [_probe_smtp]
    if port in {5432, 1521, 1433}:
        return [_probe_database_banner]
    return [_probe_http, _probe_https, _probe_ssh, _probe_redis, _probe_smtp]


def _probe_http(host: str, port: int, timeout: float) -> str | None:
    payload = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
    data = _send_and_recv_tcp(host, port, timeout, payload)
    if data.startswith(b"HTTP/") or b"Server:" in data:
        return "http"
    return None


def _probe_https(host: str, port: int, timeout: float) -> str | None:
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
                    return "https"
                return "tls"
    except OSError:
        return None


def _probe_ssh(host: str, port: int, timeout: float) -> str | None:
    data = _send_and_recv_tcp(host, port, timeout, b"", recv_first=True)
    if data.startswith(b"SSH-"):
        return "ssh"
    return None


def _probe_mysql(host: str, port: int, timeout: float) -> str | None:
    data = _send_and_recv_tcp(host, port, timeout, b"", recv_first=True)
    if len(data) > 5 and data[4] == 0x0A:
        return "mysql"
    if b"mysql" in data.lower():
        return "mysql"
    return None


def _probe_redis(host: str, port: int, timeout: float) -> str | None:
    data = _send_and_recv_tcp(host, port, timeout, b"*1\r\n$4\r\nPING\r\n")
    if data.startswith(b"+PONG") or b"redis" in data.lower():
        return "redis"
    return None


def _probe_smtp(host: str, port: int, timeout: float) -> str | None:
    data = _send_and_recv_tcp(host, port, timeout, b"EHLO scanner\r\n", recv_first=True)
    if data.startswith(b"220") or b"smtp" in data.lower():
        return "smtp"
    return None


def _probe_database_banner(host: str, port: int, timeout: float) -> str | None:
    data = _send_and_recv_tcp(host, port, timeout, b"", recv_first=True)
    low = data.lower()
    if b"postgres" in low:
        return "postgresql"
    if b"oracle" in low:
        return "oracle"
    if b"sql server" in low or b"mssql" in low:
        return "mssql"
    return None


def _send_and_recv_tcp(
    host: str,
    port: int,
    timeout: float,
    payload: bytes,
    recv_first: bool = False,
) -> bytes:
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


def _guess_service_by_port(port: int) -> str | None:
    if port in COMMON_SERVICE_PORTS:
        return COMMON_SERVICE_PORTS[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return None


def _parse_port_range(raw: str) -> tuple[int, int]:
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
    for port in ports:
        if port < 1 or port > 65535:
            raise ValueError(f"Invalid port: {port}. Valid range is 1-65535.")
    return ports