from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Iterable
from urllib.parse import urlparse


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
    service_guess = _guess_service(port)

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


def _guess_service(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


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