"""Operator-selected bind. Never 0.0.0.0. Never a public address."""

from __future__ import annotations

import fcntl
import ipaddress
import socket
import struct
from pathlib import Path

from qnsd.lan.contract import LanRefuse

_SIOCGIFADDR = 0x8915
_REFUSE_TOKENS = frozenset({"", "0.0.0.0", "::", "[::]", "*", "localhost"})


def interface_ipv4(name: str) -> str | None:
    token = str(name or "").strip()
    if not token or "/" in token or token in (".", ".."):
        return None
    if not (Path("/sys/class/net") / token).is_dir():
        return None
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = struct.pack("256s", token.encode("utf-8")[:15])
        try:
            res = fcntl.ioctl(sock.fileno(), _SIOCGIFADDR, packed)
        except OSError:
            return None
    finally:
        sock.close()
    return socket.inet_ntoa(res[20:24])


def local_ipv4() -> set[str]:
    found: set[str] = set()
    root = Path("/sys/class/net")
    if root.is_dir():
        for entry in root.iterdir():
            addr = interface_ipv4(entry.name)
            if addr:
                found.add(addr)
    found.add("127.0.0.1")
    return found


def parse_ip_port(address: str) -> tuple[str, int]:
    text = str(address or "").strip()
    if text.count(":") != 1:
        raise LanRefuse("QNS-LAN-BIND", "address must be ip:port", outcome="refused", security=True)
    host, _, port_s = text.partition(":")
    try:
        port = int(port_s)
    except ValueError as exc:
        raise LanRefuse("QNS-LAN-BIND", "port is not an integer", outcome="refused", security=True) from exc
    if port < 1 or port > 65535:
        raise LanRefuse("QNS-LAN-BIND", "port out of range", outcome="refused", security=True)
    ip = _parse_ip(host)
    _refuse_public(ip)
    return str(ip), port


def select_bind(host: str, *, allow_loopback: bool) -> str:
    """Return the IP to bind. Loopback requires an explicit opt-in."""
    token = str(host or "").strip()
    if token.lower() in _REFUSE_TOKENS or token.lower() == "localhost":
        raise LanRefuse(
            "QNS-LAN-WAN" if token in ("0.0.0.0", "::", "[::]", "*") else "QNS-LAN-BIND",
            "bind refused",
            outcome="refused",
            security=True,
        )
    try:
        ip = _parse_ip(token)
    except LanRefuse:
        raise
    if ip.is_loopback:
        if not allow_loopback:
            raise LanRefuse(
                "QNS-LAN-BIND",
                "loopback bind needs an explicit loopback opt-in",
                outcome="refused",
                security=True,
            )
        return str(ip)
    _refuse_public(ip)
    if str(ip) not in local_ipv4():
        raise LanRefuse(
            "QNS-LAN-BIND",
            "address is not assigned to a local interface",
            outcome="refused",
            security=True,
        )
    return str(ip)


def _parse_ip(token: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        ip = ipaddress.ip_address(token)
    except ValueError as exc:
        raise LanRefuse(
            "QNS-LAN-BIND",
            "bind address must be an IP, not a hostname",
            outcome="refused",
            security=True,
        ) from exc
    if ip.is_unspecified or ip.is_multicast:
        raise LanRefuse("QNS-LAN-WAN", "unspecified or multicast bind refused", outcome="refused", security=True)
    return ip


def _refuse_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    if ip.is_loopback or ip.is_private or ip.is_link_local:
        return
    raise LanRefuse("QNS-LAN-WAN", "public bind refused", outcome="refused", security=True)
