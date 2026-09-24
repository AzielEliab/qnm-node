"""Optional Tor transport. A SOCKS5 adapter, not an onion network.

Off by default. When it is on, mesh HTTP goes through the configured
proxy and does not fall back to a clearnet socket if the proxy is
down. This does not hide the node from the proxy operator, and it is
not protection against a state-level adversary. There is no
zero-knowledge claim.

Author: Aziel Eliab only.
"""

from __future__ import annotations

import json
import socket
from typing import Any
from urllib.parse import urlparse

from qnm.boot import QNMRefuse


class TorAdapter:
    def __init__(self) -> None:
        self.enabled = False
        self.host = "127.0.0.1"
        self.port = 9050
        self.last_error = ""

    def status(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "proxy": f"{self.host}:{self.port}",
            "last_error": self.last_error,
            "custom_onion": False,
            "zero_knowledge": False,
            "state_level_adversary": False,
            "note": (
                "SOCKS5 adapter for an operator-run Tor daemon. "
                "Not a private onion network. Off unless an Admin enables it. "
                "A dead proxy refuses the send and does not fall back to clearnet."
            ),
        }

    def configure(self, proxy: str, *, enabled: bool) -> None:
        host, port = _split_proxy(proxy)
        self.host = host
        self.port = port
        self.enabled = bool(enabled)

    def request(self, method: str, url: str, payload: dict[str, Any] | None) -> dict[str, Any]:
        if not self.enabled:
            raise QNMRefuse("FED-TOR-OFF", "Tor transport is off")
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise QNMRefuse("FED-TOR-ABSENT", "Tor transport accepts http(s) URLs only")
        if parsed.scheme == "https":
            raise QNMRefuse(
                "FED-TOR-ABSENT",
                "this adapter dials SOCKS5 then speaks HTTP. TLS-through-Tor is not implemented",
            )
        dest_host = parsed.hostname or ""
        dest_port = parsed.port or 80
        try:
            sock = _socks5_connect(self.host, self.port, dest_host, dest_port)
        except OSError as exc:
            self.last_error = "proxy-unreachable"
            raise QNMRefuse("FED-TOR-ABSENT", "Tor SOCKS proxy is not reachable") from exc
        self.last_error = ""
        try:
            return _http_json(sock, method, parsed, payload)
        finally:
            sock.close()


def _split_proxy(proxy: str) -> tuple[str, int]:
    text = str(proxy or "127.0.0.1:9050")
    if text.startswith("socks5://"):
        text = text[len("socks5://") :]
    if ":" not in text:
        raise QNMRefuse("FED-TOR-ABSENT", "Tor proxy must be host:port")
    host, _, port_text = text.rpartition(":")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise QNMRefuse("FED-TOR-ABSENT", "Tor proxy port refused") from exc
    if not host or port < 1 or port > 65535:
        raise QNMRefuse("FED-TOR-ABSENT", "Tor proxy refused")
    return host, port


def _readexact(sock: socket.socket, size: int) -> bytes:
    buf = b""
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise OSError("short SOCKS read")
        buf += chunk
    return buf


def _socks5_connect(proxy_host: str, proxy_port: int, dest_host: str, dest_port: int) -> socket.socket:
    sock = socket.create_connection((proxy_host, proxy_port), 2.0)
    try:
        sock.sendall(b"\x05\x01\x00")
        hello = _readexact(sock, 2)
        if hello != b"\x05\x00":
            raise OSError("SOCKS auth refused")
        host = dest_host.encode("idna")
        if len(host) > 255:
            raise OSError("SOCKS host refused")
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + int(dest_port).to_bytes(2, "big"))
        head = _readexact(sock, 4)
        if head[0] != 5 or head[1] != 0:
            raise OSError("SOCKS connect refused")
        atyp = head[3]
        if atyp == 1:
            _readexact(sock, 6)
        elif atyp == 3:
            length = _readexact(sock, 1)[0]
            _readexact(sock, length + 2)
        elif atyp == 4:
            _readexact(sock, 18)
        else:
            raise OSError("SOCKS address refused")
        return sock
    except Exception:
        sock.close()
        raise


def _http_json(sock: socket.socket, method: str, parsed: Any, payload: dict[str, Any] | None) -> dict[str, Any]:
    path = parsed.path or "/"
    if parsed.query:
        path = path + "?" + parsed.query
    body = b"" if payload is None else json.dumps(payload, sort_keys=True).encode("utf-8")
    host = parsed.hostname or "127.0.0.1"
    lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}",
        "Accept: application/json",
        "Connection: close",
    ]
    if body:
        lines.append("Content-Type: application/json")
        lines.append(f"Content-Length: {len(body)}")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body)
    raw = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        raw += chunk
        if len(raw) > 1_000_000:
            raise QNMRefuse("FED-QUOTA", "Tor response is too large")
    head, _, rest = raw.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].decode("ascii", "replace")
    parts = status_line.split()
    code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    text = rest.decode("utf-8", "replace")
    try:
        parsed_body = json.loads(text) if text.strip() else {}
    except json.JSONDecodeError as exc:
        raise QNMRefuse("FED-NO-ROUTE", "Tor peer returned non-JSON") from exc
    if not isinstance(parsed_body, dict):
        raise QNMRefuse("FED-NO-ROUTE", "Tor peer returned a non-object")
    if code >= 400:
        if parsed_body.get("code"):
            raise QNMRefuse(str(parsed_body.get("code")), str(parsed_body.get("detail") or ""))
        raise QNMRefuse("FED-NO-ROUTE", f"Tor peer HTTP {code}")
    return parsed_body
