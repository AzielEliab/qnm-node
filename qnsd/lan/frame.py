"""Length-prefixed JSON frames. Oversize lengths are not read."""

from __future__ import annotations

import json
import socket
from typing import Any

from qnsd.lan.contract import MAX_FRAME, LanRefuse


def _read_exact(sock: socket.socket, count: int) -> bytes:
    buf = bytearray()
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise LanRefuse("QNS-LAN-UNAVAILABLE", "connection closed", outcome="temporary", security=False)
        buf.extend(chunk)
    return bytes(buf)


def read_frame(sock: socket.socket) -> dict[str, Any]:
    header = _read_exact(sock, 4)
    length = int.from_bytes(header, "big")
    if length < 1 or length > MAX_FRAME:
        raise LanRefuse(
            "QNS-LAN-MALFORMED",
            "frame length refused",
            outcome="permanent",
            security=True,
        )
    raw = _read_exact(sock, length)
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LanRefuse(
            "QNS-LAN-MALFORMED",
            "frame is not JSON",
            outcome="permanent",
            security=True,
        ) from exc
    if not isinstance(obj, dict):
        raise LanRefuse("QNS-LAN-MALFORMED", "frame must be an object", outcome="permanent", security=True)
    return obj


def encode_frame(obj: dict[str, Any]) -> bytes:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(raw) < 1 or len(raw) > MAX_FRAME:
        raise LanRefuse("QNS-LAN-MALFORMED", "frame exceeds the cap", outcome="permanent", security=True)
    return len(raw).to_bytes(4, "big") + raw


def write_frame(sock: socket.socket, obj: dict[str, Any]) -> None:
    sock.sendall(encode_frame(obj))
