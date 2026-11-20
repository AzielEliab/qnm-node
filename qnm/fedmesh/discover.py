"""Peer exchange and LAN discovery.

Peer lists are signed, size-capped, and rate-limited. An oversized or
bad list is rejected whole. Nothing from it is merged.

LAN discovery is opt-in UDP. The default bind is 127.0.0.1. This is
not mDNS. Broadcast is a separate opt-in and is reported honestly if
the OS refuses it. Packets are the same signed peer lists.

Author: Aziel Eliab only.
"""

from __future__ import annotations

import socket
import time
from typing import Any, Callable

from qnm.boot import QNMRefuse
from qnm.fedmesh.wire import MAX_CARD_BYTES, verify_box_binding, verify_card_rotation, verify_peer_list

MAGIC = b"QNM1"
RATE_WINDOW_S = 10.0


class Directory:
    def __init__(self) -> None:
        self.cards: dict[str, dict[str, Any]] = {}
        # Allowlist pin is the full SHA-256 of the signing public key.
        # The 11-character handle is an alias, not the pin.
        self.allow: dict[str, dict[str, Any]] = {}
        self.addrs: dict[str, list[str]] = {}
        self.relays: list[str] = []
        self._hits: dict[str, list[float]] = {}

    def key_active(self, key_id: str) -> bool:
        row = self.allow.get(str(key_id or ""))
        return bool(row) and row.get("key_status") != "rotated"

    def remember_card(self, card: dict[str, Any], addrs: list[str] | None = None, rotation: dict[str, Any] | None = None) -> None:
        verify_box_binding(card)
        handle = str(card.get("handle") or "")
        key_id = str(card.get("key_id") or "")
        if not handle or len(key_id) != 64:
            raise QNMRefuse("FED-WRONG-KEY", "peer card must pin the full public key")
        existing = self.cards.get(handle)
        if existing and str(existing.get("key_id") or "") not in ("", key_id):
            if rotation is None:
                raise QNMRefuse("FED-WRONG-KEY", "peer allowlist is pinned to a different public key")
            verify_card_rotation(str(existing.get("sign_pub") or ""), card, rotation)
            old_id = str(existing.get("key_id") or "")
            if old_id in self.allow:
                self.allow[old_id]["key_status"] = "rotated"
                self.allow[old_id]["rotated_to"] = key_id
        stored = {
            "v": card.get("v"),
            "author": card.get("author"),
            "handle": handle,
            "key_id": key_id,
            "sign_pub": card.get("sign_pub"),
            "box_pub": card.get("box_pub"),
            "box_sig": card.get("box_sig"),
            "key_status": "active",
        }
        self.cards[handle] = stored
        self.allow[key_id] = stored
        if addrs:
            current = self.addrs.setdefault(handle, [])
            for addr in addrs:
                if addr not in current and len(current) < 4:
                    current.append(addr)

    def rotate_card(self, new_card: dict[str, Any], rotation: dict[str, Any], addrs: list[str] | None = None) -> dict[str, Any]:
        """Install ``new_card`` only when the previous pinned key signed it."""
        verify_box_binding(new_card)
        prev_id = str((rotation or {}).get("prev_key_id") or "")
        prev = self.allow.get(prev_id)
        if prev is None or prev.get("key_status") == "rotated":
            raise QNMRefuse("FED-WRONG-KEY", "previous key is not an active pin")
        verify_card_rotation(str(prev.get("sign_pub") or ""), new_card, rotation)
        prev["key_status"] = "rotated"
        prev["rotated_to"] = str(new_card["key_id"])
        if self.cards.get(str(prev.get("handle") or ""), {}).get("key_id") == prev_id:
            self.cards.pop(str(prev["handle"]), None)
        self.remember_card(new_card, addrs)
        self.allow[str(new_card["key_id"])]["prev_key_id"] = prev_id
        return {"ok": True, "key_id": str(new_card["key_id"]), "prev_key_id": prev_id, "handle": str(new_card["handle"])}

    def merge_peer_list(self, card: dict[str, Any], *, rate_limit: int = 3, now: float | None = None) -> dict[str, Any]:
        """Validate then merge. Raises before any mutation on poison."""
        sender = str(card.get("from") or "?")
        moment = time.monotonic() if now is None else now
        hits = [stamp for stamp in self._hits.get(sender, []) if moment - stamp < RATE_WINDOW_S]
        if len(hits) >= rate_limit:
            self._hits[sender] = hits
            raise QNMRefuse("FED-POISON", "peer exchange rate limit")
        hits.append(moment)
        self._hits[sender] = hits
        verify_peer_list(card)
        # Copy-on-write so a late failure cannot half-apply.
        snapshot_cards = dict(self.cards)
        snapshot_allow = dict(self.allow)
        snapshot_addrs = {key: list(value) for key, value in self.addrs.items()}
        snapshot_relays = list(self.relays)
        try:
            for url in card.get("relays") or []:
                if url not in self.relays:
                    self.relays.append(url)
            for peer in card.get("peers") or []:
                self.remember_card(peer, list(peer.get("addrs") or []))
        except Exception:
            self.cards = snapshot_cards
            self.allow = snapshot_allow
            self.addrs = snapshot_addrs
            self.relays = snapshot_relays
            raise
        return {"ok": True, "peers": len(self.cards), "relays": len(self.relays)}


class LanSocket:
    """Directed UDP listener. Bind stays loopback unless the operator set one."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.sock.settimeout(0.2)
        self.host, self.port = self.sock.getsockname()[:2]

    def close(self) -> None:
        self.sock.close()

    def announce(self, payload: bytes, targets: list[tuple[str, int]]) -> int:
        if len(payload) > MAX_CARD_BYTES:
            raise QNMRefuse("FED-POISON", "announcement exceeds the byte cap")
        packet = MAGIC + payload
        sent = 0
        for host, port in targets:
            self.sock.sendto(packet, (host, port))
            sent += 1
        return sent

    def broadcast(self, payload: bytes, port: int) -> dict[str, Any]:
        """Optional broadcast. If the OS refuses, say so. Do not claim it landed."""
        packet = MAGIC + payload
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            probe.sendto(packet, ("255.255.255.255", port))
            return {"ok": True, "broadcast": True}
        except OSError as exc:
            return {"ok": False, "broadcast": False, "detail": exc.__class__.__name__}
        finally:
            probe.close()

    def poll(self, accept: Callable[[bytes], None], *, rounds: int = 2) -> int:
        accepted = 0
        for _ in range(rounds):
            try:
                data, _addr = self.sock.recvfrom(MAX_CARD_BYTES + 8)
            except socket.timeout:
                continue
            if len(data) > MAX_CARD_BYTES + len(MAGIC):
                continue
            if not data.startswith(MAGIC):
                continue
            try:
                accept(data[len(MAGIC) :])
            except QNMRefuse:
                continue
            else:
                accepted += 1
        return accepted
