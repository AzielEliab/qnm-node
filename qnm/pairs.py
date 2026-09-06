"""Spiderweb pair-bind — AIH-WP-1.3 (medium-independent).

Supersedes AIH-WP-1.2 §2.3–§3.3 (one-bearer seal / pair dies with Wi-Fi).

pair_id = SHA256(root_A || root_B || nonce_A || nonce_B)

The bind is medium-independent. It lives in both Memorials until
isolate / PHOENIX-LOCK / Scorch / operator cut. A bearer is hop-only
(``via`` on the frame). bearer_id on SEAL is the path that day, not a
marriage license.

THIS IS NOT Bell-pair physics. No qubit claims.

Handshake: OFFER / ACCEPT / SEAL. Author: Aziel Eliab only.
Companion node law: QNM-BUILD-1.0.
"""

from __future__ import annotations

import json
import secrets
from typing import Any

from qnm.boot import AUTHOR, IDENTITY, QNMRefuse, _utc_now, sha256_hex
from qnm.memorial import Memorial

PAIR_SPEC = "AIH-WP-1.3"
NODE_SPEC = "QNM-BUILD-1.0"
HOP_MAX_DEFAULT = 8
NONCE_BYTES = 16


def _root_bytes(root: str) -> bytes:
    text = str(root).strip().lower()
    if len(text) == 64:
        try:
            return bytes.fromhex(text)
        except ValueError:
            pass
    return text.encode("utf-8")


def _nonce_bytes(nonce: bytes | str | None) -> bytes:
    if nonce is None:
        return secrets.token_bytes(NONCE_BYTES)
    if isinstance(nonce, bytes):
        return nonce
    text = str(nonce).strip()
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise QNMRefuse("AIH-HANDSHAKE", "nonce must be hex or bytes") from exc


def _canon_pair_parts(
    root_a: str,
    root_b: str,
    nonce_a: bytes,
    nonce_b: bytes,
) -> tuple[str, str, bytes, bytes]:
    """Order roots so both memorials compute the same pair_id."""
    ra, rb = str(root_a).lower(), str(root_b).lower()
    na, nb = nonce_a, nonce_b
    if ra > rb:
        ra, rb = rb, ra
        na, nb = nb, na
    return ra, rb, na, nb


def compute_pair_id(
    root_a: str,
    root_b: str,
    nonce_a: bytes | str,
    nonce_b: bytes | str,
) -> str:
    """SHA256(root_A || root_B || nonce_A || nonce_B). Canonical root order."""
    na, nb = _nonce_bytes(nonce_a), _nonce_bytes(nonce_b)
    ra, rb, na, nb = _canon_pair_parts(root_a, root_b, na, nb)
    return sha256_hex(_root_bytes(ra) + _root_bytes(rb) + na + nb)


class Pairs:
    """Many pair-ids per live node. Edges are memorialized binds."""

    def __init__(self, memorial: Memorial) -> None:
        self.memorial = memorial
        self._pending: dict[str, dict[str, Any]] = {}

    def list(self) -> list[dict[str, Any]]:
        return self.memorial.living_pairs()

    def ids(self) -> list[str]:
        return [str(p["pair_id"]) for p in self.list()]

    def peers(self) -> set[str]:
        return {str(p["peer"]) for p in self.list() if p.get("peer")}

    def has_edge(self, peer_root: str) -> bool:
        want = str(peer_root).lower()
        return any(str(p.get("peer") or "").lower() == want for p in self.list())

    def get(self, pair_id: str) -> dict[str, Any] | None:
        for item in self.list():
            if item.get("pair_id") == pair_id:
                return item
        return None

    def offer(
        self,
        *,
        root_a: str,
        peer_root: str,
        nonce_a: bytes | str | None = None,
        via: str | None = None,
    ) -> dict[str, Any]:
        if not root_a or not peer_root or str(root_a).lower() == str(peer_root).lower():
            raise QNMRefuse("AIH-HANDSHAKE", "OFFER needs two distinct roots")
        na = _nonce_bytes(nonce_a)
        rec = {
            "phase": "OFFER",
            "root_a": str(root_a).lower(),
            "root_b": str(peer_root).lower(),
            "nonce_a": na.hex(),
            "via": via or "",
            "medium_independent": True,
            "bell_pair": False,
            "qubit": False,
            "utc": _utc_now(),
            "spec": PAIR_SPEC,
            "companion": NODE_SPEC,
            "author": AUTHOR,
            "identity": IDENTITY,
        }
        key = f"offer:{rec['root_a']}:{rec['root_b']}:{rec['nonce_a']}"
        self._pending[key] = rec
        return rec

    def accept(
        self,
        offer: dict[str, Any],
        *,
        root_b: str,
        nonce_b: bytes | str | None = None,
        via: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(offer, dict) or offer.get("phase") != "OFFER":
            raise QNMRefuse("AIH-HANDSHAKE", "ACCEPT needs an OFFER")
        if str(root_b).lower() != str(offer.get("root_b") or "").lower():
            raise QNMRefuse("AIH-HANDSHAKE", "ACCEPT root is not the OFFER peer")
        if str(root_b).lower() == str(offer.get("root_a") or "").lower():
            raise QNMRefuse("AIH-HANDSHAKE", "ACCEPT needs two distinct roots")
        nb = _nonce_bytes(nonce_b)
        rec = {
            "phase": "ACCEPT",
            "root_a": str(offer["root_a"]).lower(),
            "root_b": str(root_b).lower(),
            "nonce_a": str(offer["nonce_a"]),
            "nonce_b": nb.hex(),
            "via": via or offer.get("via") or "",
            "medium_independent": True,
            "bell_pair": False,
            "qubit": False,
            "utc": _utc_now(),
            "spec": PAIR_SPEC,
            "companion": NODE_SPEC,
            "author": AUTHOR,
            "identity": IDENTITY,
        }
        rec["pair_id"] = compute_pair_id(
            rec["root_a"], rec["root_b"], rec["nonce_a"], rec["nonce_b"]
        )
        self._pending[f"accept:{rec['pair_id']}"] = rec
        return rec

    def seal(
        self,
        handshake: dict[str, Any],
        *,
        self_root: str,
        via: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(handshake, dict) or handshake.get("phase") not in ("ACCEPT", "SEAL"):
            raise QNMRefuse("AIH-HANDSHAKE", "SEAL needs ACCEPT")
        root_a = str(handshake["root_a"]).lower()
        root_b = str(handshake["root_b"]).lower()
        nonce_a = str(handshake["nonce_a"])
        nonce_b = str(handshake["nonce_b"])
        pair_id = compute_pair_id(root_a, root_b, nonce_a, nonce_b)
        me = str(self_root).lower()
        if me == root_a:
            peer = root_b
        elif me == root_b:
            peer = root_a
        else:
            raise QNMRefuse("AIH-HANDSHAKE", "SEAL root is not in the handshake")
        existing = self.get(pair_id)
        if existing is not None:
            return existing
        # bearer_id on SEAL is the path that day — not a marriage license.
        bearer_id = via or handshake.get("via") or ""
        rec = {
            "phase": "SEAL",
            "pair_id": pair_id,
            "peer": peer,
            "root_a": root_a,
            "root_b": root_b,
            "nonce_a": nonce_a,
            "nonce_b": nonce_b,
            "bearer_id": bearer_id,
            "path_that_day": True,
            "marriage_license": False,
            "medium": None,
            "medium_independent": True,
            "bell_pair": False,
            "qubit": False,
            "utc": _utc_now(),
            "spec": PAIR_SPEC,
            "companion": NODE_SPEC,
            "author": AUTHOR,
            "identity": IDENTITY,
        }
        return self.memorial.remember_pair(rec)

    def cut(self, pair_id: str) -> dict[str, Any]:
        removed = self.memorial.forget_pair(pair_id)
        if removed is None:
            raise QNMRefuse("AIH-PAIR-CUT", "no such pair")
        return {
            "ok": True,
            "cut": pair_id,
            "remaining": len(self.list()),
            "residue": False,
            "bind_remains": False,
            "spec": PAIR_SPEC,
            "companion": NODE_SPEC,
            "author": AUTHOR,
        }

    def cut_all(self) -> dict[str, Any]:
        n = self.memorial.forget_all_pairs()
        self._pending.clear()
        return {
            "ok": True,
            "cut_all": True,
            "cut_count": n,
            "remaining": 0,
            "edges": [],
            "spec": PAIR_SPEC,
            "companion": NODE_SPEC,
            "author": AUTHOR,
        }


def handshake_seal(
    node_a: Any,
    node_b: Any,
    *,
    via: str | None = "local",
    nonce_a: bytes | str | None = None,
    nonce_b: bytes | str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """OFFER → ACCEPT → SEAL on both memorials. bearer_id is path that day."""
    offer = node_a.pair_offer(node_b.install_root, nonce=nonce_a, via=via)
    accept = node_b.pair_accept(offer, nonce=nonce_b, via=via)
    sealed_a = node_a.pair_seal(accept, via=via)
    sealed_b = node_b.pair_seal(accept, via=via)
    if sealed_a["pair_id"] != sealed_b["pair_id"]:
        raise QNMRefuse("AIH-HANDSHAKE", "pair_id mismatch between memorials")
    return sealed_a, sealed_b
