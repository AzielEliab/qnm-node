"""Outbound filter. Local-first.

Keys, files, task inputs, and other raw bytes stay on the node.
What may leave without an explicit share: signed receipts, ref
updates, rollups of hashes, peer cards, and digests.

A share leaves only as an already-sealed ciphertext envelope.
The filter scans the outbound JSON for held plaintext and for raw
field names. It is applied to every relay/peer post, not only documented.

Author: Aziel Eliab only.
"""

from __future__ import annotations

from typing import Any

from qnm.boot import QNMRefuse
from qnm.fedmesh.wire import canonical

RAW_KEYS = frozenset(
    {
        "text",
        "plaintext",
        "content",
        "content_b64",
        "password",
        "passphrase",
        "sign_seed",
        "box_seed",
        "private",
        "private_key",
        "file_bytes",
    }
)

LIGHT_KINDS = frozenset(
    {
        "ref",
        "digest",
        "peers",
        "rollup",
        "rollup-sign",
        "fetch",
        "receipt",
        "delivery",
        "ack",
        "register",
        "multisig",
    }
)


def _walk_keys(value: object, found: list[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in RAW_KEYS:
                found.append(str(key))
            _walk_keys(item, found)
    elif isinstance(value, list):
        for item in value:
            _walk_keys(item, found)


class Outbound:
    def __init__(self) -> None:
        self.sensitive: set[str] = set()

    def hold(self, text: str) -> None:
        """Remember plaintext that must not appear on the wire."""
        if text and len(text) >= 4:
            self.sensitive.add(text)

    def guard(self, payload: dict[str, Any], *, share: bool = False) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise QNMRefuse("FED-POLICY", "outbound value refused")
        blob = canonical(payload).decode("utf-8", "replace")
        for secret in self.sensitive:
            if secret in blob:
                raise QNMRefuse("FED-POLICY", "raw payload stays on the node")
        raw = []
        _walk_keys(payload, raw)
        if raw:
            raise QNMRefuse("FED-POLICY", "raw field stays on the node")
        kind = str(payload.get("kind") or "")
        purpose = str(payload.get("purpose") or "")
        if kind == "msg" or purpose in ("msg", "task"):
            if not share:
                raise QNMRefuse("FED-POLICY", "raw data leaves only as an explicit encrypted share")
            if "ct" not in payload:
                raise QNMRefuse("FED-POLICY", "a share leaves only as ciphertext")
            return payload
        if kind in LIGHT_KINDS or payload.get("purpose") == "box-bind" or "sign_pub" in payload:
            return payload
        if "ok" in payload and kind == "":
            return payload
        raise QNMRefuse("FED-POLICY", "outbound kind refused")
