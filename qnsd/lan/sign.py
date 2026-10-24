"""Ed25519 over canonical JSON. Same bytes as the FED-MESH codec.

Does not call ``verify_statement`` (that function is locked to
FED-MESH-1.0). Does not define a cipher.
"""

from __future__ import annotations

from typing import Any

from qnm.fedmesh.wire import b64url, b64url_d, canonical, handle_from_pubkey
from qnsd.boot import AUTHOR
from qnsd.lan.contract import LanRefuse


def sign_document(private_key: Any, body: dict[str, Any]) -> dict[str, Any]:
    statement = {key: value for key, value in body.items() if key != "sig"}
    signed = dict(statement)
    signed["sig"] = b64url(private_key.sign(canonical(statement)))
    return signed


def verify_document(document: dict[str, Any], *, signer: str) -> bytes:
    if document.get("author") != AUTHOR:
        raise LanRefuse("QNS-LAN-REFUSED", "author refused", outcome="refused", security=True)
    raw = _raw_key(document.get("public_key"))
    if handle_from_pubkey(raw) != signer:
        raise LanRefuse("QNS-LAN-IDENTITY", "handle does not match the key", outcome="refused", security=True)
    statement = {key: value for key, value in document.items() if key != "sig"}
    _verify(raw, str(document.get("sig") or ""), canonical(statement))
    return raw


def sign_bytes(private_key: Any, payload: bytes) -> str:
    return b64url(private_key.sign(payload))


def verify_bytes(public_key: str, signature: str, payload: bytes, *, signer: str) -> None:
    raw = _raw_key(public_key)
    if handle_from_pubkey(raw) != signer:
        raise LanRefuse("QNS-LAN-IDENTITY", "handle does not match the key", outcome="refused", security=True)
    _verify(raw, signature, payload)


def _raw_key(text: Any) -> bytes:
    try:
        raw = b64url_d(str(text or ""))
    except Exception as exc:  # noqa: BLE001
        raise LanRefuse("QNS-LAN-IDENTITY", "public key refused", outcome="refused", security=True) from exc
    if len(raw) != 32:
        raise LanRefuse("QNS-LAN-IDENTITY", "public key must be 32 bytes", outcome="refused", security=True)
    return raw


def _verify(raw: bytes, signature: str, payload: bytes) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(b64url_d(signature), payload)
    except LanRefuse:
        raise
    except Exception as exc:  # noqa: BLE001
        raise LanRefuse("QNS-LAN-REFUSED", "signature refused", outcome="refused", security=True) from exc
