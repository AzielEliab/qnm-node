"""Mesh-security statements in the FED-MESH-1.0 statement shape.

aziel-runtime `docs/designs/FED-MESH-1.0.md` at
`cursor/fed-mesh-e546` (`964a3cd9`) has no Mesh Security section.
These statements use that spec's version, canonical JSON (sorted
keys, no extra whitespace), and an Ed25519 signature over the
statement with `sig` removed. Public keys and signatures are
unpadded base64url, matching the runtime codec.

The hop key schedule does not put the origin handle in HKDF info.
The runtime message cipher does (`FED-MESH-1.0|from|to|seq`), which
cannot hide the origin from a relay that must decrypt. Hop and blind
layers use `FED-MESH-1.0|hop|exit|seq` and `FED-MESH-1.0|blind|to|seq`.

Author: Aziel Eliab only.
"""

from __future__ import annotations

import base64
import os
from typing import Any

from qnm.boot import AUTHOR, QNMRefuse
from qnm.fedmesh.wire import canonical, handle_from_pubkey

SEC_VERSION = "FED-MESH-1.0"
HOP_PREFIX = b"FED-MESH-1.0|hop|"
BLIND_PREFIX = b"FED-MESH-1.0|blind|"


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_d(text: str) -> bytes:
    raw = str(text or "").strip()
    if not raw or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for ch in raw):
        raise QNMRefuse("FED-TAMPER", "bad base64url")
    pad = "=" * ((4 - len(raw) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(raw + pad)
    except Exception as exc:  # noqa: BLE001
        raise QNMRefuse("FED-TAMPER", "bad base64url") from exc


def sign_statement(private_key: Any, body: dict[str, Any]) -> dict[str, Any]:
    statement = {key: value for key, value in body.items() if key != "sig"}
    signed = dict(statement)
    signed["sig"] = b64url(private_key.sign(canonical(statement)))
    return signed


def verify_statement(document: dict[str, Any]) -> bytes:
    if document.get("v") != SEC_VERSION or document.get("author") != AUTHOR:
        raise QNMRefuse("FED-TAMPER", "security statement header refused")
    raw = b64url_d(str(document.get("public_key") or ""))
    if len(raw) != 32:
        raise QNMRefuse("FED-WRONG-KEY", "security statement key is not 32 bytes")
    if handle_from_pubkey(raw) != str(document.get("handle") or ""):
        raise QNMRefuse("FED-WRONG-KEY", "security statement handle does not match the key")
    statement = {key: value for key, value in document.items() if key != "sig"}
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(b64url_d(str(document.get("sig") or "")), canonical(statement))
    except QNMRefuse:
        raise
    except Exception as exc:  # noqa: BLE001
        raise QNMRefuse("FED-TAMPER", "security statement signature refused") from exc
    return raw


def signing_public_b64url(private_key: Any) -> str:
    from cryptography.hazmat.primitives import serialization

    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return b64url(raw)


def seal_layer(peer_public: bytes, info: bytes, plaintext: bytes) -> dict[str, str]:
    """Ephemeral X25519 + HKDF-SHA256 + AES-GCM. Salt is the spec version."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    if len(peer_public) != 32:
        raise QNMRefuse("FED-WRONG-KEY", "hop peer key is not 32 bytes")
    ephemeral = X25519PrivateKey.generate()
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(peer_public))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=SEC_VERSION.encode("ascii"), info=info).derive(shared)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    public = ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"nonce": b64url(nonce), "eph_public_key": b64url(public), "ciphertext": b64url(ciphertext)}


def open_layer(box_private: Any, info: bytes, layer: dict[str, Any]) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    try:
        shared = box_private.exchange(X25519PublicKey.from_public_bytes(b64url_d(str(layer.get("eph_public_key") or ""))))
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=SEC_VERSION.encode("ascii"), info=info).derive(shared)
        return AESGCM(key).decrypt(b64url_d(str(layer.get("nonce") or "")), b64url_d(str(layer.get("ciphertext") or "")), None)
    except QNMRefuse:
        raise
    except Exception as exc:  # noqa: BLE001
        raise QNMRefuse("FED-E2E", "hop layer failed authentication") from exc


def hop_info(exit_handle: str, seq: int) -> bytes:
    return HOP_PREFIX + exit_handle.encode("utf-8") + b"|" + str(int(seq)).encode("ascii")


def blind_info(recipient: str, seq: int) -> bytes:
    return BLIND_PREFIX + recipient.encode("utf-8") + b"|" + str(int(seq)).encode("ascii")


def wrap_two_hop(
    private_key: Any,
    *,
    origin: str,
    exit_handle: str,
    exit_box: bytes,
    recipient: str,
    recipient_box: bytes,
    envelope: dict[str, Any],
    seq: int,
    prev: str,
) -> dict[str, Any]:
    """Entry sees origin and the exit handle. Exit sees the recipient, not the origin."""
    blind_sealed = seal_layer(recipient_box, blind_info(recipient, seq), canonical(envelope))
    blind = {
        "v": SEC_VERSION,
        "kind": "blind",
        "author": AUTHOR,
        "to": recipient,
        "seq": int(seq),
        "nonce": blind_sealed["nonce"],
        "eph_public_key": blind_sealed["eph_public_key"],
        "ciphertext": blind_sealed["ciphertext"],
    }
    hop_sealed = seal_layer(exit_box, hop_info(exit_handle, seq), canonical(blind))
    return sign_statement(
        private_key,
        {
            "v": SEC_VERSION,
            "kind": "hop",
            "author": AUTHOR,
            "handle": origin,
            "public_key": signing_public_b64url(private_key),
            "to": exit_handle,
            "seq": int(seq),
            "prev": prev,
            "nonce": hop_sealed["nonce"],
            "eph_public_key": hop_sealed["eph_public_key"],
            "ciphertext": hop_sealed["ciphertext"],
        },
    )


def hop_exit_view(hop: dict[str, Any]) -> dict[str, Any]:
    """What the entry gives the exit. No origin handle and no signature."""
    return {
        "v": SEC_VERSION,
        "kind": "hop-exit",
        "author": AUTHOR,
        "seq": int(hop.get("seq") or 0),
        "nonce": hop.get("nonce"),
        "eph_public_key": hop.get("eph_public_key"),
        "ciphertext": hop.get("ciphertext"),
    }


def local_statement(private_key: Any, *, handle: str, kind: str, fields: dict[str, Any], seq: int, prev: str) -> dict[str, Any]:
    body = {
        "v": SEC_VERSION,
        "kind": kind,
        "author": AUTHOR,
        "handle": handle,
        "public_key": signing_public_b64url(private_key),
        "seq": int(seq),
        "prev": prev,
    }
    body.update(fields)
    if _has_key(body, "score"):
        raise QNMRefuse("FED-POLICY", "local trust has no score field")
    return sign_statement(private_key, body)


def _has_key(value: object, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(_has_key(item, key) for item in value.values())
    if isinstance(value, list):
        return any(_has_key(item, key) for item in value)
    return False
