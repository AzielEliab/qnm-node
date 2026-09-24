"""Mesh-security statements in the FED-MESH-1.0 statement shape.

aziel-runtime `docs/designs/FED-MESH-1.0.md` on
`cursor/fed-mesh-e546` (`b6b2ea9a`) has a Mesh Security section.
These statements use that spec's version, canonical JSON (sorted
keys, no extra whitespace), and an Ed25519 signature over the
statement with `sig` removed. Public keys and signatures are
unpadded base64url, matching the runtime codec. Wave 3 records
(isolation, appeal, mirror-restore, design-unlock) use the same
shape. That paper does not define them yet.

Message bodies use the runtime schedule in ``wire.py``
(``FED-MESH-1.0|from|to|seq``). Hop and blind layers stay separate:
``FED-MESH-1.0|hop|exit|seq`` and ``FED-MESH-1.0|blind|to|seq``, so a
decrypting exit does not learn the origin.

Author: Aziel Eliab only.
"""

from __future__ import annotations

import os
import re
from typing import Any

from qnm.boot import AUTHOR, QNMRefuse
from qnm.fedmesh.wire import b64url, b64url_d, canonical, handle_from_pubkey

SEC_VERSION = "FED-MESH-1.0"
HOP_PREFIX = b"FED-MESH-1.0|hop|"
BLIND_PREFIX = b"FED-MESH-1.0|blind|"


ISOLATION_FIELDS = (
    "v",
    "kind",
    "handle",
    "public_key",
    "subject",
    "reason",
    "check",
    "model",
    "evidence_hash",
    "seq",
    "prev",
    "sig",
)
ISOLATION_REASONS = frozenset({"NUDITY", "CHILD", "HATE", "CSAM"})
CHECK_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
ANCHOR_FIELDS = ("v", "handle", "public_key", "seq", "prev", "receipt_hash", "sig")


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


def isolation_statement(document: dict[str, Any]) -> dict[str, Any]:
    """Runtime isolation statement. No author, content, or lock flags."""
    return {
        "v": document.get("v"),
        "kind": "isolation",
        "handle": document.get("handle"),
        "public_key": document.get("public_key"),
        "subject": document.get("subject"),
        "reason": document.get("reason"),
        "check": document.get("check"),
        "model": document.get("model"),
        "evidence_hash": document.get("evidence_hash"),
        "seq": document.get("seq"),
        "prev": document.get("prev"),
    }


def verify_isolation_statement(document: dict[str, Any]) -> bytes:
    """Accept the runtime isolation field set and its signature."""
    if set(document) != set(ISOLATION_FIELDS):
        raise QNMRefuse("FED-TAMPER", "isolation record fields refused")
    if document.get("v") != SEC_VERSION or document.get("kind") != "isolation":
        raise QNMRefuse("FED-TAMPER", "isolation statement header refused")
    if document.get("subject") != document.get("handle"):
        raise QNMRefuse("FED-POLICY", "only the handle can sign its own isolation")
    if document.get("reason") not in ISOLATION_REASONS:
        raise QNMRefuse("FED-TAMPER", "isolation reason refused")
    if not CHECK_RE.fullmatch(str(document.get("check") or "")):
        raise QNMRefuse("FED-TAMPER", "isolation check refused")
    if not MODEL_RE.fullmatch(str(document.get("model") or "")):
        raise QNMRefuse("FED-TAMPER", "isolation model refused")
    evidence = str(document.get("evidence_hash") or "")
    if len(evidence) != 64 or any(ch not in "0123456789abcdef" for ch in evidence):
        raise QNMRefuse("FED-TAMPER", "isolation evidence hash refused")
    seq = document.get("seq")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        raise QNMRefuse("FED-TAMPER", "isolation sequence refused")
    prev = str(document.get("prev") or "")
    if len(prev) != 64 or any(ch not in "0123456789abcdef" for ch in prev):
        raise QNMRefuse("FED-TAMPER", "isolation prev refused")
    raw = b64url_d(str(document.get("public_key") or ""))
    if len(raw) != 32:
        raise QNMRefuse("FED-WRONG-KEY", "isolation key is not 32 bytes")
    if handle_from_pubkey(raw) != str(document.get("handle") or ""):
        raise QNMRefuse("FED-WRONG-KEY", "isolation handle does not match the key")
    statement = isolation_statement(document)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(
            b64url_d(str(document.get("sig") or "")),
            canonical(statement),
        )
    except QNMRefuse:
        raise
    except Exception as exc:  # noqa: BLE001
        raise QNMRefuse("FED-TAMPER", "isolation signature refused") from exc
    return raw


def identity_anchor_statement(anchor: dict[str, Any]) -> dict[str, Any]:
    """ACT-RECEIPT-1.1 anchor body. ``public_key`` is the key; no key_id inside."""
    return {
        "v": SEC_VERSION,
        "handle": anchor.get("handle"),
        "public_key": anchor.get("public_key"),
        "seq": anchor.get("seq"),
        "prev": anchor.get("prev"),
        "receipt_hash": anchor.get("receipt_hash"),
    }


def make_identity_anchor(
    private_key: Any,
    *,
    handle: str,
    seq: int,
    prev: str,
    receipt_hash: str,
) -> dict[str, Any]:
    """Sign a receipt hash. This is not a ChainLock acknowledgement."""
    body = identity_anchor_statement(
        {
            "handle": handle,
            "public_key": signing_public_b64url(private_key),
            "seq": int(seq),
            "prev": str(prev),
            "receipt_hash": str(receipt_hash),
        }
    )
    return sign_statement(private_key, body)


def verify_identity_anchor(anchor: dict[str, Any]) -> bytes:
    if set(anchor) != set(ANCHOR_FIELDS):
        raise QNMRefuse("FED-TAMPER", "identity anchor fields refused")
    if anchor.get("v") != SEC_VERSION:
        raise QNMRefuse("FED-TAMPER", "identity anchor version refused")
    receipt_hash = str(anchor.get("receipt_hash") or "")
    prev = str(anchor.get("prev") or "")
    for value in (receipt_hash, prev):
        if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            raise QNMRefuse("FED-TAMPER", "identity anchor hash refused")
    seq = anchor.get("seq")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        raise QNMRefuse("FED-TAMPER", "identity anchor sequence refused")
    raw = b64url_d(str(anchor.get("public_key") or ""))
    if len(raw) != 32 or handle_from_pubkey(raw) != str(anchor.get("handle") or ""):
        raise QNMRefuse("FED-WRONG-KEY", "identity anchor handle does not match the key")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(
            b64url_d(str(anchor.get("sig") or "")),
            canonical(identity_anchor_statement(anchor)),
        )
    except QNMRefuse:
        raise
    except Exception as exc:  # noqa: BLE001
        raise QNMRefuse("FED-TAMPER", "identity anchor signature refused") from exc
    return raw


def _has_key(value: object, key: str) -> bool:
    if isinstance(value, dict):
        return key in value or any(_has_key(item, key) for item in value.values())
    if isinstance(value, list):
        return any(_has_key(item, key) for item in value)
    return False
