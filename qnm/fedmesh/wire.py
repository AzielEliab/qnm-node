"""FED-MESH-1.0-draft wire, receipt, and rollup bytes.

This is the only module that defines on-wire JSON. Align it with
aziel-runtime ``docs/designs/FED-MESH-1.0.md`` when that spec lands.
Until then the draft below is the daemon contract.

Author: Aziel Eliab only. The software author is not a node handle.
A participant handle is ``#`` plus 11 Crockford base32 characters
from the high 55 bits of SHA-256 of the raw Ed25519 public key.
The runtime vector seed ``0102…1f20`` yields ``#CPV0CWYPXP4``.

Open alignment points:

1. Refs, anchors, and most daemon objects stay ``FED-MESH-1.0-draft``.
   Message envelopes and the runtime isolation record use ``FED-MESH-1.0``.
2. Handle length 11, Crockford alphabet (no I, L, O, U), no padding.
3. ``key_id`` = hex SHA-256 of the raw 32-byte Ed25519 public key.
4. Canonical JSON: UTF-8, sorted keys, separators ``(',', ':')``.
5. Ed25519 signature over the canonical object with ``sig`` removed.
6. Message bodies use ephemeral X25519, HKDF-SHA256 salt
   ``FED-MESH-1.0``, info ``FED-MESH-1.0|from|to|seq`` (not sorted),
   AES-256-GCM, 12-byte nonce, no additional data. The recipient key
   is that handle's static X25519 key. A later leak of the recipient
   key opens old bodies; this process does not claim forward secrecy.
7. Daemon send and direct stay ``/v1/fedmesh/*``. Isolation is posted
   to ``/v1/mesh/relay/isolation``. ``GET /v1/mesh`` never enables
   radios. ``GET /v1/mesh/relay`` is health and does not enable.
8. Rollup bodies are signed plaintext hashes so a relay can hold them.
   They are not E2E. This daemon does not claim the runtime Worker
   has ChainLock- or TemporalLock-anchored them.
9. Default relay URL is the aziel-runtime Worker origin. Opt-in only.
   This daemon does not claim that Worker already speaks this draft.

Messages are signed. Message and file bodies are encrypted. This is
not anonymity. NAT traversal is not implemented.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from qnm.boot import AUTHOR, QNMRefuse

VERSION = "FED-MESH-1.0-draft"
HANDLE_BODY_LEN = 11
GENESIS_PREV = "0" * 64
DEFAULT_RELAY = "https://aziel-runtime.vibelock.workers.dev"
E2E_ALG = "x25519-hkdf-sha256-aes-256-gcm"
MSG_VERSION = "FED-MESH-1.0"
HKDF_SALT = b"FED-MESH-1.0"
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
MSG_FIELDS = (
    "v",
    "kind",
    "handle",
    "public_key",
    "to",
    "seq",
    "prev",
    "nonce",
    "eph_public_key",
    "ciphertext",
    "via",
)
MAX_PEERS = 32
MAX_RELAYS = 8
MAX_ADDRS = 4
MAX_URL_LEN = 200
MAX_CARD_BYTES = 8192
MAX_CT_BYTES = 65536
PREFIX_CAP = 128
PROJECTION_KEYS = (
    "kind",
    "body",
    "hash",
    "prev",
    "seq",
    "utc",
    "spec",
    "author",
    "on_disk",
)

# What a relay or store-and-forward peer can read without the recipient key.
# Matches the runtime ALLOWED.msg set. ``via`` is optional.
RELAY_VISIBLE = MSG_FIELDS + ("sig",)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    try:
        return base64.b64decode(str(text), validate=True)
    except Exception as exc:  # noqa: BLE001 — invalid wire is a refuse
        raise QNMRefuse("FED-TAMPER", "bad base64") from exc


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_pub(text: str) -> bytes:
    """32-byte key, standard base64 or unpadded base64url."""
    raw = str(text or "").strip()
    decoded = b64d(raw) if any(ch in raw for ch in "+/=") else b64url_d(raw)
    if len(decoded) != 32:
        raise QNMRefuse("FED-WRONG-KEY", "public key must be 32 bytes")
    return decoded


def b64url_d(text: str) -> bytes:
    raw = str(text or "").strip()
    if not raw or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for ch in raw):
        raise QNMRefuse("FED-TAMPER", "bad base64url")
    pad = "=" * ((4 - len(raw) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(raw + pad)
    except Exception as exc:  # noqa: BLE001
        raise QNMRefuse("FED-TAMPER", "bad base64url") from exc


def handle_from_pubkey(raw_pub: bytes) -> str:
    """``#`` + 11 Crockford symbols from SHA-256(pubkey). No registry.

    Eleven symbols are 55 bits, taken from the high end of the digest.
    The alphabet omits I, L, O, and U.
    """
    if len(raw_pub) != 32:
        raise QNMRefuse("FED-WRONG-KEY", "Ed25519 public key must be 32 bytes")
    digest = hashlib.sha256(raw_pub).digest()
    acc = 0
    bits = 0
    out: list[str] = []
    for byte in digest:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5 and len(out) < HANDLE_BODY_LEN:
            bits -= 5
            out.append(CROCKFORD[(acc >> bits) & 31])
    if len(out) != HANDLE_BODY_LEN:
        raise QNMRefuse("FED-WRONG-KEY", "handle derivation was short")
    return "#" + "".join(out)


def key_id_from_pubkey(raw_pub: bytes) -> str:
    if len(raw_pub) != 32:
        raise QNMRefuse("FED-WRONG-KEY", "Ed25519 public key must be 32 bytes")
    return hashlib.sha256(raw_pub).hexdigest()


def assert_handle_matches(handle: str, raw_pub: bytes, key_id: str) -> None:
    expect_handle = handle_from_pubkey(raw_pub)
    expect_id = key_id_from_pubkey(raw_pub)
    if handle != expect_handle or key_id != expect_id:
        raise QNMRefuse("FED-WRONG-KEY", "handle or key id does not match the signing key")


def timeslate(payload_hash: str) -> dict[str, Any]:
    """TemporalLock if that engine is importable. Otherwise local UTC.

    ``applied`` is true only when an engine returns a stamp. This
    process does not invent one.
    """
    utc = utc_now()
    engine = None
    try:
        import temporallock  # type: ignore
    except ImportError:
        temporallock = None
    if temporallock is not None and hasattr(temporallock, "timeslate"):
        stamp = temporallock.timeslate(payload_hash)
        if isinstance(stamp, dict) and stamp.get("stamp"):
            return {
                "applied": True,
                "source": "temporallock",
                "engine": "temporallock",
                "utc": str(stamp.get("utc") or utc),
                "stamp": stamp.get("stamp"),
            }
        engine = "temporallock"
    return {
        "applied": False,
        "source": "local-utc",
        "engine": engine,
        "utc": utc,
        "note": "TemporalLock did not stamp this receipt; utc is the daemon clock",
    }


def projection_of(receipt: dict[str, Any]) -> dict[str, Any]:
    return {key: receipt[key] for key in PROJECTION_KEYS}


def payload_hash(obj: dict[str, Any]) -> str:
    return sha256_hex(canonical(obj))


def _sign(private_key: Any, data: bytes) -> str:
    return b64e(private_key.sign(data))


def _verify(raw_pub: bytes, sig_b64: str, data: bytes) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(raw_pub).verify(b64d(sig_b64), data)
    except Exception as exc:  # noqa: BLE001
        raise QNMRefuse("FED-TAMPER", "signature does not match") from exc


def box_binding(handle: str, key_id: str, sign_pub: str, box_pub: str) -> dict[str, Any]:
    return {
        "v": VERSION,
        "purpose": "box-bind",
        "author": AUTHOR,
        "handle": handle,
        "key_id": key_id,
        "sign_pub": sign_pub,
        "box_pub": box_pub,
    }


def sign_box_binding(private_key: Any, handle: str, key_id: str, sign_pub: str, box_pub: str) -> str:
    return _sign(private_key, canonical(box_binding(handle, key_id, sign_pub, box_pub)))


def verify_box_binding(card: dict[str, Any]) -> bytes:
    """Return raw signing pubkey after the encryption key is bound to it."""
    raw = b64d(str(card.get("sign_pub") or ""))
    assert_handle_matches(str(card.get("handle") or ""), raw, str(card.get("key_id") or ""))
    binding = box_binding(
        str(card["handle"]),
        str(card["key_id"]),
        str(card["sign_pub"]),
        str(card["box_pub"]),
    )
    try:
        _verify(raw, str(card.get("box_sig") or ""), canonical(binding))
    except QNMRefuse as exc:
        raise QNMRefuse("FED-WRONG-KEY", "encryption key is not bound to the signing key") from exc
    box = b64d(str(card.get("box_pub") or ""))
    if len(box) != 32:
        raise QNMRefuse("FED-WRONG-KEY", "X25519 public key must be 32 bytes")
    return raw


def make_anchor(
    private_key: Any,
    *,
    handle: str,
    key_id: str,
    sign_pub: str,
    seq: int,
    prev: str,
    payload_hash_hex: str,
) -> dict[str, Any]:
    """Per-handle ChainLock-style anchor. No private key material."""
    temporal = timeslate(payload_hash_hex)
    core = {
        "v": VERSION,
        "author": AUTHOR,
        "handle": handle,
        "key_id": key_id,
        "sign_pub": sign_pub,
        "seq": int(seq),
        "prev": str(prev),
        "payload_hash": str(payload_hash_hex),
        "utc": temporal["utc"],
        "temporal": temporal,
    }
    digest = sha256_hex(canonical(core))
    anchor = dict(core)
    anchor["hash"] = digest
    anchor["sig"] = _sign(private_key, canonical(core))
    return anchor


def verify_anchor_crypto(anchor: dict[str, Any]) -> bytes:
    """Signature, hash, and handle binding. Does not apply chain rules.

    Returns the raw signing public key.
    """
    raw = b64d(str(anchor.get("sign_pub") or ""))
    handle = str(anchor.get("handle") or "")
    key_id = str(anchor.get("key_id") or "")
    assert_handle_matches(handle, raw, key_id)
    core = {
        "v": anchor.get("v"),
        "author": anchor.get("author"),
        "handle": handle,
        "key_id": key_id,
        "sign_pub": anchor.get("sign_pub"),
        "seq": anchor.get("seq"),
        "prev": anchor.get("prev"),
        "payload_hash": anchor.get("payload_hash"),
        "utc": anchor.get("utc"),
        "temporal": anchor.get("temporal"),
    }
    if anchor.get("v") != VERSION or anchor.get("author") != AUTHOR:
        raise QNMRefuse("FED-TAMPER", "anchor version or author mismatch")
    expect = sha256_hex(canonical(core))
    if anchor.get("hash") != expect:
        raise QNMRefuse("FED-TAMPER", "anchor hash mismatch")
    _verify(raw, str(anchor.get("sig") or ""), canonical(core))
    return raw


def message_info(from_handle: str, to_handle: str, seq: int) -> bytes:
    """Runtime HKDF info. Directional: not sorted by handle."""
    return f"{MSG_VERSION}|{from_handle}|{to_handle}|{int(seq)}".encode("utf-8")


def _message_key(shared: bytes, from_handle: str, to_handle: str, seq: int) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=HKDF_SALT,
        info=message_info(from_handle, to_handle, seq),
    ).derive(shared)


def message_statement(envelope: dict[str, Any]) -> dict[str, Any]:
    """Signed message fields. Optional ``via`` is included only when present."""
    out: dict[str, Any] = {}
    for key in MSG_FIELDS:
        if key in envelope and envelope[key] is not None:
            out[key] = envelope[key]
    return out


def _signing_public_b64url(private_key: Any) -> str:
    from cryptography.hazmat.primitives import serialization

    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return b64url(raw)


def _verify_url(raw_pub: bytes, sig_text: str, data: bytes) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(raw_pub).verify(b64url_d(sig_text), data)
    except QNMRefuse:
        raise
    except Exception as exc:  # noqa: BLE001
        raise QNMRefuse("FED-TAMPER", "signature does not match") from exc


def seal_runtime_body(
    *,
    recipient_public: bytes,
    from_handle: str,
    to_handle: str,
    seq: int,
    plaintext: bytes,
    ephemeral_private: Any = None,
    nonce: bytes | None = None,
) -> dict[str, str]:
    """Seal raw bytes with the runtime message schedule. No plaintext returned."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    import os

    if len(recipient_public) != 32:
        raise QNMRefuse("FED-WRONG-KEY", "X25519 public key must be 32 bytes")
    ephemeral = ephemeral_private if ephemeral_private is not None else X25519PrivateKey.generate()
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient_public))
    key = _message_key(shared, from_handle, to_handle, seq)
    nonce_b = nonce if nonce is not None else os.urandom(12)
    if len(nonce_b) != 12:
        raise QNMRefuse("FED-TAMPER", "nonce must be 12 bytes")
    ciphertext = AESGCM(key).encrypt(nonce_b, plaintext, None)
    if len(ciphertext) > MAX_CT_BYTES:
        raise QNMRefuse("FED-QUOTA", "ciphertext exceeds the relay cap")
    public = ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {
        "nonce": b64url(nonce_b),
        "eph_public_key": b64url(public),
        "ciphertext": b64url(ciphertext),
    }


def open_message_body(
    box_private: Any,
    *,
    from_handle: str,
    to_handle: str,
    seq: int,
    nonce: str,
    eph_public_key: str,
    ciphertext: str,
) -> bytes:
    """Open a runtime message body with the recipient's static X25519 key."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        shared = box_private.exchange(X25519PublicKey.from_public_bytes(b64url_d(eph_public_key)))
        key = _message_key(shared, from_handle, to_handle, seq)
        return AESGCM(key).decrypt(b64url_d(nonce), b64url_d(ciphertext), None)
    except QNMRefuse:
        raise
    except Exception as exc:  # noqa: BLE001
        raise QNMRefuse("FED-E2E", "ciphertext failed authentication") from exc


def seal_envelope(
    *,
    private_key: Any,
    box_private: Any,
    sender: dict[str, Any],
    recipient_card: dict[str, Any],
    seq: int,
    prev: str,
    purpose: str,
    plaintext: dict[str, Any],
    nonce: bytes | None = None,
    ephemeral_private: Any = None,
) -> dict[str, Any]:
    """Encrypt plaintext to the recipient and sign the runtime envelope.

    ``purpose`` stays inside the ciphertext (note, file, object, or
    task). Relays see the runtime message fields, not the purpose.
    ``box_private`` is the sender's static key and is not the message key.
    """
    del box_private
    verify_box_binding(recipient_card)
    verify_box_binding(sender)
    if purpose not in ("msg", "task"):
        raise QNMRefuse("FED-TAMPER", "purpose must be msg or task")
    sealed = seal_runtime_body(
        recipient_public=decode_pub(str(recipient_card["box_pub"])),
        from_handle=str(sender["handle"]),
        to_handle=str(recipient_card["handle"]),
        seq=int(seq),
        plaintext=canonical(plaintext),
        ephemeral_private=ephemeral_private,
        nonce=nonce,
    )
    signed = {
        "v": MSG_VERSION,
        "kind": "msg",
        "handle": sender["handle"],
        "public_key": _signing_public_b64url(private_key),
        "to": recipient_card["handle"],
        "seq": int(seq),
        "prev": str(prev),
        "nonce": sealed["nonce"],
        "eph_public_key": sealed["eph_public_key"],
        "ciphertext": sealed["ciphertext"],
    }
    envelope = dict(signed)
    envelope["sig"] = b64url(private_key.sign(canonical(signed)))
    return envelope


def open_envelope(box_private: Any, my_card: dict[str, Any], envelope: dict[str, Any]) -> dict[str, Any]:
    """Verify the sender and decrypt. Raises FED-TAMPER / FED-WRONG-KEY / FED-E2E."""
    verify_envelope(envelope)
    if envelope["to"] != my_card["handle"]:
        raise QNMRefuse("FED-TAMPER", "envelope is not addressed to this handle")
    raw = open_message_body(
        box_private,
        from_handle=str(envelope["handle"]),
        to_handle=str(envelope["to"]),
        seq=int(envelope["seq"]),
        nonce=str(envelope["nonce"]),
        eph_public_key=str(envelope["eph_public_key"]),
        ciphertext=str(envelope["ciphertext"]),
    )
    try:
        inner = json.loads(raw.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise QNMRefuse("FED-TAMPER", "plaintext is not the expected JSON") from exc
    if not isinstance(inner, dict):
        raise QNMRefuse("FED-TAMPER", "plaintext is not an object")
    return inner


def verify_envelope(envelope: dict[str, Any]) -> None:
    """Relay-side check: signature, handle, size. Does not decrypt."""
    extra = [key for key in envelope if key not in RELAY_VISIBLE]
    if extra:
        raise QNMRefuse("FED-TAMPER", "envelope field refused")
    raw = b64url_d(str(envelope.get("public_key") or ""))
    if len(raw) != 32:
        raise QNMRefuse("FED-WRONG-KEY", "message public key is not 32 bytes")
    if handle_from_pubkey(raw) != str(envelope.get("handle") or ""):
        raise QNMRefuse("FED-WRONG-KEY", "message handle does not match the key")
    signed = message_statement(envelope)
    if signed.get("v") != MSG_VERSION or signed.get("kind") != "msg":
        raise QNMRefuse("FED-TAMPER", "envelope version or kind mismatch")
    ct = b64url_d(str(signed.get("ciphertext") or ""))
    if len(ct) > MAX_CT_BYTES or len(ct) < 16:
        raise QNMRefuse("FED-TAMPER", "ciphertext size refused")
    if len(b64url_d(str(signed.get("nonce") or ""))) != 12:
        raise QNMRefuse("FED-TAMPER", "nonce must be 12 bytes")
    _verify_url(raw, str(envelope.get("sig") or ""), canonical(signed))


def envelope_id(envelope: dict[str, Any]) -> str:
    return sha256_hex(canonical(message_statement(envelope)))


def verify_committed_inner(inner: dict[str, Any]) -> None:
    """Plaintext must match the anchor the sender included."""
    projection = inner.get("projection")
    anchor = inner.get("anchor")
    plaintext = inner.get("plaintext")
    if not isinstance(projection, dict) or not isinstance(anchor, dict) or not isinstance(plaintext, dict):
        raise QNMRefuse("FED-TAMPER", "message inner is missing projection, anchor, or plaintext")
    if payload_hash(projection) != anchor.get("payload_hash"):
        raise QNMRefuse("FED-TAMPER", "anchor does not commit to the projection")
    body = projection.get("body")
    if not isinstance(body, dict) or body.get("payload_hash") != payload_hash(plaintext):
        raise QNMRefuse("FED-TAMPER", "projection does not commit to the plaintext")
    verify_anchor_crypto(anchor)


def peer_core(sender_handle: str, relays: list[str], peers: list[dict[str, Any]], utc: str) -> dict[str, Any]:
    return {
        "v": VERSION,
        "kind": "peers",
        "author": AUTHOR,
        "from": sender_handle,
        "utc": utc,
        "relays": list(relays),
        "peers": peers,
    }


def sign_peer_list(
    private_key: Any,
    *,
    sender_handle: str,
    sign_pub: str,
    relays: list[str],
    peers: list[dict[str, Any]],
) -> dict[str, Any]:
    core = peer_core(sender_handle, relays, peers, utc_now())
    signed = dict(core)
    # sign_pub is outside the signed core. The handle check binds it.
    signed["sign_pub"] = sign_pub
    signed["sig"] = _sign(private_key, canonical(core))
    return signed


def check_peer_list_shape(card: dict[str, Any]) -> None:
    raw = canonical({key: card[key] for key in card if key != "sig"})
    if len(raw) > MAX_CARD_BYTES:
        raise QNMRefuse("FED-POISON", "peer list exceeds the byte cap")
    relays = card.get("relays")
    peers = card.get("peers")
    if not isinstance(relays, list) or not isinstance(peers, list):
        raise QNMRefuse("FED-POISON", "peer list shape refused")
    if len(relays) > MAX_RELAYS or len(peers) > MAX_PEERS:
        raise QNMRefuse("FED-POISON", "peer list exceeds the count cap")
    for url in relays:
        if not isinstance(url, str) or not url or len(url) > MAX_URL_LEN:
            raise QNMRefuse("FED-POISON", "relay URL refused")
    for peer in peers:
        if not isinstance(peer, dict):
            raise QNMRefuse("FED-POISON", "peer card refused")
        addrs = peer.get("addrs") or []
        if not isinstance(addrs, list) or len(addrs) > MAX_ADDRS:
            raise QNMRefuse("FED-POISON", "peer address list refused")
        for addr in addrs:
            if not isinstance(addr, str) or len(addr) > MAX_URL_LEN:
                raise QNMRefuse("FED-POISON", "peer address refused")


def verify_peer_list(card: dict[str, Any]) -> None:
    """Reject oversized, unsigned, or wrong-key peer lists. No partial merge."""
    check_peer_list_shape(card)
    raw = b64d(str(card.get("sign_pub") or "")) if card.get("sign_pub") else b""
    # The signer is ``from``. sign_pub may sit on the matching peer entry or on the card.
    sign_pub = str(card.get("sign_pub") or "")
    if not sign_pub:
        for peer in card.get("peers") or []:
            if isinstance(peer, dict) and peer.get("handle") == card.get("from"):
                sign_pub = str(peer.get("sign_pub") or "")
                break
    if not sign_pub:
        raise QNMRefuse("FED-POISON", "peer list has no signing key")
    raw = b64d(sign_pub)
    assert_handle_matches(str(card.get("from") or ""), raw, key_id_from_pubkey(raw))
    core = peer_core(
        str(card.get("from") or ""),
        list(card.get("relays") or []),
        list(card.get("peers") or []),
        str(card.get("utc") or ""),
    )
    if card.get("v") != VERSION or card.get("kind") != "peers" or card.get("author") != AUTHOR:
        raise QNMRefuse("FED-POISON", "peer list version refused")
    _verify(raw, str(card.get("sig") or ""), canonical(core))
    for peer in card.get("peers") or []:
        if not isinstance(peer, dict):
            raise QNMRefuse("FED-POISON", "peer card refused")
        if peer.get("handle") and peer.get("sign_pub") and peer.get("box_pub") and peer.get("box_sig"):
            verify_box_binding(peer)


def rollup_batch_hash(changes: list[dict[str, Any]]) -> str:
    return payload_hash({"v": VERSION, "kind": "rollup-batch", "changes": changes})


def make_rollup(changes: list[dict[str, Any]], signers: list[dict[str, Any]]) -> dict[str, Any]:
    """Signed plaintext rollup. Not E2E. Hashes only in ``changes``.

    Each signer is ``{"anchor", "projection"}``. The projection body
    carries ``batch_hash``. Upstream can verify the signature without
    this daemon's ledger. Chain gaps need the signer's earlier anchors.
    """
    batch = rollup_batch_hash(changes)
    for row in signers:
        _bind_rollup_signer(row, batch)
    return {
        "v": VERSION,
        "kind": "rollup",
        "author": AUTHOR,
        "batch_hash": batch,
        "changes": changes,
        "signers": signers,
        "utc": utc_now(),
        "e2e": False,
        "temporal_lock": False,
        "chainlock_upstream": False,
        "note": "relay may store this rollup; runtime ChainLock/TemporalLock ack is not claimed",
    }


def _bind_rollup_signer(row: dict[str, Any], batch: str) -> None:
    anchor = row.get("anchor")
    projection = row.get("projection")
    if not isinstance(anchor, dict) or not isinstance(projection, dict):
        raise QNMRefuse("FED-TAMPER", "rollup signer needs anchor and projection")
    verify_anchor_crypto(anchor)
    if payload_hash(projection) != anchor.get("payload_hash"):
        raise QNMRefuse("FED-TAMPER", "rollup signer anchor does not commit to its projection")
    body = projection.get("body")
    if not isinstance(body, dict) or body.get("batch_hash") != batch:
        raise QNMRefuse("FED-TAMPER", "rollup signer does not commit to the batch")


def verify_rollup(rollup: dict[str, Any]) -> None:
    if rollup.get("v") != VERSION or rollup.get("kind") != "rollup" or rollup.get("author") != AUTHOR:
        raise QNMRefuse("FED-TAMPER", "rollup header refused")
    changes = rollup.get("changes")
    signers = rollup.get("signers")
    if not isinstance(changes, list) or not isinstance(signers, list) or not signers:
        raise QNMRefuse("FED-TAMPER", "rollup needs changes and signers")
    batch = rollup_batch_hash(changes)
    if rollup.get("batch_hash") != batch:
        raise QNMRefuse("FED-TAMPER", "rollup batch hash mismatch")
    seen = set()
    for row in signers:
        _bind_rollup_signer(row, batch)
        handle = row["anchor"].get("handle")
        if handle in seen:
            raise QNMRefuse("FED-FORK", "duplicate rollup signer")
        seen.add(handle)


def multisig_core(subject_hash: str, m: int, n: int) -> dict[str, Any]:
    return {
        "v": VERSION,
        "kind": "multisig",
        "author": AUTHOR,
        "subject_hash": subject_hash,
        "m": int(m),
        "n": int(n),
    }


def sign_multisig(private_key: Any, handle: str, sign_pub: str, subject_hash: str, m: int, n: int) -> dict[str, Any]:
    core = multisig_core(subject_hash, m, n)
    return {
        "handle": handle,
        "sign_pub": sign_pub,
        "sig": _sign(private_key, canonical(core)),
        "subject_hash": subject_hash,
        "m": int(m),
        "n": int(n),
    }


def verify_multisig(approvals: list[dict[str, Any]], subject_hash: str, m: int, n: int) -> None:
    if m < 1 or n < m:
        raise QNMRefuse("FED-MULTISIG", "threshold refused")
    core = multisig_core(subject_hash, m, n)
    seen = set()
    good = 0
    for row in approvals:
        raw = b64d(str(row.get("sign_pub") or ""))
        handle = str(row.get("handle") or "")
        assert_handle_matches(handle, raw, key_id_from_pubkey(raw))
        if handle in seen:
            raise QNMRefuse("FED-MULTISIG", "duplicate approval")
        seen.add(handle)
        if row.get("subject_hash") != subject_hash or int(row.get("m") or 0) != int(m):
            raise QNMRefuse("FED-TAMPER", "approval does not match the subject")
        _verify(raw, str(row.get("sig") or ""), canonical(core))
        good += 1
    if good < m:
        raise QNMRefuse("FED-MULTISIG", f"{good} of {m} approvals")


def ref_core(
    *,
    handle: str,
    key_id: str,
    sign_pub: str,
    ref: str,
    object_hash: str,
    prev: str,
    seq: int,
    utc: str,
) -> dict[str, Any]:
    """Signed ref update. This is the default broadcast: hashes, not bytes."""
    return {
        "v": VERSION,
        "kind": "ref",
        "author": AUTHOR,
        "handle": handle,
        "key_id": key_id,
        "sign_pub": sign_pub,
        "ref": ref,
        "object": object_hash,
        "prev": prev,
        "seq": int(seq),
        "utc": utc,
    }


def sign_ref(private_key: Any, **kwargs: Any) -> dict[str, Any]:
    core = ref_core(**kwargs)
    signed = dict(core)
    signed["hash"] = sha256_hex(canonical(core))
    signed["sig"] = _sign(private_key, canonical(core))
    return signed


def verify_ref(update: dict[str, Any]) -> bytes:
    raw = b64d(str(update.get("sign_pub") or ""))
    assert_handle_matches(str(update.get("handle") or ""), raw, str(update.get("key_id") or ""))
    core = ref_core(
        handle=str(update.get("handle") or ""),
        key_id=str(update.get("key_id") or ""),
        sign_pub=str(update.get("sign_pub") or ""),
        ref=str(update.get("ref") or ""),
        object_hash=str(update.get("object") or ""),
        prev=str(update.get("prev") or ""),
        seq=int(update.get("seq") or 0),
        utc=str(update.get("utc") or ""),
    )
    if update.get("v") != VERSION or update.get("kind") != "ref" or update.get("author") != AUTHOR:
        raise QNMRefuse("FED-TAMPER", "ref update header refused")
    if update.get("hash") != sha256_hex(canonical(core)):
        raise QNMRefuse("FED-TAMPER", "ref update hash mismatch")
    obj = str(update.get("object") or "")
    if len(obj) != 64 or any(ch not in "0123456789abcdef" for ch in obj):
        raise QNMRefuse("FED-TAMPER", "ref object is not a sha256 hex digest")
    ref_name = str(update.get("ref") or "")
    if not ref_name or len(ref_name) > 64 or "/" in ref_name or ref_name.startswith("."):
        raise QNMRefuse("FED-TAMPER", "ref name refused")
    _verify(raw, str(update.get("sig") or ""), canonical(core))
    return raw


def fetch_core(*, handle: str, key_id: str, sign_pub: str, object_hash: str, utc: str) -> dict[str, Any]:
    return {
        "v": VERSION,
        "kind": "fetch",
        "author": AUTHOR,
        "from": handle,
        "key_id": key_id,
        "sign_pub": sign_pub,
        "object": object_hash,
        "utc": utc,
    }


def sign_fetch(private_key: Any, **kwargs: Any) -> dict[str, Any]:
    core = fetch_core(**kwargs)
    signed = dict(core)
    signed["sig"] = _sign(private_key, canonical(core))
    return signed


def verify_fetch(request: dict[str, Any]) -> bytes:
    raw = b64d(str(request.get("sign_pub") or ""))
    assert_handle_matches(str(request.get("from") or ""), raw, str(request.get("key_id") or ""))
    core = fetch_core(
        handle=str(request.get("from") or ""),
        key_id=str(request.get("key_id") or ""),
        sign_pub=str(request.get("sign_pub") or ""),
        object_hash=str(request.get("object") or ""),
        utc=str(request.get("utc") or ""),
    )
    if request.get("kind") != "fetch" or request.get("author") != AUTHOR:
        raise QNMRefuse("FED-TAMPER", "fetch request refused")
    _verify(raw, str(request.get("sig") or ""), canonical(core))
    return raw
