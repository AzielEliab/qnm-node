"""Cold-shelf tip packs at rest — honest operator-key wrap.

No invented key in git. Operator key from QNM_SHELF_KEY or
QNM_SHELF_KEY_FILE only. Placeholder keys refuse.

Default stdlib wrap is HMAC-SHA256 counter XOR + HMAC-SHA256 MAC,
labeled hmac-sha256-ctr — not AES. If the optional `cryptography`
extra is installed, AES-256-GCM is used and labeled honestly.

Local plaintext packs may stay under data/archive/. Non-local
plaintext export refuses unless operator_plaintext_export=true.
Remote without TLS refuses.

Author: Aziel Eliab only.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path
from typing import Any

from qnm.boot import AUTHOR, SPEC, QNMRefuse, sha256_hex
from qnm.fold import fold_sensitive, foldlock_cite
from qnm.surface import PLACEHOLDER_TOKENS, is_loopback_bind

SHELF_SPEC = "QNM-SHELF-1.0"
MAGIC = "QNMS1"
ALG_HMAC = "hmac-sha256-ctr"
ALG_AES = "aes-256-gcm"
KDF = "pbkdf2-hmac-sha256"
PBKDF2_ITERS = 210_000
KEY_ENV = "QNM_SHELF_KEY"
KEY_FILE_ENV = "QNM_SHELF_KEY_FILE"
NONCE_LEN = 16
SALT_LEN = 16
MAC_LEN = 32


def cryptography_available() -> bool:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401

        return True
    except ImportError:
        return False


def load_operator_key(
    key: bytes | str | None = None,
    *,
    key_file: str | Path | None = None,
) -> bytes:
    """Operator-supplied key only. Empty / placeholder / invented refuse."""
    raw: bytes | None = None
    if key is not None:
        raw = key.encode("utf-8") if isinstance(key, str) else bytes(key)
    elif key_file is not None or os.environ.get(KEY_FILE_ENV):
        path = Path(str(key_file or os.environ.get(KEY_FILE_ENV) or ""))
        if not path.is_file():
            raise QNMRefuse("QNM-SHELF-NO-KEY", "operator shelf key file missing")
        raw = path.read_bytes().strip()
    elif os.environ.get(KEY_ENV):
        raw = os.environ[KEY_ENV].encode("utf-8")
    if not raw:
        raise QNMRefuse(
            "QNM-SHELF-NO-KEY",
            "operator shelf key required (QNM_SHELF_KEY / QNM_SHELF_KEY_FILE); no invented key",
        )
    probe = raw.decode("utf-8", errors="replace").strip().lower()
    if probe in PLACEHOLDER_TOKENS or len(raw) < 16:
        raise QNMRefuse("QNM-SHELF-NO-KEY", "placeholder / short shelf key refused")
    return raw


def _derive(key: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", key, salt, PBKDF2_ITERS, dklen=32)


def _hmac_stream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def _xor(data: bytes, stream: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, stream))


def encrypt_pack(
    raw: bytes | str,
    *,
    key: bytes | str | None = None,
    key_file: str | Path | None = None,
) -> dict[str, Any]:
    """Wrap tip-pack bytes. Operator key required. No invented cipher claim."""
    body = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
    if not body:
        raise QNMRefuse("QNM-SHELF-EMPTY", "shelf pack needs bytes")
    secret = load_operator_key(key, key_file=key_file)
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    derived = _derive(secret, salt)
    if cryptography_available():
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        ct = AESGCM(derived).encrypt(nonce, body, MAGIC.encode("ascii"))
        alg = ALG_AES
        mac = ""
    else:
        stream = _hmac_stream(derived, nonce, len(body))
        ct = _xor(body, stream)
        mac = hmac.new(derived, b"QNMS1-MAC" + nonce + ct, hashlib.sha256).hexdigest()
        alg = ALG_HMAC
    folded = fold_sensitive({"kind": "shelf-pack", "bytes": len(body), "alg": alg})
    envelope = {
        "magic": MAGIC,
        "v": SHELF_SPEC,
        "alg": alg,
        "kdf": KDF,
        "iters": PBKDF2_ITERS,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "mac": mac,
        "ct": ct.hex(),
        "plain_digest": sha256_hex(body),
        "bytes": len(body),
        "fold": folded,
        "foldlock": foldlock_cite(),
        "spec": SHELF_SPEC,
        "build": SPEC,
        "author": AUTHOR,
    }
    return envelope


def decrypt_pack(
    envelope: dict[str, Any],
    *,
    key: bytes | str | None = None,
    key_file: str | Path | None = None,
) -> bytes:
    if not isinstance(envelope, dict) or envelope.get("magic") != MAGIC:
        raise QNMRefuse("QNM-SHELF-WRAP", "not a QNMS1 shelf envelope")
    secret = load_operator_key(key, key_file=key_file)
    salt = bytes.fromhex(str(envelope.get("salt") or ""))
    nonce = bytes.fromhex(str(envelope.get("nonce") or ""))
    ct = bytes.fromhex(str(envelope.get("ct") or ""))
    derived = _derive(secret, salt)
    alg = str(envelope.get("alg") or "")
    if alg == ALG_AES:
        if not cryptography_available():
            raise QNMRefuse("QNM-SHELF-NO-BACKEND", "AES-256-GCM envelope needs cryptography extra")
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        try:
            body = AESGCM(derived).decrypt(nonce, ct, MAGIC.encode("ascii"))
        except Exception as exc:  # noqa: BLE001 — refuse, do not interpret
            raise QNMRefuse("QNM-SHELF-WRAP", "AES-GCM open failed") from exc
    elif alg == ALG_HMAC:
        expect = str(envelope.get("mac") or "")
        got = hmac.new(derived, b"QNMS1-MAC" + nonce + ct, hashlib.sha256).hexdigest()
        if not expect or not hmac.compare_digest(expect, got):
            raise QNMRefuse("QNM-SHELF-WRAP", "shelf MAC mismatch")
        body = _xor(ct, _hmac_stream(derived, nonce, len(ct)))
    else:
        raise QNMRefuse("QNM-SHELF-WRAP", "unknown shelf alg")
    expect_digest = str(envelope.get("plain_digest") or "")
    if expect_digest and expect_digest != sha256_hex(body):
        raise QNMRefuse("QNM-SHELF-WRAP", "shelf plain digest mismatch")
    return body


def is_remote_dest(dest: str) -> bool:
    token = str(dest or "").strip().lower()
    if not token:
        return False
    if token.startswith("http://"):
        return True
    if token.startswith("https://"):
        host = token.split("://", 1)[1].split("/", 1)[0]
        return not is_loopback_bind(host.split(":")[0])
    if token in {"wan", "remote", "public", "0.0.0.0"}:
        return True
    return False


def export_tip(
    raw: bytes | str,
    dest: str = "local",
    *,
    key: bytes | str | None = None,
    key_file: str | Path | None = None,
    tls: bool = False,
    operator_plaintext_export: bool = False,
    encrypt: bool = True,
) -> dict[str, Any]:
    """Export a tip pack. Non-local plaintext refuses without operator flag."""
    body = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
    remote = is_remote_dest(dest)
    if remote and not tls and not operator_plaintext_export:
        raise QNMRefuse(
            "QNM-NO-PLAINTEXT-REMOTE",
            "plaintext tip export over non-local refuses without operator_plaintext_export + TLS",
        )
    if remote and not tls:
        raise QNMRefuse(
            "QNM-NO-PLAINTEXT-REMOTE",
            "remote tip export needs TLS",
        )
    if remote and encrypt is False and not operator_plaintext_export:
        raise QNMRefuse(
            "QNM-NO-PLAINTEXT-REMOTE",
            "non-local plaintext tip export needs explicit operator_plaintext_export",
        )
    if encrypt:
        envelope = encrypt_pack(body, key=key, key_file=key_file)
        envelope["dest"] = dest
        envelope["remote"] = remote
        envelope["tls"] = bool(tls)
        envelope["plaintext"] = False
        return envelope
    folded = fold_sensitive({"kind": "shelf-plain-export", "dest": dest, "bytes": len(body)})
    return {
        "ok": True,
        "dest": dest,
        "remote": remote,
        "tls": bool(tls),
        "plaintext": True,
        "plain_digest": sha256_hex(body),
        "bytes": len(body),
        "operator_plaintext_export": True,
        "fold": folded,
        "foldlock": foldlock_cite(),
        "spec": SHELF_SPEC,
        "author": AUTHOR,
    }


def restore_signed(
    raw: bytes | str,
    digest: str | None,
    *,
    envelope: dict[str, Any] | None = None,
    key: bytes | str | None = None,
    key_file: str | Path | None = None,
) -> dict[str, Any]:
    """Restore a tip pack only with a matching digest. Unsigned refuses."""
    expect = str(digest or "").strip().lower()
    if not expect:
        raise QNMRefuse("QNM-TIP-UNSIGNED", "unsigned tip restore refused")
    if envelope is not None:
        body = decrypt_pack(envelope, key=key, key_file=key_file)
    else:
        body = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
    got = sha256_hex(body)
    if got != expect:
        raise QNMRefuse("QNM-TIP-UNSIGNED", "tip restore digest mismatch")
    return {
        "ok": True,
        "restored": True,
        "signed": True,
        "digest": got,
        "bytes": len(body),
        "spec": SHELF_SPEC,
        "author": AUTHOR,
    }
