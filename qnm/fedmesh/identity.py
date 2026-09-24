"""Per-node and per-tenant keystore.

Ed25519 signs. A separate X25519 key encrypts. The encryption public
key is signed by the Ed25519 key (box binding) so a relay cannot swap it.

Private seeds are sealed with scrypt + AES-256-GCM.

* Tenant seals use that tenant's passphrase. The passphrase is not
  stored. The Admin role has no decrypt API.
* The host owner, when started with no passphrase, is sealed with a
  random file ``unattended.seal`` (mode 0600) so the local daemon can
  sign receipts. A full disk copy includes that file. That is file
  permission protection, not a passphrase.

Argon2id is not used: it is not in the Python standard library or in
the ``cryptography`` package this process already depends on. scrypt
is the KDF that actually runs.

Author: Aziel Eliab only.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

from qnm.boot import QNMRefuse
from qnm.fedmesh.wire import (
    b64d,
    b64e,
    box_binding,
    handle_from_pubkey,
    key_id_from_pubkey,
    sign_box_binding,
)

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SEAL_NAME = "private.seal"
PUBLIC_NAME = "public.json"
UNATTENDED_NAME = "unattended.seal"


def _chmod_private(path: Path) -> None:
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, stat.S_IRWXU)
    path.write_text(text, encoding="utf-8")
    _chmod_private(path)


def _scrypt(password: bytes, salt: bytes) -> bytes:
    return hashlib.scrypt(password, salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32)


def _seal_bytes(password: bytes, plaintext: bytes) -> dict[str, Any]:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _scrypt(password, salt)
    ct = AESGCM(key).encrypt(nonce, plaintext, b"fedmesh-seal")
    return {"salt": b64e(salt), "nonce": b64e(nonce), "ct": b64e(ct)}


def _open_bytes(password: bytes, sealed: dict[str, Any]) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        key = _scrypt(password, b64d(str(sealed["salt"])))
        return AESGCM(key).decrypt(b64d(str(sealed["nonce"])), b64d(str(sealed["ct"])), b"fedmesh-seal")
    except QNMRefuse:
        raise
    except Exception as exc:  # noqa: BLE001
        raise QNMRefuse("FED-PASSPHRASE", "keystore did not open") from exc


class Identity:
    """Unlocked signing identity. ``repr`` has the handle only."""

    def __init__(
        self,
        *,
        handle: str,
        key_id: str,
        sign_private: Any,
        box_private: Any,
        card: dict[str, Any],
        seal_kind: str,
    ) -> None:
        self.handle = handle
        self.key_id = key_id
        self._sign = sign_private
        self._box = box_private
        self.card = card
        self.seal_kind = seal_kind

    def __repr__(self) -> str:
        return f"Identity(handle={self.handle})"

    @property
    def sign_private(self) -> Any:
        return self._sign

    @property
    def box_private(self) -> Any:
        return self._box


def _generate_seeds() -> tuple[bytes, bytes]:
    return os.urandom(32), os.urandom(32)


def _identity_from_seeds(sign_seed: bytes, box_seed: bytes, *, seal_kind: str) -> Identity:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    sign_private = Ed25519PrivateKey.from_private_bytes(sign_seed)
    box_private = X25519PrivateKey.from_private_bytes(box_seed)
    sign_raw = sign_private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    box_raw = box_private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    handle = handle_from_pubkey(sign_raw)
    key_id = key_id_from_pubkey(sign_raw)
    sign_pub = b64e(sign_raw)
    box_pub = b64e(box_raw)
    card = box_binding(handle, key_id, sign_pub, box_pub)
    card["box_sig"] = sign_box_binding(sign_private, handle, key_id, sign_pub, box_pub)
    card["seal"] = seal_kind
    return Identity(
        handle=handle,
        key_id=key_id,
        sign_private=sign_private,
        box_private=box_private,
        card=card,
        seal_kind=seal_kind,
    )


def create_keystore(directory: Path, password: bytes, *, seal_kind: str) -> Identity:
    """Create a new keystore. ``password`` is not written."""
    directory = Path(directory)
    if (directory / SEAL_NAME).is_file():
        raise QNMRefuse("FED-TENANT", "keystore already exists")
    sign_seed, box_seed = _generate_seeds()
    ident = _identity_from_seeds(sign_seed, box_seed, seal_kind=seal_kind)
    plaintext = canonical_seeds(sign_seed, box_seed)
    sealed = _seal_bytes(password, plaintext)
    sealed["kdf"] = "scrypt"
    sealed["n"] = SCRYPT_N
    sealed["r"] = SCRYPT_R
    sealed["p"] = SCRYPT_P
    sealed["seal"] = seal_kind
    sealed["alg"] = "aes-256-gcm"
    _write_private(directory / PUBLIC_NAME, json.dumps(ident.card, sort_keys=True, indent=2) + "\n")
    # Public card is not secret, but the directory stays owner-only.
    os.chmod(directory / PUBLIC_NAME, stat.S_IRUSR | stat.S_IWUSR)
    _write_private(directory / SEAL_NAME, json.dumps(sealed, sort_keys=True, indent=2) + "\n")
    return ident


def canonical_seeds(sign_seed: bytes, box_seed: bytes) -> bytes:
    return json.dumps(
        {"box_seed": b64e(box_seed), "sign_seed": b64e(sign_seed)},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def open_keystore(directory: Path, password: bytes) -> Identity:
    directory = Path(directory)
    sealed = json.loads((directory / SEAL_NAME).read_text(encoding="utf-8"))
    raw = json.loads(_open_bytes(password, sealed).decode("utf-8"))
    ident = _identity_from_seeds(b64d(raw["sign_seed"]), b64d(raw["box_seed"]), seal_kind=str(sealed.get("seal") or ""))
    return ident


def load_or_create_owner(directory: Path, passphrase: str | None) -> Identity:
    """Owner identity. Passphrase if the operator set one, else unattended seal file."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, stat.S_IRWXU)
    seal_path = directory / SEAL_NAME
    if seal_path.is_file():
        if passphrase:
            return open_keystore(directory, passphrase.encode("utf-8"))
        unattended = directory / UNATTENDED_NAME
        if not unattended.is_file():
            raise QNMRefuse(
                "FED-PASSPHRASE",
                "owner keystore needs QNM_NODE_PASSPHRASE or the unattended seal file",
            )
        return open_keystore(directory, unattended.read_bytes())
    if passphrase:
        return create_keystore(directory, passphrase.encode("utf-8"), seal_kind="scrypt-passphrase")
    password = os.urandom(32)
    _write_private(directory / UNATTENDED_NAME, "")
    (directory / UNATTENDED_NAME).write_bytes(password)
    _chmod_private(directory / UNATTENDED_NAME)
    return create_keystore(directory, password, seal_kind="unattended-file")
