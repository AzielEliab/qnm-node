"""Boot / install_root — QNM-BUILD-1.0 §4.

install_root = SHA256(entropy || nonce || optional_genesis)

Two installs produce two roots. Resume is allowed only from
``data/locks/``. A lock is not an account. Scorched locks stay
scorched — no resurrection.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SPEC = "QNM-BUILD-1.0"
COMPANION = "AIH-WP-1.1"
AUTHOR = "Aziel Eliab"
IDENTITY = "Aziel Eliab"
LOCK_DIR = "locks"
LOCK_NAME = "install.lock"
GENESIS_EMPTY = b""

# Live status tokens that must never appear as success / completeness.
FORBIDDEN_LIVE_SYMBOLS = (
    "Lumen",
    "Mandible",
    "lattice_online",
    "mesh_complete",
)


class QNMRefuse(Exception):
    """Hard refuse. Payload is not interpreted after the code is set."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(code if not detail else f"{code}: {detail}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": False,
            "refused": True,
            "code": self.code,
            "detail": self.detail,
            "spec": SPEC,
            "author": AUTHOR,
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_install_root(
    entropy: bytes,
    nonce: bytes,
    genesis: bytes | None = None,
) -> str:
    """SHA256(entropy || nonce || optional_genesis)."""
    blob = entropy + nonce + (genesis if genesis else GENESIS_EMPTY)
    return sha256_hex(blob)


def locks_dir(root: Path) -> Path:
    return Path(root) / "data" / LOCK_DIR


def lock_path(root: Path) -> Path:
    return locks_dir(root) / LOCK_NAME


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def load_lock(root: Path) -> dict[str, Any] | None:
    path = lock_path(root)
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def write_lock(root: Path, record: dict[str, Any]) -> Path:
    path = lock_path(root)
    _atomic_write(
        path,
        json.dumps(record, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
    )
    return path


def install(
    root: Path,
    *,
    entropy: bytes | None = None,
    nonce: bytes | None = None,
    genesis: bytes | None = None,
) -> dict[str, Any]:
    """First boot. Two calls with different entropy/nonce → two roots."""
    existing = load_lock(root)
    if existing is not None:
        raise QNMRefuse(
            "QNM-RESUME-LOCK-ONLY",
            "lock exists; resume from data/locks/ — do not reinstall",
        )
    entropy_b = entropy if entropy is not None else os.urandom(32)
    nonce_b = nonce if nonce is not None else secrets.token_bytes(16)
    genesis_b = genesis if genesis is not None else GENESIS_EMPTY
    install_root = compute_install_root(entropy_b, nonce_b, genesis_b)
    record = {
        "spec": SPEC,
        "companion": COMPANION,
        "author": AUTHOR,
        "identity": IDENTITY,
        "install_root": install_root,
        "entropy_sha256": sha256_hex(entropy_b),
        "nonce_sha256": sha256_hex(nonce_b),
        "genesis_sha256": sha256_hex(genesis_b) if genesis_b else "",
        "created_utc": _utc_now(),
        "scorched": False,
        "resume_only": "data/locks/",
    }
    write_lock(root, record)
    return record


def resume(root: Path, *, from_path: str | Path | None = None) -> dict[str, Any]:
    """Resume only from data/locks/. Any other path is refused."""
    if from_path is not None:
        candidate = Path(from_path)
        allowed = lock_path(root).resolve()
        try:
            same = candidate.resolve() == allowed
        except OSError:
            same = False
        if not same:
            raise QNMRefuse(
                "QNM-RESUME-LOCK-ONLY",
                "resume only in data/locks/",
            )
    record = load_lock(root)
    if record is None:
        raise QNMRefuse("QNM-RESUME-LOCK-ONLY", "no lock in data/locks/")
    if record.get("identity") != IDENTITY:
        raise QNMRefuse("QNM-IDENTITY", "identity is Aziel Eliab only")
    return record


def mark_scorched(root: Path) -> dict[str, Any]:
    record = load_lock(root)
    if record is None:
        raise QNMRefuse("QNM-RESUME-LOCK-ONLY", "no lock to scorch")
    record["scorched"] = True
    record["scorched_utc"] = _utc_now()
    write_lock(root, record)
    return record
