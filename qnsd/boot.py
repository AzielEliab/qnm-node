"""Boot / install_root — QNS-CD-1.0.

Reuses QNM-BUILD-1.0 lock law: install_root = SHA256(entropy || nonce ||
optional_genesis). Resume only from data/locks/. Two installs → two
roots. Scorched locks stay scorched.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from qnm.boot import (  # noqa: F401 — re-export lock law
    AUTHOR,
    FORBIDDEN_LIVE_SYMBOLS,
    IDENTITY,
    QNMRefuse,
    compute_install_root,
    install as qnm_install,
    load_lock,
    lock_path,
    locks_dir,
    mark_scorched,
    resume as qnm_resume,
    sha256_hex,
    write_lock,
    _atomic_write,
    _utc_now,
)

SPEC = "QNS-CD-1.0"
PARENTS = (
    "QNS-WP-1.3",
    "QNM-BUILD-1.0",
    "AIH-WP-1.3",
    "APG",
    "AZPIPE",
    "ChainLock",
)
COMPANION = "QNM-BUILD-1.0"
PAIR_SPEC = "AIH-WP-1.3"
HUB_LAW = "AIH-WP-1.1"


class QNSRefuse(QNMRefuse):
    """Hard refuse. Payload is not interpreted after the code is set."""

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": False,
            "refused": True,
            "code": self.code,
            "detail": self.detail,
            "spec": SPEC,
            "author": AUTHOR,
            "interpreted": False,
        }


def install(
    root: Path,
    *,
    entropy: bytes | None = None,
    nonce: bytes | None = None,
    genesis: bytes | None = None,
) -> dict[str, Any]:
    record = qnm_install(root, entropy=entropy, nonce=nonce, genesis=genesis)
    record["qnsd_spec"] = SPEC
    record["parents"] = list(PARENTS)
    write_lock(root, record)
    return record


def resume(root: Path, *, from_path: str | Path | None = None) -> dict[str, Any]:
    return qnm_resume(root, from_path=from_path)


def ensure_data_dirs(root: Path) -> None:
    for name in ("chain", "locks", "outbox", "receipts", "witness"):
        (Path(root) / "data" / name).mkdir(parents=True, exist_ok=True)
