"""AZPIPE hop list — QNS-CD-1.0 / AP-WP-0.2.

Inbound: frag → sweep → fold → static → fold → entry.

FoldLock is optional. If foldlock.py is missing, fld3-wire still folds
block-keys / off-origin URLs, but fold receipts are skipped.
"""

from __future__ import annotations

import json
import re
from typing import Any

from qnsd.apg import APG
from qnsd.boot import AUTHOR, SPEC, QNSRefuse, sha256_hex
from qnsd.photon import canonical_bytes

HOPS = ("frag", "sweep", "fold", "static", "fold", "entry")
MAGIC = "FLD3"
PIPE_VER = "AZPIPE-0.2"

_BLOCK_KEYS = frozenset(
    {"password", "private_key", "secret", "ssn", "legal_name", "home_address"}
)
_ALLOW_HOSTS = (
    "www.azielcorpuslibrary.net",
    "godlock.uk",
    "www.azieleliab.com",
    "aziel-runtime.vibelock.workers.dev",
)
_URL_RE = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)


def foldlock_available() -> bool:
    try:
        import foldlock  # type: ignore  # noqa: F401

        return True
    except ImportError:
        try:
            import qnsd.foldlock  # type: ignore  # noqa: F401

            return True
        except ImportError:
            return False


def _fold_text(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        url = match.group(0)
        host = url.split("://", 1)[-1].split("/", 1)[0].lower()
        if host in _ALLOW_HOSTS:
            return url
        return "[FLD3:url]"

    return _URL_RE.sub(repl, text)


def _fold_obj(obj: Any) -> Any:
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for key, value in obj.items():
            if str(key).lower() in _BLOCK_KEYS:
                out[key] = "[FLD3:block]"
            else:
                out[key] = _fold_obj(value)
        return out
    if isinstance(obj, list):
        return [_fold_obj(item) for item in obj]
    if isinstance(obj, str):
        return _fold_text(obj)
    return obj


def fld3_wire(payload: dict[str, Any]) -> dict[str, Any]:
    return _fold_obj(payload)


class AZPIPE:
    """Admission path. Memory never sees raw inbound bytes after sweep."""

    def __init__(self, apg: APG | None = None) -> None:
        self.apg = apg or APG()
        self.hops_done: list[str] = []

    def admit(self, raw: bytes | str) -> dict[str, Any]:
        self.hops_done = []
        data = raw.encode("utf-8") if isinstance(raw, str) else raw

        # frag — empty / ungrounded inbound refuses before sweep spends work
        if not data or not data.strip():
            raise QNSRefuse("QNS-AZPIPE-FRAG", "empty inbound")
        self.hops_done.append("frag")

        # sweep — APG raw-byte airlock. Poison never walks.
        self.apg.scan_raw(data)
        admitted = self.apg.admit(data)
        self.hops_done.append("sweep")

        # fold — FoldLock or fld3-wire
        folded = fld3_wire(admitted)
        have_foldlock = foldlock_available()
        fold_receipt = have_foldlock
        self.hops_done.append("fold")

        # static — canonical freeze
        frozen = json.loads(canonical_bytes(folded).decode("utf-8"))
        body_hash = sha256_hex(canonical_bytes(frozen))
        self.hops_done.append("static")

        # fold again — tethers that appear only after canonicalization
        frozen = fld3_wire(frozen)
        self.hops_done.append("fold")

        # entry — fact-bearing card (caller stamps chain)
        card = {
            "magic": MAGIC,
            "v": PIPE_VER,
            "dir": "in",
            "path": list(HOPS),
            "ok": True,
            "h": body_hash,
            "fh": body_hash,
            "foldlock": have_foldlock,
            "teth": "foldlock.py" if have_foldlock else "fld3-wire",
            "fold_receipt": fold_receipt,
            "skip_receipt": not fold_receipt,
            "inner": frozen,
            "hops_done": list(self.hops_done) + ["entry"],
            "spec": SPEC,
            "author": AUTHOR,
        }
        self.hops_done.append("entry")
        card["hops_done"] = list(self.hops_done)
        return card
