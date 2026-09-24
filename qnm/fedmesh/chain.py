"""Per-handle receipt ledger.

Rejects replay (same handle + seq + hash), forks (same seq, other
hash, or prev that is not the previous hash), wrong-key handles,
sequence gaps, and tampered anchors.

Author: Aziel Eliab only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from qnm.boot import QNMRefuse
from qnm.fedmesh.wire import GENESIS_PREV, verify_anchor_crypto


def classify_link(
    *,
    seen: str | None,
    tip_seq: int | None,
    tip_hash: str | None,
    seq: int,
    prev: str,
    digest: str,
) -> None:
    """Shared fork / replay / gap check for receipt chains and ref branches."""
    if seq < 1:
        raise QNMRefuse("FED-GAP", "sequence must start at 1")
    if seen is not None:
        if seen == digest:
            raise QNMRefuse("FED-REPLAY", "sequence already accepted")
        raise QNMRefuse("FED-FORK", "sequence already committed to a different hash")
    if tip_seq is None:
        if seq != 1:
            raise QNMRefuse("FED-GAP", "missing earlier link")
        if prev != GENESIS_PREV:
            raise QNMRefuse("FED-FORK", "first prev is not genesis")
        return
    if seq == tip_seq + 1:
        if prev != tip_hash:
            raise QNMRefuse("FED-FORK", "prev is not the last hash")
        return
    if seq > tip_seq + 1:
        raise QNMRefuse("FED-GAP", "sequence gap")
    raise QNMRefuse("FED-FORK", "sequence goes backwards")


class Ledger:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.tips: dict[str, dict[str, Any]] = {}
        self.seen: dict[tuple[str, int], str] = {}
        self.anchors: dict[str, list[dict[str, Any]]] = {}
        if self.path.is_file():
            self._load()

    def _load(self) -> None:
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            anchor = json.loads(line)
            self._accept(anchor, persist=False)

    def _accept(self, anchor: dict[str, Any], *, persist: bool) -> dict[str, Any]:
        verify_anchor_crypto(anchor)
        handle = str(anchor["handle"])
        seq = int(anchor["seq"])
        prev = str(anchor["prev"])
        digest = str(anchor["hash"])
        key = (handle, seq)
        tip = self.tips.get(handle)
        classify_link(
            seen=self.seen.get(key),
            tip_seq=None if tip is None else int(tip["seq"]),
            tip_hash=None if tip is None else str(tip["hash"]),
            seq=seq,
            prev=prev,
            digest=digest,
        )
        if persist:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(anchor, sort_keys=True, separators=(",", ":")) + "\n")
                fh.flush()
        self.seen[key] = digest
        self.tips[handle] = {"seq": seq, "hash": digest}
        self.anchors.setdefault(handle, []).append(anchor)
        return anchor

    def submit(self, anchor: dict[str, Any]) -> dict[str, Any]:
        return self._accept(anchor, persist=True)

    def tip(self, handle: str) -> tuple[int, str]:
        row = self.tips.get(handle)
        if row is None:
            return 0, GENESIS_PREV
        return int(row["seq"]), str(row["hash"])

    def prefix(self, handle: str) -> list[dict[str, Any]]:
        return list(self.anchors.get(handle) or [])

    def verify_all(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {"ok": True, "handles": len(self.tips), "receipts": len(self.seen), "errors": []}
        try:
            fresh = Ledger(self.path)
        except QNMRefuse as exc:
            return {
                "ok": False,
                "handles": len(self.tips),
                "receipts": len(self.seen),
                "errors": [f"{exc.code}: {exc.detail}"],
            }
        return {"ok": True, "handles": len(fresh.tips), "receipts": len(fresh.seen), "errors": []}
