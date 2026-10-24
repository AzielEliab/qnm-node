"""LAN-local sequence ledger. Calls classify_link. Does not change it."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from qnm.fedmesh.chain import classify_link
from qnm.fedmesh.wire import GENESIS_PREV
from qnsd.lan.contract import LanRefuse


class SeqLedger:
    def __init__(self, root: Path) -> None:
        self.path = Path(root) / "data" / "lan" / "seq.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, stat.S_IRWXU)
        self.tips: dict[str, dict[str, Any]] = {}
        self.seen: dict[tuple[str, int], str] = {}
        if self.path.is_file():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    self._remember(json.loads(line))

    def tip(self, handle: str) -> tuple[int, str]:
        row = self.tips.get(handle)
        if row is None:
            return 0, GENESIS_PREV
        return int(row["seq"]), str(row["hash"])

    def preview(self, handle: str, seq: int, prev: str, digest: str) -> None:
        self._classify(handle, seq, prev, digest)

    def accept(self, handle: str, seq: int, prev: str, digest: str) -> None:
        self._classify(handle, seq, prev, digest)
        row = {"handle": handle, "seq": int(seq), "prev": str(prev), "hash": str(digest)}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._remember(row)

    def _classify(self, handle: str, seq: int, prev: str, digest: str) -> None:
        key = (handle, int(seq))
        tip = self.tips.get(handle)
        try:
            classify_link(
                seen=self.seen.get(key),
                tip_seq=None if tip is None else int(tip["seq"]),
                tip_hash=None if tip is None else str(tip["hash"]),
                seq=int(seq),
                prev=str(prev),
                digest=str(digest),
            )
        except Exception as exc:
            code = getattr(exc, "code", "FED-FORK")
            security = code != "FED-GAP"
            outcome = "temporary" if code == "FED-GAP" else "refused"
            raise LanRefuse(str(code), "sequence refused", outcome=outcome, security=security) from exc

    def _remember(self, row: dict[str, Any]) -> None:
        handle = str(row["handle"])
        seq = int(row["seq"])
        self.seen[(handle, seq)] = str(row["hash"])
        self.tips[handle] = {"seq": seq, "hash": str(row["hash"])}
