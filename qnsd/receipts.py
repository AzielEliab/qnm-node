"""Disk receipts — QNS-CD-1.0.

One JSONL log plus one leaf file per event under data/receipts/.
AZPIPE skips fold receipts when FoldLock is missing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from qnsd.boot import AUTHOR, SPEC
from qnsd.chain import Chain


class Receipts:
    def __init__(self, root: Path, chain: Chain) -> None:
        self.root = Path(root)
        self.chain = chain
        self.dir = self.root / "data" / "receipts"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.log = self.dir / "receipts.jsonl"
        if not self.log.is_file():
            self.log.write_text("", encoding="utf-8")

    def write(self, kind: str, body: dict[str, Any]) -> dict[str, Any] | None:
        if kind.startswith("fold") and body.get("skip_receipt"):
            return None
        if body.get("skip_receipt") and kind in ("fold", "azpipe-fold"):
            return None
        link = self.chain.append(kind, body)
        receipt = {
            "kind": kind,
            "body": body,
            "hash": link.hash,
            "prev": link.prev,
            "seq": link.seq,
            "utc": link.utc,
            "spec": SPEC,
            "author": AUTHOR,
            "on_disk": True,
        }
        with self.log.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
            fh.flush()
        leaf = self.dir / f"{link.seq:06d}-{link.hash[:16]}.json"
        leaf.write_text(
            json.dumps(receipt, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return receipt

    def list(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for line in self.log.read_text(encoding="utf-8").splitlines():
            if line.strip():
                items.append(json.loads(line))
        return items
