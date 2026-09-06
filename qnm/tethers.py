"""Declared tethers — QNM-BUILD-1.0 §10.

Visible corridors only. Cut drops clean: no leftover, no auto-rewire.
Companion geometry is AIH-WP-1.1 (declared tethers, not Hub meaning).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from qnm.boot import AUTHOR, SPEC, QNMRefuse, _atomic_write, _utc_now, sha256_hex

TETHER_NAME = "declared.jsonl"


class Tethers:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.path = self.root / "data" / "witness" / TETHER_NAME
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.is_file():
            self.path.write_text("", encoding="utf-8")

    def list(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                items.append(json.loads(line))
        return items

    def declare(self, src: str, dst: str) -> dict[str, Any]:
        if not src or not dst or src == dst:
            raise QNMRefuse("QNM-TETHER-CLEAN", "declared pair required")
        for item in self.list():
            if item.get("src") == src and item.get("dst") == dst:
                raise QNMRefuse("QNM-TETHER-CLEAN", "already declared")
        item = {
            "id": sha256_hex(f"{src}|{dst}|{_utc_now()}".encode()),
            "src": src,
            "dst": dst,
            "utc": _utc_now(),
            "spec": SPEC,
            "author": AUTHOR,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n")
            fh.flush()
        return item

    def cut(self, src: str, dst: str) -> dict[str, Any]:
        kept: list[dict[str, Any]] = []
        removed = None
        for item in self.list():
            if item.get("src") == src and item.get("dst") == dst:
                removed = item
            else:
                kept.append(item)
        if removed is None:
            raise QNMRefuse("QNM-TETHER-CLEAN", "no such tether")
        lines = [json.dumps(i, sort_keys=True, separators=(",", ":")) for i in kept]
        _atomic_write(self.path, ("\n".join(lines) + ("\n" if lines else "")))
        leftover = [
            i for i in self.list() if i.get("src") == src and i.get("dst") == dst
        ]
        if leftover:
            raise QNMRefuse("QNM-TETHER-CLEAN", "cut left residue")
        return {
            "ok": True,
            "cut": {"src": src, "dst": dst},
            "remaining": len(kept),
            "residue": False,
            "auto_rewire": False,
            "spec": SPEC,
            "author": AUTHOR,
        }

    def clear(self) -> None:
        _atomic_write(self.path, "")
