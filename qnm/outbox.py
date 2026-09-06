"""Visible outbox — QNM-BUILD-1.0 §9.

Queued locally. Listed in full. Cut drops the item. Nothing publishes.
AnonBroadcast is never a publish path.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from qnm.boot import AUTHOR, SPEC, QNMRefuse, _atomic_write, _utc_now, sha256_hex

OUTBOX_NAME = "visible.jsonl"


class Outbox:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.path = self.root / "data" / "outbox" / OUTBOX_NAME
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.is_file():
            self.path.write_text("", encoding="utf-8")

    def list(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        text = self.path.read_text(encoding="utf-8")
        for line in text.splitlines():
            if line.strip():
                items.append(json.loads(line))
        return items

    def queue(self, kind: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        body = dict(payload or {})
        if body.get("publish") or kind in ("publish", "anon-broadcast-publish"):
            raise QNMRefuse("QNM-ANON-NO-PUBLISH", "outbox is not a publish path")
        item = {
            "id": sha256_hex(f"{kind}:{_utc_now()}:{json.dumps(body, sort_keys=True)}".encode()),
            "kind": kind,
            "payload": body,
            "utc": _utc_now(),
            "visible": True,
            "published": False,
            "spec": SPEC,
            "author": AUTHOR,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n")
            fh.flush()
        return item

    def cut(self, item_id: str) -> dict[str, Any]:
        kept: list[dict[str, Any]] = []
        removed = None
        for item in self.list():
            if item.get("id") == item_id:
                removed = item
            else:
                kept.append(item)
        if removed is None:
            raise QNMRefuse("QNM-OUTBOX-CUT", "unknown outbox id")
        lines = [
            json.dumps(item, sort_keys=True, separators=(",", ":")) for item in kept
        ]
        _atomic_write(self.path, ("\n".join(lines) + ("\n" if lines else "")))
        return {
            "ok": True,
            "cut": item_id,
            "remaining": len(kept),
            "spec": SPEC,
            "author": AUTHOR,
        }

    def clear(self) -> None:
        _atomic_write(self.path, "")
