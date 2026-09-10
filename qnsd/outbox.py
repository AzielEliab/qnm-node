"""Visible outbox + lock-backed wait — QNS-CD-1.0.

Wait survives restart from data/locks/. Cut drops the item. publish is
refused. Anon-broadcast is never a publish path.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from qnsd.boot import AUTHOR, SPEC, QNSRefuse, _atomic_write, _utc_now, sha256_hex

OUTBOX_NAME = "visible.jsonl"
WAIT_LOCK_NAME = "wait.jsonl"


class Outbox:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.path = self.root / "data" / "outbox" / OUTBOX_NAME
        self.lock_path = self.root / "data" / "locks" / WAIT_LOCK_NAME
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.is_file():
            self.path.write_text("", encoding="utf-8")
        if not self.lock_path.is_file():
            self.lock_path.write_text("", encoding="utf-8")
        self._reconcile_from_locks()

    def list(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                items.append(json.loads(line))
        return items

    def waits(self) -> list[dict[str, Any]]:
        return [item for item in self.list() if item.get("waiting")]

    def queue(self, kind: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        body = dict(payload or {})
        if body.get("publish") or kind in ("publish", "anon-broadcast-publish"):
            raise QNSRefuse("QNM-ANON-NO-PUBLISH", "outbox is not a publish path")
        item = {
            "id": sha256_hex(
                f"{kind}:{_utc_now()}:{json.dumps(body, sort_keys=True)}".encode()
            ),
            "kind": kind,
            "payload": body,
            "utc": _utc_now(),
            "visible": True,
            "published": False,
            "waiting": bool(body.get("waiting") or kind == "qns-wait"),
            "from_locks": True,
            "spec": SPEC,
            "author": AUTHOR,
        }
        self._append(item)
        return item

    def wait_photon(self, photon: dict[str, Any], via: str, reason: str) -> dict[str, Any]:
        return self.queue(
            "qns-wait",
            {
                "photon": photon,
                "photon_id": photon.get("photon_id"),
                "via": via,
                "reason": reason,
                "waiting": True,
                "remapped": False,
                "death": False,
            },
        )

    def cut(self, item_id: str) -> dict[str, Any]:
        kept: list[dict[str, Any]] = []
        removed = None
        for item in self.list():
            if item.get("id") == item_id:
                removed = item
            else:
                kept.append(item)
        if removed is None:
            raise QNSRefuse("QNM-OUTBOX-CUT", "unknown outbox id")
        self._rewrite(kept)
        return {
            "ok": True,
            "cut": item_id,
            "remaining": len(kept),
            "spec": SPEC,
            "author": AUTHOR,
        }

    def clear(self) -> None:
        self._rewrite([])

    def resume_from_locks(self) -> list[dict[str, Any]]:
        """Restart path: locks are the source of wait truth."""
        self._reconcile_from_locks()
        return self.waits()

    def _append(self, item: dict[str, Any]) -> None:
        line = json.dumps(item, sort_keys=True, separators=(",", ":"))
        for path in (self.path, self.lock_path):
            with path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()

    def _rewrite(self, items: list[dict[str, Any]]) -> None:
        text = (
            "\n".join(
                json.dumps(item, sort_keys=True, separators=(",", ":")) for item in items
            )
            + ("\n" if items else "")
        )
        _atomic_write(self.path, text)
        _atomic_write(self.lock_path, text)

    def _reconcile_from_locks(self) -> None:
        if not self.lock_path.is_file():
            return
        lock_items: list[dict[str, Any]] = []
        for line in self.lock_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                lock_items.append(json.loads(line))
        if not lock_items:
            return
        visible = self.list()
        ids = {item.get("id") for item in visible}
        missing = [item for item in lock_items if item.get("id") not in ids]
        if missing:
            merged = visible + missing
            self._rewrite(merged)
        elif not visible and lock_items:
            self._rewrite(lock_items)
