"""Crash-safe LAN queue. Not the visible qnsd outbox."""

from __future__ import annotations

import json
import os
import random
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from qnm.fedmesh.wire import canonical, sha256_hex
from qnsd.boot import _utc_now
from qnsd.lan.contract import (
    MAX_QUEUE_BYTES,
    MAX_QUEUE_ITEMS,
    RETRY_BASE_S,
    RETRY_BUDGET,
    RETRY_CAP_S,
    LanRefuse,
)


def _parse(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


class QueueStore:
    def __init__(self, root: Path) -> None:
        self.path = Path(root) / "data" / "lan" / "queue.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, stat.S_IRWXU)
        self.items: list[dict[str, Any]] = []
        if self.path.is_file():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    self.items.append(json.loads(line))

    def get(self, packet_id: str) -> dict[str, Any] | None:
        for item in self.items:
            if item.get("packet_id") == packet_id and item.get("state") in ("queued", "waiting"):
                return item
        return None

    def append(self, item: dict[str, Any]) -> dict[str, Any]:
        active = [row for row in self.items if row.get("state") in ("queued", "waiting")]
        nbytes = sum(int(row.get("nbytes") or 0) for row in active) + int(item.get("nbytes") or 0)
        if len(active) >= MAX_QUEUE_ITEMS or nbytes > MAX_QUEUE_BYTES:
            raise LanRefuse(
                "QNS-LAN-QUOTA",
                "queue cap reached",
                outcome="temporary",
                security=True,
            )
        self.items.append(item)
        self._rewrite()
        return item

    def ready(self, now: datetime | None = None) -> list[dict[str, Any]]:
        moment = now or datetime.now(timezone.utc)
        due = []
        for item in self.items:
            if item.get("state") not in ("queued", "waiting"):
                continue
            try:
                expiry = _parse(str(item["expiry_utc"]))
            except (KeyError, ValueError):
                continue
            if moment > expiry:
                item["state"] = "expired"
                item["last_outcome"] = "permanent"
                item["last_code"] = "QNS-LAN-EXPIRED"
                continue
            try:
                nxt = _parse(str(item.get("next_attempt_utc") or item["created_utc"]))
            except ValueError:
                nxt = moment
            if nxt <= moment:
                due.append(item)
        self._rewrite()
        return due

    def mark(self, packet_id: str, *, state: str, outcome: str, code: str) -> None:
        for item in self.items:
            if item.get("packet_id") == packet_id:
                item["state"] = state
                item["last_outcome"] = outcome
                item["last_code"] = code
        self._rewrite()

    def schedule_retry(self, packet_id: str) -> str:
        """Return ``retry`` or ``spent``. Does not delete other rows."""
        for item in self.items:
            if item.get("packet_id") != packet_id:
                continue
            attempts = int(item.get("attempts") or 0) + 1
            item["attempts"] = attempts
            if attempts >= RETRY_BUDGET:
                item["state"] = "refused"
                item["last_outcome"] = "permanent"
                item["last_code"] = "QNS-LAN-RETRY"
                self._rewrite()
                return "spent"
            delay = min(RETRY_CAP_S, RETRY_BASE_S * (2 ** (attempts - 1)))
            delay = delay * (0.5 + random.random() / 2)
            nxt = datetime.now(timezone.utc) + timedelta(seconds=delay)
            item["state"] = "waiting"
            item["next_attempt_utc"] = nxt.strftime("%Y-%m-%dT%H:%M:%SZ")
            item["last_outcome"] = "temporary"
            self._rewrite()
            return "retry"
        return "missing"

    def _rewrite(self) -> None:
        text = "".join(
            json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
            for item in self.items
        )
        tmp = self.path.with_suffix(".jsonl.tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        tmp.replace(self.path)


def envelope_nbytes(envelope: dict[str, Any]) -> int:
    return len(canonical(envelope))


def new_item(envelope: dict[str, Any], *, packet_id: str, payload_hash: str, expiry_utc: str) -> dict[str, Any]:
    return {
        "packet_id": packet_id,
        "payload_hash": payload_hash,
        "created_utc": _utc_now(),
        "expiry_utc": expiry_utc,
        "attempts": 0,
        "next_attempt_utc": _utc_now(),
        "state": "queued",
        "last_outcome": "",
        "last_code": "",
        "nbytes": envelope_nbytes(envelope),
        "custody": "local",
        "dst_handle": envelope.get("dst_handle"),
        "envelope_sha256": sha256_hex(canonical(envelope)),
        "envelope": envelope,
    }
