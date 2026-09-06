"""Memorial — QNM-BUILD-1.0 §13 + AIH-WP-1.3 pair ledger.

Terminal commemorative record after SCORCHED. Not an account. Not a
key. Cannot resurrect a prior install.

Living pair-ids (AIH-WP-1.3) sit in ``pair_memorial.jsonl`` until
isolate / PHOENIX-LOCK / Scorch / operator cut. The bind is
medium-independent. THIS IS NOT Bell-pair physics.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from qnm.boot import AUTHOR, IDENTITY, SPEC, QNMRefuse, _atomic_write, _utc_now, sha256_hex

MEMORIAL_NAME = "memorial.json"
PAIR_MEMORIAL_NAME = "pair_memorial.jsonl"
PAIR_SPEC = "AIH-WP-1.3"


class Memorial:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.path = self.root / "data" / "witness" / MEMORIAL_NAME
        self.pair_path = self.root / "data" / "witness" / PAIR_MEMORIAL_NAME
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.pair_path.is_file():
            self.pair_path.write_text("", encoding="utf-8")

    def living_pairs(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        if not self.pair_path.is_file():
            return items
        for line in self.pair_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                items.append(json.loads(line))
        return items

    def remember_pair(self, record: dict[str, Any]) -> dict[str, Any]:
        pair_id = str(record.get("pair_id") or "")
        if not pair_id:
            raise QNMRefuse("AIH-HANDSHAKE", "pair_id required")
        for existing in self.living_pairs():
            if existing.get("pair_id") == pair_id:
                return existing
        body = dict(record)
        body.setdefault("spec", PAIR_SPEC)
        body.setdefault("companion", SPEC)
        body.setdefault("author", AUTHOR)
        body.setdefault("identity", IDENTITY)
        body.setdefault("medium_independent", True)
        body.setdefault("bell_pair", False)
        body.setdefault("qubit", False)
        with self.pair_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n")
            fh.flush()
        return body

    def forget_pair(self, pair_id: str) -> dict[str, Any] | None:
        kept: list[dict[str, Any]] = []
        removed = None
        for item in self.living_pairs():
            if item.get("pair_id") == pair_id:
                removed = item
            else:
                kept.append(item)
        if removed is None:
            return None
        lines = [json.dumps(i, sort_keys=True, separators=(",", ":")) for i in kept]
        _atomic_write(self.pair_path, ("\n".join(lines) + ("\n" if lines else "")))
        return removed

    def forget_all_pairs(self) -> int:
        n = len(self.living_pairs())
        _atomic_write(self.pair_path, "")
        return n

    def write(self, install_root: str, reason: str, pairs_cut: list[str] | None = None) -> dict[str, Any]:
        record = {
            "kind": "MEMORIAL",
            "install_root": install_root,
            "reason": reason,
            "utc": _utc_now(),
            "identity": IDENTITY,
            "author": AUTHOR,
            "spec": SPEC,
            "companion": PAIR_SPEC,
            "account": None,
            "resurrectable": False,
            "pairs_cut": list(pairs_cut or []),
            "bell_pair": False,
            "qubit": False,
        }
        record["hash"] = sha256_hex(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        )
        _atomic_write(
            self.path,
            json.dumps(record, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        )
        return record

    def load(self) -> dict[str, Any] | None:
        if not self.path.is_file():
            return None
        return json.loads(self.path.read_text(encoding="utf-8"))
