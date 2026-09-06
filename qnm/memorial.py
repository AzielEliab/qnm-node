"""Memorial — QNM-BUILD-1.0 §13.

Terminal commemorative record after SCORCHED. Not an account. Not a
key. Cannot resurrect a prior install.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from qnm.boot import AUTHOR, IDENTITY, SPEC, _atomic_write, _utc_now, sha256_hex

MEMORIAL_NAME = "memorial.json"


class Memorial:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.path = self.root / "data" / "witness" / MEMORIAL_NAME
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, install_root: str, reason: str) -> dict[str, Any]:
        record = {
            "kind": "MEMORIAL",
            "install_root": install_root,
            "reason": reason,
            "utc": _utc_now(),
            "identity": IDENTITY,
            "author": AUTHOR,
            "spec": SPEC,
            "account": None,
            "resurrectable": False,
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
