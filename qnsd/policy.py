"""Send policy — QNS-CD-1.0.

always_try walks VIA_ORDER. force_via restricts to one class (fail →
wait, no silent remap). sticky-via is banned.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from qnsd.boot import AUTHOR, SPEC, QNSRefuse, _atomic_write, _utc_now
from qnsd.vias.base import VIA_ORDER

POLICY_NAME = "policy.json"


class Policy:
    def __init__(self, root: Path | None = None) -> None:
        self.root = Path(root) if root is not None else None
        self.always_try = True
        self.force_via: str | None = None
        self.hop_max = 8
        self.operator = False
        self.sticky_via = False
        if self.root is not None:
            self._load()

    def path(self) -> Path | None:
        if self.root is None:
            return None
        return self.root / "data" / "locks" / POLICY_NAME

    def snapshot(self) -> dict[str, Any]:
        return {
            "always_try": bool(self.always_try),
            "force_via": self.force_via,
            "hop_max": int(self.hop_max),
            "operator": bool(self.operator),
            "sticky_via": False,
            "via_order": list(VIA_ORDER),
            "spec": SPEC,
            "author": AUTHOR,
        }

    def apply(self, body: dict[str, Any]) -> dict[str, Any]:
        if body.get("sticky_via") is True or body.get("sticky") is True:
            raise QNSRefuse("QNS-STICKY-VIA", "sticky-via banned")
        if "always_try" in body:
            self.always_try = bool(body["always_try"])
        if "force_via" in body:
            via = body.get("force_via")
            if via in ("", None, False):
                self.force_via = None
            else:
                name = str(via)
                if name not in VIA_ORDER:
                    raise QNSRefuse("QNS-VIA-UNKNOWN", f"unknown via:{name}")
                self.force_via = name
        if "hop_max" in body:
            self.hop_max = int(body["hop_max"])
        if body.get("operator") is True:
            self.operator = True
        if body.get("operator") is False:
            self.operator = False
        self.sticky_via = False
        self._persist()
        return self.snapshot()

    def restricted(self) -> bool:
        return bool(self.force_via)

    def _persist(self) -> None:
        path = self.path()
        if path is None:
            return
        record = dict(self.snapshot())
        record["utc"] = _utc_now()
        _atomic_write(
            path,
            json.dumps(record, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        )

    def _load(self) -> None:
        path = self.path()
        if path is None or not path.is_file():
            return
        data = json.loads(path.read_text(encoding="utf-8"))
        self.always_try = bool(data.get("always_try", True))
        force = data.get("force_via")
        self.force_via = str(force) if force else None
        self.hop_max = int(data.get("hop_max") or 8)
        self.operator = bool(data.get("operator") or False)
        self.sticky_via = False
