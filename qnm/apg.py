"""Airlock Poison Gate — QNM-BUILD-1.0 §7.

Every ingress is scanned as raw bytes first. Poison is refused, not
interpreted. Forbidden live symbols (Lumen, Mandible, lattice_online,
mesh_complete) never become success tokens.
"""

from __future__ import annotations

import json
import re
from typing import Any

from qnm.boot import AUTHOR, FORBIDDEN_LIVE_SYMBOLS, SPEC, QNMRefuse

# Raw markers scanned before JSON parse. Case-insensitive.
_POISON_MARKERS = (
    "lumen",
    "mandible",
    "lattice_online",
    "mesh_complete",
    "account_resurrect",
    "account_restore",
    "account_create",
    "controller_hunt",
    "hunt_controller",
    "scorch_remote",
    "anon-broadcast/publish",
    "anon_broadcast_publish",
)

_POISON_RE = re.compile(
    "|".join(re.escape(m) for m in _POISON_MARKERS),
    re.IGNORECASE,
)

MAX_INGRESS_BYTES = 64 * 1024


class APG:
    """Refuse-first ingress gate. Does not interpret poison."""

    def __init__(self) -> None:
        self.refused: list[dict[str, Any]] = []

    def scan_raw(self, raw: bytes | str) -> None:
        if isinstance(raw, str):
            data = raw.encode("utf-8")
        else:
            data = raw
        if len(data) > MAX_INGRESS_BYTES:
            self._refuse("QNM-APG-POISON", "ingress too large")
        text = data.decode("utf-8", errors="replace")
        found = _POISON_RE.search(text)
        if found:
            self._refuse("QNM-APG-POISON", f"marker:{found.group(0).lower()}")

    def admit(self, raw: bytes | str) -> dict[str, Any]:
        """Scan raw, then parse JSON. Poison never reaches the parser path."""
        self.scan_raw(raw)
        if isinstance(raw, bytes):
            text = raw.decode("utf-8")
        else:
            text = raw
        if not text.strip():
            return {}
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            self._refuse("QNM-APG-REFUSE", "malformed")
        if not isinstance(payload, dict):
            self._refuse("QNM-APG-REFUSE", "object required")
        self._refuse_forbidden_values(payload)
        return payload

    def _refuse_forbidden_values(self, payload: dict[str, Any]) -> None:
        for key, value in payload.items():
            if key in FORBIDDEN_LIVE_SYMBOLS or str(value) in FORBIDDEN_LIVE_SYMBOLS:
                self._refuse("QNM-APG-POISON", "forbidden live symbol")
            if key in ("views",) and payload.get("op") == "score":
                self._refuse("QNM-SCORE-NO-VIEWS", "score never reads views")

    def _refuse(self, code: str, detail: str) -> None:
        rec = {
            "ok": False,
            "refused": True,
            "code": code,
            "detail": detail,
            "interpreted": False,
            "spec": SPEC,
            "author": AUTHOR,
        }
        self.refused.append(rec)
        raise QNMRefuse(code, detail)
