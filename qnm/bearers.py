"""Bearers — QNM-BUILD-1.0 §6.

local = on. All other bearers default off. Radios stay off. LIVE
requires an explicit operator bearer. Site ping is not a bearer.
"""

from __future__ import annotations

from typing import Any

from qnm.boot import AUTHOR, SPEC, QNMRefuse

LOCAL_ON = "local"
OPERATOR = "operator"
DEFAULT_OFF = ("operator", "lan", "radio", "remote")


class Bearers:
    def __init__(self) -> None:
        self._on: dict[str, bool] = {LOCAL_ON: True}
        for name in DEFAULT_OFF:
            self._on[name] = False

    def snapshot(self) -> dict[str, bool]:
        return dict(self._on)

    def is_on(self, name: str) -> bool:
        return bool(self._on.get(name, False))

    def set(self, name: str, on: bool) -> dict[str, Any]:
        if name in ("Lumen", "Mandible", "lumen", "mandible"):
            raise QNMRefuse("QNM-APG-POISON", "no Lumen/Mandible live symbols")
        if name == "radio" and on:
            raise QNMRefuse("QNM-RADIO-OFF", "radios stay off")
        if name == "remote" and on:
            raise QNMRefuse("QNM-BEARER-OFF", "remote bearer default off")
        if name not in self._on:
            raise QNMRefuse("QNM-BEARER-OFF", f"unknown bearer:{name}")
        if name == LOCAL_ON and not on:
            raise QNMRefuse("QNM-BEARER-OFF", "local bearer stays on")
        self._on[name] = bool(on)
        return {
            "ok": True,
            "bearer": name,
            "on": self._on[name],
            "bearers": self.snapshot(),
            "spec": SPEC,
            "author": AUTHOR,
        }

    def drop_all_except_local(self) -> None:
        for name in list(self._on):
            if name != LOCAL_ON:
                self._on[name] = False
