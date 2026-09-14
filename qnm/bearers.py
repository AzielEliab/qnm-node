"""Bearers — QNM-BUILD-1.0 §6 + FABRIC-MESH-PIPELINE ALL-CHANNELS-ON.

local = on. Remote stays off. LIVE requires an explicit operator bearer.
Site ping is not a bearer.

When fabric is enabled, RF / BT / Wi-Fi / lan arm ON. That is armed
posture, not a live-packet claim. Radio enable without fabric still
refuses (`QNM-RADIO-OFF`). GET /v1/mesh never enables these bearers.
"""

from __future__ import annotations

from typing import Any

from qnm.boot import AUTHOR, SPEC, QNMRefuse

LOCAL_ON = "local"
OPERATOR = "operator"
DEFAULT_OFF = ("operator", "lan", "radio", "remote", "wifi", "bt")
FABRIC_ARM = ("lan", "radio", "wifi", "bt")


class Bearers:
    def __init__(self) -> None:
        self.fabric_armed = False
        self._on: dict[str, bool] = {LOCAL_ON: True}
        for name in DEFAULT_OFF:
            self._on[name] = False

    def snapshot(self) -> dict[str, bool]:
        return dict(self._on)

    def is_on(self, name: str) -> bool:
        return bool(self._on.get(name, False))

    def arm_fabric(self) -> dict[str, Any]:
        """Arm RF / BT / Wi-Fi / lan. Not a live PHY claim."""
        self.fabric_armed = True
        for name in FABRIC_ARM:
            self._on[name] = True
        return {
            "ok": True,
            "armed": True,
            "bearers": self.snapshot(),
            "live_rf_mesh": False,
            "spec": SPEC,
            "author": AUTHOR,
        }

    def set(self, name: str, on: bool) -> dict[str, Any]:
        if name in ("Lumen", "Mandible", "lumen", "mandible"):
            raise QNMRefuse("QNM-APG-POISON", "no Lumen/Mandible live symbols")
        if name == "radio" and on and not self.fabric_armed:
            raise QNMRefuse("QNM-RADIO-OFF", "radios stay off until fabric enable")
        if name in ("wifi", "bt") and on and not self.fabric_armed:
            raise QNMRefuse("QNM-RADIO-OFF", "radios stay off until fabric enable")
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
            "armed": self.fabric_armed and name in FABRIC_ARM and on,
            "live_link": False,
            "bearers": self.snapshot(),
            "spec": SPEC,
            "author": AUTHOR,
        }

    def drop_all_except_local(self) -> None:
        for name in list(self._on):
            if name != LOCAL_ON:
                self._on[name] = False
