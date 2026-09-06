"""PHOENIX-LOCK — QNM-BUILD-1.0 §11.

Waits locally. Does not hunt a controller. Does not open radios.
Arm is an operator act. After arm, the node stays on this machine.
"""

from __future__ import annotations

from typing import Any

from qnm.boot import AUTHOR, SPEC, QNMRefuse


class Phoenix:
    def __init__(self) -> None:
        self.armed = False
        self.waiting_local = False
        self.controller_hunt = False

    def arm(self) -> dict[str, Any]:
        self.armed = True
        self.waiting_local = True
        self.controller_hunt = False
        return self.status()

    def hunt_controller(self) -> None:
        raise QNMRefuse(
            "QNM-PHOENIX-LOCAL-WAIT",
            "PHOENIX-LOCK waits locally; no controller hunt",
        )

    def status(self) -> dict[str, Any]:
        return {
            "ok": True,
            "armed": self.armed,
            "waiting": "local" if self.waiting_local else "off",
            "controller_hunt": False,
            "spec": SPEC,
            "author": AUTHOR,
        }
