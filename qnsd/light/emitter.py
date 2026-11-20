"""Flash emitter hook — QNS-CD-1.0.

The bytes that leave this hook are the shared sealed photon frame,
carried on simulated hardware. This process does not open a LED.
``live`` and ``real_hardware`` stay false.
"""

from __future__ import annotations

from typing import Any

from qnsd.light.carrier import SimulatedHardware


class Emitter:
    def __init__(self) -> None:
        self.link = SimulatedHardware()
        self.flashes: list[bytes] = []
        self.mock = False
        self.real_hardware = False
        self.live = False

    def carry(self, payload: bytes) -> dict[str, Any]:
        result = self.link.transmit(payload)
        self.flashes.append(bytes(payload))
        return result

    def flash(self, bits: bytes) -> dict[str, Any]:
        """Record a codec buffer. The carrier result is still simulated."""
        self.flashes.append(bytes(bits))
        return {
            "ok": True,
            "mock": False,
            "live": False,
            "real_hardware": False,
            "hardware": "simulated",
            "fielded": False,
            "count": len(self.flashes),
        }
