"""Bluetooth via — protocol-complete; no OS radio.

Fabric-armed posture is ON. Emit without a real driver is HOOK-PENDING.
Do not claim a live BT packet flew.
"""

from __future__ import annotations

from qnsd.vias.base import PRESENT, BaseAdapter, ViaContext


class BtAdapter(BaseAdapter):
    name = "bt"
    mock = True
    device_hook = "HOOK-PENDING"
    protocol = "ViaAdapter"

    def presence(self, ctx: ViaContext) -> str:
        _ = ctx
        return PRESENT


ADAPTER = BtAdapter()
