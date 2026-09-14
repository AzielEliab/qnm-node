"""Bluetooth via — software MOCK. Protocol-complete; no OS radio.

Channels-ON allows the software path. Emit without a fielded PHY is
HOOK-PENDING refuse. Do not claim a live BT packet flew.
"""

from __future__ import annotations

from qnsd.vias.base import MOCK, PRESENT, BaseAdapter, ViaContext


class BtAdapter(BaseAdapter):
    name = "bt"
    mock = True
    device_hook = MOCK
    protocol = "ViaAdapter"

    def presence(self, ctx: ViaContext) -> str:
        _ = ctx
        return PRESENT


ADAPTER = BtAdapter()
