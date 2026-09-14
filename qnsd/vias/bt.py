"""Bluetooth via — BlueZ (`bluetoothctl`) / sysfs.

LIVE when an adapter is present. No invented pairing.
"""

from __future__ import annotations

from qnsd.vias.base import ABSENT, PRESENT, BaseAdapter, ViaContext, os_phy_emit


class BtAdapter(BaseAdapter):
    name = "bt"
    mock = False
    device_hook = "os"
    protocol = "ViaAdapter"

    def presence(self, ctx: ViaContext) -> str:
        return PRESENT if ctx.phy("bt").get("live") else ABSENT

    def emit(self, photon, ctx: ViaContext):
        return os_phy_emit(self.name, photon, ctx)


ADAPTER = BtAdapter()
