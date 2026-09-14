"""Wi-Fi via — NetworkManager / `iw` / sysfs wireless.

LIVE when an 802.11 adapter is present. No invented association.
"""

from __future__ import annotations

from qnsd.vias.base import ABSENT, PRESENT, BaseAdapter, ViaContext, os_phy_emit


class WifiAdapter(BaseAdapter):
    name = "wifi"
    mock = False
    device_hook = "os"
    protocol = "ViaAdapter"

    def presence(self, ctx: ViaContext) -> str:
        return PRESENT if ctx.phy("wifi").get("live") else ABSENT

    def emit(self, photon, ctx: ViaContext):
        return os_phy_emit(self.name, photon, ctx)


ADAPTER = WifiAdapter()
