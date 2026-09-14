"""Wi-Fi via — fabric-armed ON. Device hook is HOOK-PENDING until a PHY binds.

Protocol-complete ViaAdapter. No invented 802.11 success.
"""

from __future__ import annotations

from qnsd.vias.base import ABSENT, PRESENT, BaseAdapter, ViaContext


class WifiAdapter(BaseAdapter):
    name = "wifi"
    mock = True
    device_hook = "HOOK-PENDING"
    protocol = "ViaAdapter"

    def presence(self, ctx: ViaContext) -> str:
        if ctx.fabric_armed:
            return PRESENT
        rec = ctx.declared_via("wifi")
        if rec.get("link") or rec.get("ssid") or rec:
            return PRESENT
        return ABSENT


ADAPTER = WifiAdapter()
