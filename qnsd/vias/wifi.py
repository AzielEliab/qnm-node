"""Wi-Fi via — software path may be ON. Device hook is MOCK until a PHY binds.

Protocol-complete ViaAdapter. No invented 802.11 success. Channels-ON
is not a fielded radio.
"""

from __future__ import annotations

from qnsd.vias.base import ABSENT, MOCK, PRESENT, BaseAdapter, ViaContext


class WifiAdapter(BaseAdapter):
    name = "wifi"
    mock = True
    device_hook = MOCK
    protocol = "ViaAdapter"

    def presence(self, ctx: ViaContext) -> str:
        if ctx.fabric_armed:
            return PRESENT
        rec = ctx.declared_via("wifi")
        if rec.get("link") or rec.get("ssid") or rec:
            return PRESENT
        return ABSENT


ADAPTER = WifiAdapter()
