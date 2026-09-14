"""RF via — cellular LTE/5G via ModemManager (`mmcli`).

LIVE when a modem+SIM is present. ABSENT otherwise. Emit without a
modem is RADIO-NO-MODEM. Fabric enable does not invent a tower.
"""

from __future__ import annotations

from qnsd.vias.base import ABSENT, PRESENT, BaseAdapter, ViaContext, os_phy_emit


class RfAdapter(BaseAdapter):
    name = "rf"
    mock = False
    device_hook = "os"
    protocol = "ViaAdapter"

    def presence(self, ctx: ViaContext) -> str:
        return PRESENT if ctx.phy("rf").get("live") else ABSENT

    def emit(self, photon, ctx: ViaContext):
        return os_phy_emit(self.name, photon, ctx)


ADAPTER = RfAdapter()
