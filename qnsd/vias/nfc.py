"""NFC via — libnfc / PCSC. LIVE when a reader is present. No invented tap."""

from __future__ import annotations

from typing import Any

from qnsd.vias.base import ABSENT, PRESENT, BaseAdapter, ViaContext, ViaResult, os_phy_emit


class NfcAdapter(BaseAdapter):
    name = "nfc"
    mock = False
    device_hook = "os"
    protocol = "ViaAdapter"

    def presence(self, ctx: ViaContext) -> str:
        return PRESENT if ctx.phy("nfc").get("live") else ABSENT

    def emit(self, photon: dict[str, Any], ctx: ViaContext) -> ViaResult:
        return os_phy_emit(self.name, photon, ctx)


ADAPTER = NfcAdapter()
