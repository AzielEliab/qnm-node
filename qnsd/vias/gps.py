"""GNSS via — gpsd / NMEA receive-only.

LIVE when a receiver reports a 2D/3D fix. Transmit is RADIO-GNSS-RX-ONLY.
Not a GIS truth engine.
"""

from __future__ import annotations

from typing import Any

from qnsd.vias.base import (
    ABSENT,
    FIELDING_ABSENT,
    FIELDING_LIVE,
    OK,
    PRESENT,
    REFUSED,
    BaseAdapter,
    ViaContext,
    ViaResult,
    os_phy_emit,
)


class GpsAdapter(BaseAdapter):
    name = "gps"
    mock = False
    device_hook = "os"
    protocol = "ViaAdapter"

    def presence(self, ctx: ViaContext) -> str:
        return PRESENT if ctx.phy("gps").get("live") else ABSENT

    def emit(self, photon: dict[str, Any], ctx: ViaContext) -> ViaResult:
        return os_phy_emit(self.name, photon, ctx)

    def admit(self, raw: bytes, ctx: ViaContext) -> ViaResult:
        probe = ctx.phy("gps")
        if not probe.get("live"):
            return ViaResult(
                ok=False,
                kind=REFUSED,
                via=self.name,
                absent=True,
                status=FIELDING_ABSENT,
                code="RADIO-NO-GNSS",
                detail="gpsd/NMEA receiver not present",
            )
        extra: dict[str, Any] = {"raw_len": len(raw), "via": self.name}
        if probe.get("fix"):
            extra["fix"] = probe["fix"]
        return ViaResult(
            ok=True,
            kind=OK,
            via=self.name,
            detail="GNSS receive-only admit",
            live_link=True,
            status=FIELDING_LIVE,
            photon=extra,
        )


ADAPTER = GpsAdapter()
