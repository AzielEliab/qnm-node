"""PLC via — ABSENT without a declared domain unless fabric-armed.

No invented PLC PHY. Armed presence is not a live power-line packet.
"""

from __future__ import annotations

from typing import Any

from qnsd.vias.base import ABSENT, FAIL, OK, PRESENT, BaseAdapter, ViaContext, ViaResult


class PlcAdapter(BaseAdapter):
    name = "plc"
    mock = False
    device_hook = "none"
    protocol = "software-declare"

    def presence(self, ctx: ViaContext) -> str:
        if ctx.fabric_armed:
            return PRESENT
        rec = ctx.declared_via("plc")
        if rec.get("domain"):
            return PRESENT
        return ABSENT

    def emit(self, photon: dict[str, Any], ctx: ViaContext) -> ViaResult:
        rec = ctx.declared_via("plc")
        if not rec.get("domain"):
            return ViaResult(
                ok=False,
                kind=FAIL,
                via=self.name,
                code="QNS-PLC-UNDECLARED",
                detail="plc armed; domain undeclared; no invented PHY",
                live_link=False,
            )
        return ViaResult(
            ok=True,
            kind=OK,
            via=self.name,
            photon=photon,
            detail="plc emit",
            live_link=False,
        )


ADAPTER = PlcAdapter()
