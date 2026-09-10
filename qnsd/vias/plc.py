"""PLC via — ABSENT without a declared domain."""

from __future__ import annotations

from qnsd.vias.base import ABSENT, PRESENT, BaseAdapter, ViaContext


class PlcAdapter(BaseAdapter):
    name = "plc"

    def presence(self, ctx: ViaContext) -> str:
        rec = ctx.declared_via("plc")
        if rec.get("domain"):
            return PRESENT
        return ABSENT


ADAPTER = PlcAdapter()
