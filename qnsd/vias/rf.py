"""RF via — ABSENT without a declared profile. Device hook is mock."""

from __future__ import annotations

from qnsd.vias.base import ABSENT, PRESENT, BaseAdapter, ViaContext


class RfAdapter(BaseAdapter):
    name = "rf"

    def presence(self, ctx: ViaContext) -> str:
        rec = ctx.declared_via("rf")
        if rec.get("profile"):
            return PRESENT
        return ABSENT


ADAPTER = RfAdapter()
