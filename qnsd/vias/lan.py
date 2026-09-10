"""LAN via — software present. Emit fails without a declared link."""

from __future__ import annotations

from typing import Any

from qnsd.vias.base import (
    ABSENT,
    FAIL,
    OK,
    PRESENT,
    BaseAdapter,
    ViaContext,
    ViaResult,
)


class LanAdapter(BaseAdapter):
    name = "lan"

    def presence(self, ctx: ViaContext) -> str:
        _ = ctx
        return PRESENT

    def emit(self, photon: dict[str, Any], ctx: ViaContext) -> ViaResult:
        rec = ctx.declared_via("lan")
        linked = bool(ctx.lan_link or rec.get("link"))
        if not linked:
            return ViaResult(
                ok=False,
                kind=FAIL,
                via=self.name,
                code="QNS-LAN-FAIL",
                detail="lan link down",
            )
        return ViaResult(ok=True, kind=OK, via=self.name, photon=photon, detail="lan emit")


ADAPTER = LanAdapter()
