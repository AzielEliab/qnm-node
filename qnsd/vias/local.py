"""Local via — always PRESENT (software / loopback)."""

from __future__ import annotations

from qnsd.vias.base import BaseAdapter, PRESENT, ViaContext


class LocalAdapter(BaseAdapter):
    name = "local"

    def presence(self, ctx: ViaContext) -> str:
        _ = ctx
        return PRESENT


ADAPTER = LocalAdapter()
