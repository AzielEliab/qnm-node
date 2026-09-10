"""QNS native medium — always PRESENT (software)."""

from __future__ import annotations

from qnsd.vias.base import BaseAdapter, PRESENT, ViaContext


class QnsAdapter(BaseAdapter):
    name = "qns"

    def presence(self, ctx: ViaContext) -> str:
        _ = ctx
        return PRESENT


ADAPTER = QnsAdapter()
