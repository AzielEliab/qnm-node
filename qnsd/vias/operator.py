"""Operator via — always PRESENT (software). LIVE is an operator act."""

from __future__ import annotations

from qnsd.vias.base import BaseAdapter, PRESENT, ViaContext


class OperatorAdapter(BaseAdapter):
    name = "operator"

    def presence(self, ctx: ViaContext) -> str:
        _ = ctx
        return PRESENT


ADAPTER = OperatorAdapter()
