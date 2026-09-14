"""Bluetooth via — software mock. Protocol-complete; no OS radio."""

from __future__ import annotations

from qnsd.vias.base import BaseAdapter, PRESENT, ViaContext


class BtAdapter(BaseAdapter):
    name = "bt"
    mock = True
    device_hook = "mock"

    def presence(self, ctx: ViaContext) -> str:
        _ = ctx
        return PRESENT


ADAPTER = BtAdapter()
