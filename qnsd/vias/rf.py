"""RF via — ABSENT without a declared profile unless fabric-armed.

Device hook is MOCK until a fielded PHY binds. No invented live RF mesh.
"""

from __future__ import annotations

from qnsd.vias.base import ABSENT, MOCK, PRESENT, BaseAdapter, ViaContext


class RfAdapter(BaseAdapter):
    name = "rf"
    mock = True
    device_hook = MOCK
    protocol = "ViaAdapter"

    def presence(self, ctx: ViaContext) -> str:
        if ctx.fabric_armed:
            return PRESENT
        rec = ctx.declared_via("rf")
        if rec.get("profile"):
            return PRESENT
        return ABSENT


ADAPTER = RfAdapter()
