"""Send classes — QNS-CD-1.0.

VIA_ORDER = lan, plc, bt, rf, light, qns, operator, local.
local + qns + operator are always PRESENT (software).
rf / plc / light need declare.
"""

from __future__ import annotations

from qnsd.vias import bt, lan, light, local, operator, plc, qns, rf
from qnsd.vias.base import (
    ALWAYS_PRESENT,
    DECLARE_REQUIRED,
    VIA_ORDER,
    ViaAdapter,
    ViaContext,
    ViaResult,
)
from qnsd.vias.bt import BtAdapter
from qnsd.vias.lan import LanAdapter
from qnsd.vias.light import LightAdapter
from qnsd.vias.local import LocalAdapter
from qnsd.vias.operator import OperatorAdapter
from qnsd.vias.plc import PlcAdapter
from qnsd.vias.qns import QnsAdapter
from qnsd.vias.rf import RfAdapter

ADAPTERS: dict[str, ViaAdapter] = {
    "lan": lan.ADAPTER,
    "plc": plc.ADAPTER,
    "bt": bt.ADAPTER,
    "rf": rf.ADAPTER,
    "light": light.ADAPTER,
    "qns": qns.ADAPTER,
    "operator": operator.ADAPTER,
    "local": local.ADAPTER,
}

__all__ = [
    "ADAPTERS",
    "ALWAYS_PRESENT",
    "BtAdapter",
    "DECLARE_REQUIRED",
    "LanAdapter",
    "LightAdapter",
    "LocalAdapter",
    "OperatorAdapter",
    "PlcAdapter",
    "QnsAdapter",
    "RfAdapter",
    "VIA_ORDER",
    "ViaAdapter",
    "ViaContext",
    "ViaResult",
    "bt",
    "lan",
    "light",
    "local",
    "operator",
    "plc",
    "qns",
    "rf",
]
