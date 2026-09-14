"""Send classes — QNS-CD-1.0.

VIA_ORDER = lan, wifi, plc, bt, rf, light, qns, operator, local.
local + qns + operator are always PRESENT (software).
rf / plc / light / wifi need declare unless fabric-armed.
Fabric enable arms RF / BT / Wi-Fi / photon. PHY without a driver
is HOOK-PENDING — not invented live-link success.
"""

from __future__ import annotations

from qnsd.vias import bt, lan, light, local, operator, plc, qns, rf, wifi
from qnsd.vias.base import (
    ALWAYS_PRESENT,
    CHANNELS_ON,
    DECLARE_REQUIRED,
    HOOK_PENDING,
    PHYSICAL_HOOK,
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
from qnsd.vias.wifi import WifiAdapter

ADAPTERS: dict[str, ViaAdapter] = {
    "lan": lan.ADAPTER,
    "wifi": wifi.ADAPTER,
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
    "CHANNELS_ON",
    "DECLARE_REQUIRED",
    "HOOK_PENDING",
    "LanAdapter",
    "LightAdapter",
    "LocalAdapter",
    "OperatorAdapter",
    "PHYSICAL_HOOK",
    "PlcAdapter",
    "QnsAdapter",
    "RfAdapter",
    "VIA_ORDER",
    "ViaAdapter",
    "ViaContext",
    "ViaResult",
    "WifiAdapter",
    "bt",
    "lan",
    "light",
    "local",
    "operator",
    "plc",
    "qns",
    "rf",
    "wifi",
]
