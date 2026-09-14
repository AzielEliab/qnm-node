"""Send classes — QNS-CD-1.0.

VIA_ORDER = lan, wifi, plc, bt, rf, light, qns, operator, local.
local + qns + operator are always PRESENT (software).
rf / plc / light / wifi need declare unless fabric-armed.
Fabric enable allows the software path (Channels-ON). Soft RF / BT /
Wi-Fi / photon / bitmesh stay **MOCK** until real PHY is fielded.
Invented live-link success is refused (`QNS-HOOK-PENDING`).
"""

from __future__ import annotations

from qnsd.vias import bt, lan, light, local, operator, plc, qns, rf, wifi
from qnsd.vias.base import (
    ALWAYS_PRESENT,
    CHANNELS_ON,
    CHANNELS_ON_MEANS,
    DECLARE_REQUIRED,
    HOOK_PENDING,
    MOCK,
    PHYSICAL_HOOK,
    SOFT_RADIO_CHANNELS,
    VIA_ORDER,
    ViaAdapter,
    ViaContext,
    ViaResult,
    channel_honesty,
    physical_via_stamps,
    radios_stamp,
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
    "CHANNELS_ON_MEANS",
    "DECLARE_REQUIRED",
    "HOOK_PENDING",
    "MOCK",
    "LanAdapter",
    "LightAdapter",
    "LocalAdapter",
    "OperatorAdapter",
    "PHYSICAL_HOOK",
    "PlcAdapter",
    "QnsAdapter",
    "RfAdapter",
    "SOFT_RADIO_CHANNELS",
    "VIA_ORDER",
    "ViaAdapter",
    "ViaContext",
    "ViaResult",
    "WifiAdapter",
    "channel_honesty",
    "physical_via_stamps",
    "radios_stamp",
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
