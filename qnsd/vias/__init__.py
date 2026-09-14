"""Send classes — QNS-CD-1.0.

VIA_ORDER = lan, wifi, plc, bt, rf, gps, nfc, light, qns, operator, local.
local + qns + operator are always PRESENT (software).
Cellular / Wi-Fi / BT / GNSS / NFC are LIVE OS bindings or ABSENT.
Emit without hardware is REFUSED. Fabric enable does not invent PRESENT.
Light camera/emitter stays HOOK-PENDING (not an OS radio PHY).
"""

from __future__ import annotations

from qnsd.vias import bt, gps, lan, light, local, nfc, operator, plc, qns, rf, wifi
from qnsd.vias.base import (
    ALWAYS_PRESENT,
    CHANNELS_ON,
    CHANNELS_ON_MEANS,
    DECLARE_REQUIRED,
    FIELDING_ABSENT,
    FIELDING_HOOK,
    FIELDING_LIVE,
    FIELDING_OFF,
    FIELDING_REAL,
    FIELDING_REFUSED,
    HOOK_PENDING,
    MOCK,
    OS_PHY,
    PHYSICAL_HOOK,
    REFUSED,
    SOFT_RADIO_CHANNELS,
    SOFTWARE_DECLARE,
    VIA_ORDER,
    ViaAdapter,
    ViaContext,
    ViaResult,
    audit_channels,
    channel_fielding,
    channel_honesty,
    physical_via_stamps,
    radios_stamp,
)
from qnsd.vias.bt import BtAdapter
from qnsd.vias.gps import GpsAdapter
from qnsd.vias.lan import LanAdapter
from qnsd.vias.light import LightAdapter
from qnsd.vias.local import LocalAdapter
from qnsd.vias.nfc import NfcAdapter
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
    "gps": gps.ADAPTER,
    "nfc": nfc.ADAPTER,
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
    "FIELDING_ABSENT",
    "FIELDING_HOOK",
    "FIELDING_LIVE",
    "FIELDING_OFF",
    "FIELDING_REAL",
    "FIELDING_REFUSED",
    "GpsAdapter",
    "HOOK_PENDING",
    "MOCK",
    "NfcAdapter",
    "OS_PHY",
    "LanAdapter",
    "LightAdapter",
    "LocalAdapter",
    "OperatorAdapter",
    "PHYSICAL_HOOK",
    "PlcAdapter",
    "QnsAdapter",
    "REFUSED",
    "RfAdapter",
    "SOFT_RADIO_CHANNELS",
    "SOFTWARE_DECLARE",
    "VIA_ORDER",
    "ViaAdapter",
    "ViaContext",
    "ViaResult",
    "WifiAdapter",
    "audit_channels",
    "channel_fielding",
    "channel_honesty",
    "physical_via_stamps",
    "radios_stamp",
    "bt",
    "gps",
    "lan",
    "light",
    "local",
    "nfc",
    "operator",
    "plc",
    "qns",
    "rf",
    "wifi",
]
