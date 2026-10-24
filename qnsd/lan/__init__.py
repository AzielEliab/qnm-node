"""Authenticated LAN transport. Importing this package does not bind a socket.

The adapter does not report LIVE. Loopback is not a cross-host proof.
"""

from qnsd.lan.contract import ADAPTER_ID, LAN_V, PACKET_V
from qnsd.lan.node import LanNode, LanTLSAdapter

__all__ = ["ADAPTER_ID", "LAN_V", "PACKET_V", "LanNode", "LanTLSAdapter"]
