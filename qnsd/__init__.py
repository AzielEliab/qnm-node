"""QNS-CD-1.0 Quantum Node Signal daemon (local qnsd).

Photon is the packet. QNS is the native medium. Light is camera-flash
OCC. Every send class lives in one program. Restriction walks the next
class. Packet id does not change across hops.

Parents: QNS-WP-1.3 · QNM-BUILD-1.0 · AIH-WP-1.3 · APG · AZPIPE ·
ChainLock. Author: Aziel Eliab only.

Local process. Suite Workers cite/proxy only. Not a Softwares-tab
product. GET /v1/mesh never enables. No Node Gate.
"""

from __future__ import annotations

from qnsd.boot import AUTHOR, SPEC, QNSRefuse
from qnsd.node import STATES, Node
from qnsd.photon import PHOTON_FIELDS, Photon, dumps, loads, photon_id
from qnsd.vias import VIA_ORDER

__version__ = "1.2.0"
__author__ = AUTHOR
__design__ = SPEC
__parents__ = (
    "QNS-WP-1.3",
    "QNM-BUILD-1.0",
    "AIH-WP-1.3",
    "APG",
    "AZPIPE",
    "ChainLock",
)

__all__ = [
    "AUTHOR",
    "PHOTON_FIELDS",
    "SPEC",
    "STATES",
    "VIA_ORDER",
    "Node",
    "Photon",
    "QNSRefuse",
    "dumps",
    "loads",
    "photon_id",
    "__author__",
    "__design__",
    "__parents__",
    "__version__",
]
