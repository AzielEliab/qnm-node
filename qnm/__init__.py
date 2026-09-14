"""QNM-BUILD-1.0 Quantum Node Mesh local node.

Companion pair-bind: AIH-WP-1.3 (medium-independent spiderweb).
Hub / Interface law remains AIH-WP-1.1. Author: Aziel Eliab only.

Local process. Radios off. Receipts to disk. Poison refused, not
interpreted. Tamper isolates. PHOENIX-LOCK waits / re-seals locally
after poison or isolation (not public hostname restore). Split the
wires: tick is presence+tip; payload is receiver-pull. Tethers drop
clean. No account resurrection. AnonBroadcast is never a publish path.
No Lumen/Mandible live symbols. No lattice_online / mesh_complete.
Score never reads views. Pair-id is medium-independent — not Bell-pair
physics, no qubit claims.
"""

from __future__ import annotations

from qnm.apg import APG
from qnm.boot import GENESIS_EMPTY, QNMRefuse, compute_install_root
from qnm.node import STATES, Node
from qnm.pairs import HOP_MAX_DEFAULT, compute_pair_id, handshake_seal
from qnm.score import score_local
from qnm.spiderweb import Spiderweb
from qnm.wires import CITE_SOCKET, DWELL_S, TICK_BYTES, TICK_SOCKET, Wires

__version__ = "1.1.0"
__author__ = "Aziel Eliab"
__spec__ = "QNM-BUILD-1.0"
__companion__ = "AIH-WP-1.3"
__pair_bind__ = "AIH-WP-1.3"
__hub_law__ = "AIH-WP-1.1"

__all__ = [
    "APG",
    "GENESIS_EMPTY",
    "HOP_MAX_DEFAULT",
    "Node",
    "QNMRefuse",
    "STATES",
    "Spiderweb",
    "TICK_BYTES",
    "TICK_SOCKET",
    "CITE_SOCKET",
    "DWELL_S",
    "Wires",
    "compute_install_root",
    "compute_pair_id",
    "handshake_seal",
    "score_local",
    "__author__",
    "__companion__",
    "__hub_law__",
    "__pair_bind__",
    "__spec__",
    "__version__",
]
