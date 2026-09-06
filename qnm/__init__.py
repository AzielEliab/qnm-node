"""QNM-BUILD-1.0 Quantum Node Mesh local node.

Companion: AIH-WP-1.1. Author: Aziel Eliab only.

Local process. Radios off. Receipts to disk. Poison refused, not
interpreted. Tamper isolates. PHOENIX-LOCK waits locally. Tethers drop
clean. No account resurrection. AnonBroadcast is never a publish path.
No Lumen/Mandible live symbols. No lattice_online / mesh_complete.
Score never reads views.
"""

from __future__ import annotations

from qnm.apg import APG
from qnm.boot import GENESIS_EMPTY, QNMRefuse, compute_install_root
from qnm.node import STATES, Node
from qnm.score import score_local

__version__ = "1.0.0"
__author__ = "Aziel Eliab"
__spec__ = "QNM-BUILD-1.0"
__companion__ = "AIH-WP-1.1"

__all__ = [
    "APG",
    "GENESIS_EMPTY",
    "Node",
    "QNMRefuse",
    "STATES",
    "compute_install_root",
    "score_local",
    "__author__",
    "__companion__",
    "__spec__",
    "__version__",
]
