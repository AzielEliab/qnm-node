"""QNM-BUILD-1.0 Quantum Node Mesh local node.

Companion pair-bind: AIH-WP-1.3 (medium-independent spiderweb).
Hub / Interface law remains AIH-WP-1.1. Author: Aziel Eliab only.

Local process. Radios off. Receipts to disk. Poison refused, not
interpreted. Tamper isolates. PHOENIX-LOCK waits / re-seals locally
after poison or isolation (not public hostname restore). Tethers drop
clean. No account resurrection. AnonBroadcast is never a publish path.
No Lumen/Mandible live symbols. No lattice_online / mesh_complete.
Score never reads views. Pair-id is medium-independent — not Bell-pair
physics, no qubit claims. Split the wires: tick plane is presence +
tip hash only; payloads are pull-only. Cold copies survive a public
pull. Re-expand is archive verify plus a new local node on tip.
Reheal is own last good tip, or phoenix-WAIT — not neighbor chatter.
If the public network and live data die, the chain still survives
(cold copies / archive re-expand / self-reheal). Public tunnels and
sites die with the pull.
"""

from __future__ import annotations

from qnm.apg import APG
from qnm.archive import ChainArchive
from qnm.boot import GENESIS_EMPTY, QNMRefuse, compute_install_root
from qnm.coldcopy import ColdCopy
from qnm.node import STATES, Node
from qnm.pairs import HOP_MAX_DEFAULT, compute_pair_id, handshake_seal
from qnm.score import score_local
from qnm.spiderweb import Spiderweb
from qnm.wires import Wires

__version__ = "1.1.0"
__author__ = "Aziel Eliab"
__spec__ = "QNM-BUILD-1.0"
__companion__ = "AIH-WP-1.3"
__wires__ = "SPLIT-WIRES-1.0"
__coldcopy__ = "COLD-COPY-1.0"
__archive__ = "RE-EXPAND-1.0"
__reheal__ = "REHEAL-1.0"
__survival__ = "CROSS-NETWORK-SURVIVAL-1.0"
__pair_bind__ = "AIH-WP-1.3"
__hub_law__ = "AIH-WP-1.1"

__all__ = [
    "APG",
    "ChainArchive",
    "ColdCopy",
    "GENESIS_EMPTY",
    "HOP_MAX_DEFAULT",
    "Node",
    "QNMRefuse",
    "STATES",
    "Spiderweb",
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
