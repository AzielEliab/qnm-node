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
(cold copies / archive re-expand / self-reheal). The network never
lies, even to stay alive, adapt, or prevent death. No rewrite key.
Published tip cannot be rewritten or mutated. Receipts still hash.
Verify is without voice. Copies are not all on one tunnel.
Public tunnels and sites die with the pull.
"""

from __future__ import annotations

from qnm.apg import APG
from qnm.archive import ChainArchive
from qnm.boot import GENESIS_EMPTY, QNMRefuse, compute_install_root
from qnm.bitmesh import BITMESH_SPEC, Bitmesh
from qnm.coldcopy import ColdCopy
from qnm.fabric import FABRIC_SPEC, Fabric
from qnm.node import STATES, Node
from qnm.pairs import HOP_MAX_DEFAULT, compute_pair_id, handshake_seal
from qnm.score import score_local
from qnm.planes import PLANES_SPEC, Planes
from qnm.unkillability import TARGET as UNKILL_TARGET
from qnm.unkillability import FIELDED_BAND, UNKILL_SPEC, compute_unkillability
from qnm.spiderweb import Spiderweb
from qnm.nolie import NoLie
from qnm.wires import Wires
from qnm.surface import SURFACE_SPEC, attack_surface_map, redline_checklist
from qnm.fold import FOLD_SPEC, fold_sensitive, foldlock_cite
from qnm.shelf import SHELF_SPEC, encrypt_pack, export_tip

__version__ = "1.6.0"
__author__ = "Aziel Eliab"
__spec__ = "QNM-BUILD-1.0"
__companion__ = "AIH-WP-1.3"
__wires__ = "SPLIT-WIRES-1.0"
__coldcopy__ = "COLD-COPY-1.0"
__archive__ = "RE-EXPAND-1.0"
__reheal__ = "REHEAL-1.0"
__survival__ = "CROSS-NETWORK-SURVIVAL-1.0"
__nolie__ = "NO-LIE-1.0"
__norewrite__ = "NO-REWRITE-1.0"
__fabric__ = FABRIC_SPEC
__bitmesh__ = BITMESH_SPEC
__unkill__ = UNKILL_SPEC
__planes__ = PLANES_SPEC
__pair_bind__ = "AIH-WP-1.3"
__hub_law__ = "AIH-WP-1.1"

__all__ = [
    "APG",
    "BITMESH_SPEC",
    "Bitmesh",
    "ChainArchive",
    "ColdCopy",
    "FABRIC_SPEC",
    "Fabric",
    "GENESIS_EMPTY",
    "HOP_MAX_DEFAULT",
    "NoLie",
    "Node",
    "PLANES_SPEC",
    "Planes",
    "QNMRefuse",
    "STATES",
    "Spiderweb",
    "FIELDED_BAND",
    "UNKILL_SPEC",
    "UNKILL_TARGET",
    "Wires",
    "compute_unkillability",
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
