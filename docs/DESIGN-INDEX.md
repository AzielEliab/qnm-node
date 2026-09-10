# Fabric design papers

Author: **Aziel Eliab** only.

Companion to `QNM-BUILD-1.0.md` and `AIH-WP-1.3.md`.

| Paper | One line |
| --- | --- |
| [QNM-WP-1.0](./QNM-WP-1.0.md) | Quantum Node Mesh — local ON / public rollup OFF; cell 25 + 2 bridges |
| [NODE-OPS-1.0](./NODE-OPS-1.0.md) | Node operations + surface law + phoenix loop |
| [QNS-CD-1.0](./QNS-CD-1.0.md) | Quantum Node Signal Coding Design — local `qnsd` owns vias; photon packet |

QNM-WP-1.0 absorbs BUILD+TOPO: local process ON, public rollup OFF; GET /v1/mesh never enables.

QNS-CD-1.0 is the coding design for the local `qnsd` process (parents:
QNS-WP-1.3 · QNM-BUILD-1.0 · AIH-WP-1.3 · APG · AZPIPE · ChainLock).
Local qnsd owns vias. Suite Workers cite/proxy only. Not a
Softwares-tab product. GET /v1/mesh never enables. No Node Gate.
Print companion: `QNS-CD-1.0.pdf` (git-hosted; Worker does not serve).
