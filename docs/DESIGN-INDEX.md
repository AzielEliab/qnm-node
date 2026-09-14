# Fabric design papers

Author: **Aziel Eliab** only.

Companion to `QNM-BUILD-1.0.md` and `AIH-WP-1.3.md`.

| Paper | One line |
| --- | --- |
| [QNM-WP-1.0](./QNM-WP-1.0.md) | Quantum Node Mesh — local ON / public rollup dies with pull; cell 25 + 2 bridges |
| [NODE-OPS-1.0](./NODE-OPS-1.0.md) | Node operations + surface law + phoenix wait / re-seal (not public hostname restore) |
| [QNS-CD-1.0](./QNS-CD-1.0.md) | Quantum Node Signal Coding Design — local `qnsd` owns vias; photon packet |
| [SPLIT-WIRES-1.0](./SPLIT-WIRES-1.0.md) | Tick plane = presence + tip hash; payload is pull-only; two clocks stay strangers |
| [COLD-COPY-1.0](./COLD-COPY-1.0.md) | N named cold replicas; no live body sync; public pull does not erase copies |
| [RE-EXPAND-1.0](./RE-EXPAND-1.0.md) | Archive bytes, not summaries; verify + new local node on tip |
| [REHEAL-1.0](./REHEAL-1.0.md) | Own last good tip + trusted pull, or phoenix-WAIT; no neighbor / majority reheal |
| [CROSS-NETWORK-SURVIVAL-1.0](./CROSS-NETWORK-SURVIVAL-1.0.md) | If network + live data die, chain survives (cold copy / re-expand / self-reheal) |
| [NO-LIE-1.0](./NO-LIE-1.0.md) | Network never lies, even to stay alive / adapt / prevent death; receipts still hash; verify without voice |
| [NO-REWRITE-1.0](./NO-REWRITE-1.0.md) | No rewrite key; published tip immutable; copies not all on one tunnel |
| [FABRIC-MESH-PIPELINE-1.0](./FABRIC-MESH-PIPELINE-1.0.md) | Local ingress → APG → stranger clocks → via walker → photon → outbox → survival; ALL-CHANNELS-ON when fabric-enabled; internal bitmesh geo; pissed-off-gov unkillability 80+; MirageGrid Node Gate is an external claim stranger |

QNM-WP-1.0 absorbs BUILD+TOPO: local process ON, public rollup OFF and
dies with the pull; GET /v1/mesh never enables. Phoenix is wait /
re-seal after poison or isolation — not restore of a public hostname.

QNS-CD-1.0 is the coding design for the local `qnsd` process (parents:
QNS-WP-1.3 · QNM-BUILD-1.0 · AIH-WP-1.3 · APG · AZPIPE · ChainLock).
Local qnsd owns vias. Suite Workers cite/proxy only. Not a
Softwares-tab product. GET /v1/mesh never enables. No Node Gate
in qnm-node. Node Gate is a MirageGrid subsystem only (outward claim
surface; AZ Generator is not called from this repo).
Print companion: `QNS-CD-1.0.pdf` (git-hosted; Worker does not serve).

FABRIC-MESH-PIPELINE-1.0 locks the local order (APG → wires → vias →
photon → outbox → phoenix / reheal / cold-copy). MirageGrid claim
clock is an external stranger to qnm tip and dwell clocks. When
fabric-enabled, RF / BT / Wi-Fi / photon arm ON. Physical Bluetooth /
RF / Wi-Fi / camera hooks stay HOOK-PENDING until a PHY binds. Public
receipts stay no user/geo.
