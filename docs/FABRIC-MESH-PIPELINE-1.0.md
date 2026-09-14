# FABRIC-MESH-PIPELINE-1.0

**Author:** Aziel Eliab only
**Parents:** [QNM-BUILD-1.0](QNM-BUILD-1.0.md) · [QNS-CD-1.0](QNS-CD-1.0.md) · [AIH-WP-1.3](AIH-WP-1.3.md) · [SPLIT-WIRES-1.0](SPLIT-WIRES-1.0.md) · [COLD-COPY-1.0](COLD-COPY-1.0.md) · [RE-EXPAND-1.0](RE-EXPAND-1.0.md) · [REHEAL-1.0](REHEAL-1.0.md) · [CROSS-NETWORK-SURVIVAL-1.0](CROSS-NETWORK-SURVIVAL-1.0.md) · [NO-LIE-1.0](NO-LIE-1.0.md) · [NO-REWRITE-1.0](NO-REWRITE-1.0.md) · [QNM-WP-1.0](QNM-WP-1.0.md) · [NODE-OPS-1.0](NODE-OPS-1.0.md)
**License:** Apache-2.0
**Date:** September 2026
**Software:** qnm-node 1.3.0 · local `qnm` + sibling `qnsd`

Public identity is **Aziel Eliab** only.

This paper locks the **local fabric mesh pipeline**. It does not invent
a live RF mesh, a public hostname restore, or a call into AZ Generator.

**Operator override (ALL-CHANNELS-ON).** When the node is
**fabric-enabled**, the **software path** allows RF, Bluetooth,
Wi-Fi, photon flashes (QNS1 light), plus lan / plc / operator /
local. Channels-ON is not fielded radios. A PHY without fielded
hardware stays a protocol-complete adapter stamped **MOCK** — never
an invented live-link success. Photon / QNS1 **codec** stays REAL
where already real; the photon **channel** is MOCK. Bitmesh is an
internal software plane, also MOCK as a radio. `GET /v1/mesh` on
public Workers still never enables suite radios. This is **local
qnm-node fabric**.

## Sentence

Ingress is scanned, then refused or admitted. Tip clock, dwell clock,
and MirageGrid claim clock stay strangers. Restriction walks the via
order. Photon is the packet. Outbox waits; it does not lie. Survival
is own last good tip, trusted pull, cold copy, archive re-expand, or
phoenix-WAIT.

## What this is

A **127.0.0.1** process path. Unarmed, radios stay **OFF**
(`QNM-RADIO-OFF` until fabric enable). **Fabric enable** allows the
RF / BT / Wi-Fi / photon software path. Soft radios stay **MOCK**.
`GET /v1/mesh` never enables. There is **no Node Gate
in qnm-node**. This is **not** a Softwares-tab product.

Photon is the packet (`QNS1` ver 1.3). Light is camera-flash OCC of
that same photon — not a second network. An internal **bitmesh**
plane may bind a geohash to a tip for routing only. Public receipts
stay **no user / no geo** (not ACT-RECEIPT geo).

## What this is not

- Not a VPN, mixnet, or live radio mesh claim.
- Not Lumen, Mandible, `lattice_online`, or `mesh_complete`.
- Not a public `qnsd` proxy. Faces do not publish this port.
- Not a back-gate / stand-back call into AZ Generator.
- Not Node Gate. **Node Gate = MirageGrid subsystem only.**
- Not public hostname restore. Phoenix waits / re-seals locally.
  Public tunnels and sites **die with the pull**.

Device hooks for Bluetooth, RF, Wi-Fi, photon-flash, camera/emitter,
and bitmesh are **MOCK**. The Protocol is real. Invented live
hardware is forbidden. Spec already allows mock.

## Pipeline (local only)

```
ingress
  → APG (raw bytes first; poison refused, not interpreted)
  → tip / dwell / claim stay strangers
  → via walker (lan, wifi, plc, bt, rf, light, qns, operator, local)
  → photon translate (same photon_id; translate=true across class)
  → outbox (force_via / path wait; lock-backed)
  → cold-copy / phoenix / reheal / re-expand
```

| Stage | Law | Honest act |
| --- | --- | --- |
| Ingress | QNM-BUILD-1.0 · QNS-CD-1.0 | Bind 127.0.0.1 only. Remote bearer stays off. |
| APG | QNM-BUILD-1.0 §7 | Size + marker refuse. Forbidden live symbols never become success. |
| Tip plane | SPLIT-WIRES-1.0 | Presence + tip hash only. Fixed-size. No body. |
| Dwell plane | SPLIT-WIRES-1.0 | 777s after a valid cite. Clock is not a yes. |
| Claim surface | this paper | MirageGrid Node Gate is **outside** this process. See below. |
| Via walker | QNS-CD-1.0 §8 | One program. Next class on fail/absent/PERM. Sticky-via banned. |
| Translate | QNS-CD-1.0 §7 | Admit one class, emit another. `photon_id` does not change. |
| Outbox | QNS-CD-1.0 · AIH-WP-1.3 | Wait is not death. Pair cut ⇒ no further emit. |
| Cold copy | COLD-COPY-1.0 | N named replicas. No live body sync. Public pull does not erase copies. |
| Phoenix | QNM-BUILD-1.0 · NODE-OPS-1.0 | Local wait / re-seal. No controller hunt. |
| Reheal | REHEAL-1.0 | Own last good tip + trusted pull, or phoenix-WAIT. No neighbor vote. |
| Re-expand | RE-EXPAND-1.0 | Archive verify + new local node on tip. Bytes, not summaries. |
| Survival | CROSS-NETWORK-SURVIVAL-1.0 | If network + live data die, the chain still survives. |
| No lie / no rewrite | NO-LIE-1.0 · NO-REWRITE-1.0 | Receipts still hash. No rewrite key. No lie to stay alive. |

`hop_max` (default 8) and the seen-list drop loops. Payload on a via
is sanitized and refused when it carries a live-symbol, remote-bearer,
Node Gate, AZ Generator, mesh-enable, sticky-via, or public-proxy key.
Sanitize **refuses**. It does not rewrite a sealed photon
(NO-REWRITE-1.0).

## Three clocks that stay strangers

| Clock | Socket | Owner | Carries |
| --- | --- | --- | --- |
| `tick_0.5_1s` | tick socket | qnm-node | presence + tip hash |
| `dwell_777s` | dwell socket | qnm-node | cite-then-dwell; not “take whatever arrived” |
| `miragegrid_claim` | Node Gate front | **MirageGrid only** | outward claim. Not a qnm tip. Not a dwell. |

The 1s loop and the 777s gate already stay strangers
([SPLIT-WIRES-1.0](SPLIT-WIRES-1.0.md)). This paper names the **third**
stranger: the MirageGrid claim clock. Sharing a socket across any two
of the three is refuse (`QNM-WIRES-THREE-CLOCKS`).

Claim is **not** a qnm hop. qnm does not schedule it, vote with it, or
heal from it.

## MirageGrid Node Gate (external stranger)

AZ Generator (MirageGrid) **does not get called** from qnm-node.

It lives **deep in the MirageGrid node** and exits **outward** through
the **FRONT Node Gate** only. That is not a back-gate. That is not a
stand-back call pipeline. qnm-node must not grow a
`call_az_generator` path.

```
MirageGrid (external)
  deep-node AZ Generator
        |  (outward only)
        v
  FRONT Node Gate     <- claim surface
        |
        x  no call from qnm
        |
qnm-node (this repo)
  APG -> wires -> vias -> photon -> outbox -> phoenix / reheal / cold-copy
```

- **Node Gate = MirageGrid subsystem only** (not qnm-node).
- The Node Gate is an **outward claim surface** fed by the deep-node
  generator.
- That claim clock is an **external stranger** to qnm tip and dwell
  clocks.
- Catalog form `miragegrid/assign` stays on the MirageGrid side
  ([QNM-WP-1.0](QNM-WP-1.0.md) §5). qnm cites the law. It does not
  execute the assign.

`node_gate: false` on a qnm / qnsd snapshot means this process is not
that gate. It does not mean the gate is called and answered “no.”

## Vias (walker order)

```
VIA_ORDER = lan, wifi, plc, bt, rf, gps, nfc, light, qns, operator, local
```

Fabric enable allows the software path. OS radios do **not** become
PRESENT from fabric alone. Missing hardware is ABSENT; emit is REFUSED.

| Class | Presence | Device |
| --- | --- | --- |
| `local`, `qns`, `operator` | always PRESENT (software) | **REAL** |
| `lan` | PRESENT (software). Emit fails without a declared link. | **REAL** software when declared/armed |
| `plc` | ABSENT without declared `domain` unless fabric-armed | software declare; no invented PLC PHY |
| `wifi` | PRESENT only when an 802.11 adapter is LIVE | NetworkManager / `iw` — **LIVE** or **ABSENT** |
| `bt` | PRESENT only when a BlueZ adapter is LIVE | BlueZ — **LIVE** or **ABSENT** |
| `rf` | PRESENT only when ModemManager sees modem+SIM | `mmcli` — **LIVE** or **ABSENT** (`RADIO-NO-MODEM`) |
| `gps` | PRESENT only when gpsd reports a 2D/3D fix | receive-only — TX is `RADIO-GNSS-RX-ONLY` |
| `nfc` | PRESENT only when libnfc/PCSC sees a reader | **LIVE** or **ABSENT** (`RADIO-NO-NFC`) |
| `light` | ABSENT without declare unless fabric-armed. Camera deny is PERM. | QNS1 codec **REAL**; camera / emitter **HOOK-PENDING** |

**Persist / transfer.** Cold-copy / vault-on-transfer / outbox places
the tip on named device classes: laptop, phone, apple-watch,
phone-watch, radio, bluetooth. That is a **local named-host vault**.
Radio / bluetooth PHY path is **LIVE** or **ABSENT** from OS probes.
A pull or offline hop does **not** erase the tip.

**Bitmesh geo (internal).** Geohash binds to tip on the internal
bitmesh plane for routing only. GNSS must be LIVE (`RADIO-NO-GNSS`
without a receiver). Public receipts stay no user / geo.

**Pissed-off-gov unkillability.** Architecture ≠ fielded.
`architecture_score` may be high (law + software Channels-ON + persist).
`fielded_score` / `score` is the hub-safe number. Fielded band today
is **68–70** (Cap-7 live + OS PHY ABSENT/LIVE facts) until Plane B has
a **hash-verified** Codeberg / archive.org / GitFlic shelf **and**
Plane C has an operator offline-verify / attest receipt. Zenodo is
IP-banned and is **not required**. A format-only DOI does not open
the gate. `meets_target` is true only when those fielded gates pass.
Hubs must **not** publish `architecture_score` or 100. Plane A hubs
are LIVE on the **same CF tunnel** — not four independent copies.
Plane B is SLOT until hash-verified. Plane C USB pack is READY, not
LIVE, until the operator attests. No FAN. Do not invent a DOI or
airgap success. `GET /local/unkillability`. `GET /local/channels`
and `GET /local/phy` stamp LIVE | ABSENT | REFUSED. This is not a
live RF mesh claim. Plane C attest-before-LIVE. Lamb Lens:
Service → Clarity → Peace. No hub chrome.

Restriction walks the next class inside the same call. `force_via`
restricted ⇒ wait. No silent remap. Packet id does not change.
Sticky-via is banned (`QNS-STICKY-VIA`).

COLD walker may use **local** only. Pair cut ⇒ no further emit.
APG poison ⇒ **no walk**.

## Survival path (legal order)

1. Poison → refuse (APG). Do not interpret.
2. Tamper / poison aftermath → **isolate** (tethers drop, pairs cut).
3. No trusted last-good bytes → **phoenix-WAIT** (local). Not a
   public hostname restore. Not a controller hunt.
4. Public origin / Worker / DNS pull → **die-with-pull**. Cold copies
   remain. Local verify / append may continue.
5. Reheal = own last good tip + trusted pull, **or** phoenix-WAIT.
   Neighbor / majority / “should be” refuse.
6. Re-expand = archive verify + new local node on that tip.
7. No lie to stay alive, adapt, or prevent death. No rewrite key.

## Attack surface (minimized)

| Control | Refuse |
| --- | --- |
| Bind | 127.0.0.1 / `::1` only (`QNM-LOOPBACK-ONLY`) |
| Radio bearer | off until fabric enable (`QNM-RADIO-OFF`); then software-on (**MOCK**, not fielded / not live mesh) |
| Remote bearer | cannot enable (`QNM-BEARER-OFF`) |
| APG size | ingress > 64 KiB (`QNM-APG-POISON`) |
| APG markers | Lumen / Mandible / lattice_online / mesh_complete / hunt / publish |
| Live symbols | never assigned as success states |
| Mesh GET | `/v1/mesh` never enables (`QNM-MESH-NEVER-ENABLES`) |
| Node Gate / AZ Generator | not a qnm path (`QNM-NO-NODE-GATE`, `QNM-NO-AZ-GENERATOR`) |
| Public qnsd proxy | refused (`QNM-NO-QNSD-PROXY`) |
| Via payload | sanitize-refuse (`QNS-VIA-SANITIZE`) |
| Loops | `hop_max` + seen-list (`QNS-HOP-MAX`, `QNS-LOOP-DROP`) |
| Sticky-via | banned (`QNS-STICKY-VIA`) |

## Tests

File: `tests/test_fabric.py` (pipeline + three-clock stranger +
survival integration). File: `tests/test_attack_surface.py`
(bind / radio / remote / APG size / markers / mesh GET / sanitize).
Existing `tests/test_qnsd.py` remains QNS-CD-1.0 §14.

Offline. pytest. No invented hardware.

## Cite

Eliab, Aziel. (2026). FABRIC-MESH-PIPELINE-1.0 local fabric mesh
pipeline [Law]. Companion: QNM-BUILD-1.0 · QNS-CD-1.0. Apache-2.0.
https://github.com/AzielEliab/qnm-node

Do not invent a DOI.

Specified 2026-09-14. Author: Aziel Eliab only.
