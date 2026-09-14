# qnm-node

Local **Quantum Node Mesh** process from **[QNM-BUILD-1.0](docs/QNM-BUILD-1.0.md)**
with **[AIH-WP-1.3](docs/AIH-WP-1.3.md)** Spiderweb Pair-Bind
(medium-independent) and **[QNS-CD-1.0](docs/QNS-CD-1.0.md)** local
`qnsd` (photon packet; vias in one program). Hub / Interface law
remains **AIH-WP-1.1**.

**Author:** Aziel Eliab only
**Date:** September 2026 · v1.5.0
**License:** [Apache-2.0](LICENSE)
**Spec:** QNM-BUILD-1.0 · AIH-WP-1.3 · QNS-CD-1.0 · FABRIC-MESH-PIPELINE-1.0

> Fabric enable is Channels-ON: the software path is allowed.
> Cellular / Wi-Fi / BT / GNSS / NFC stamp **LIVE | ABSENT | REFUSED**
> from real OS probes — never mock chatter. Receipts to disk. Poison
> refused, not interpreted. Pair-id outlives the path. Waiting is
> not death. GET /v1/mesh never enables.

**Forks are welcome and always allowed.**

This is a **local node**. It is not AZHub, not AZInterface, not the
hosted suite mesh, and not AnonBroadcast as a Softwares-tab product.
Local **qnsd owns vias**. Suite Workers **cite / proxy only**.
`GET /v1/mesh` **never enables**. There is **no Node Gate**.

## Honest scope

**THIS IS:** a 127.0.0.1 process with APG on every ingress, unarmed
bearers until fabric enable (then software paths ON; OS radios
**LIVE | ABSENT | REFUSED**), a visible outbox, declared tethers, PHOENIX-LOCK (local wait /
re-seal after poison or isolation; not public hostname restore),
QNM-S (score never reads views), medium-independent pair-ids that
forward only along existing spiderweb edges, a sibling `qnsd`
process where the photon is the packet and restriction walks the next
via class in one program, persist-across-device cold copies (laptop /
phone / watch / radio / bluetooth), an internal bitmesh geohash plane
(not public ACT-RECEIPT geo), and a local fabric pipeline
(ingress → APG → tip/dwell/claim strangers → walker → translate →
outbox → cold-copy / phoenix / reheal / re-expand).

**THIS IS NOT:** a VPN, a live radio mesh, Lumen, Mandible,
`lattice_online`, `mesh_complete`, an account system, a publish path,
Bell-pair physics, a qubit machine, a public `qnsd` proxy, a Node Gate,
or a call into AZ Generator.

### REAL vs LIVE / ABSENT / REFUSED vs LAW

| Kind | What |
|------|------|
| **REAL** | Local 127.0.0.1 process. APG refuse-first. Split-wires tip + dwell clocks. Photon (`QNS1` 1.3) codec + walker + translate. Outbox / receipts / chain on disk. Cold copies, named-host persist/transfer, archive re-expand, own-tip reheal, phoenix-WAIT. Loopback bind. Remote bearer stays off. |
| **LIVE / ABSENT / REFUSED** | Cellular (ModemManager/`mmcli`), Wi-Fi (NetworkManager/`iw`), Bluetooth (BlueZ), GNSS (gpsd/NMEA receive-only), NFC (libnfc/PCSC). LIVE only when the OS adapter is present. Missing hardware is ABSENT; emit is REFUSED (`RADIO-NO-*`). No mock chatter. Camera/emitter stays HOOK-PENDING. |
| **LAW** | CROSS-NETWORK-SURVIVAL / REHEAL / SPLIT-WIRES / COLD-COPY / NO-LIE / NO-REWRITE / NO-FAN / QNS-CD / FABRIC-MESH-PIPELINE ALL-CHANNELS-ON. Internal bitmesh geo needs LIVE GNSS (`RADIO-NO-GNSS` without a receiver). Public receipts stay no user/geo. Unkillability **architecture ≠ fielded**; hubs must not publish 100. Plane B is hash-verified Codeberg/archive/GitFlic (Zenodo not required); Plane C attest-before-LIVE. `GET /v1/mesh` never enables radios. No Softwares-tab product. AZ Generator is not called from qnm. Identity Aziel Eliab only. |

MirageGrid **Node Gate** is an **outward claim surface** fed by a
deep-node AZ Generator. That generator is **not called** from qnm.
Node Gate is a MirageGrid subsystem only. Its claim clock is an
**external stranger** to qnm tip and dwell clocks. qnm stays local
fabric. Channels-ON when fabric-enabled means the software path is
allowed; OS radios are LIVE only when adapters are present.
Phoenix does not restore a public hostname.

## Bulletproof law (QNM-BUILD-1.0)

- Local modules run **radios off** until fabric enable; then the
  software path is ON and OS PHYs stamp LIVE | ABSENT | REFUSED
  (not invented live RF mesh)
- Receipts to **disk** (`data/receipts/`, `data/chain/`)
- Poison **refused, not interpreted**
- Tamper **isolates**
- PHOENIX-LOCK **waits / re-seals locally** after poison or isolation
  (no controller hunt; **not** public hostname restore)
- Public tunnels and sites **die with the pull**. Mesh does not climb
  back onto the public hostname by itself. Local node may keep
  verifying and appending after a pull.
- Tethers **drop clean**
- **No account resurrection**
- AnonBroadcast is **never a publish path**
- No Lumen / Mandible live symbols
- No `lattice_online` / `mesh_complete`
- Score **never reads views**
- Identity **Aziel Eliab** only
- **Split the wires:** tick = presence + tip hash; payloads are pull-only
- **Cold copies** survive a public pull. No live body sync. Named hosts only
- **Re-expand** = archive verify + new local node on tip (bytes, not summaries)
- **Reheal** = own last good tip + trusted pull, or phoenix-WAIT. Not neighbors
- **Cross-network survival:** if network + live data die, the chain still
  survives. Local verify / append stay offline. Tips do not need the
  public network
- **No lie:** network never lies, even to stay alive, adapt, or prevent
  death. Receipts still hash. Verify is without voice
- **No rewrite:** no rewrite key. Published tip cannot be rewritten or
  mutated. Copies are not all on one tunnel

## Pair-bind law (AIH-WP-1.3)

Supersedes AIH-WP-1.2 §2.3–§3.3 (one-bearer seal / pair dies with Wi-Fi).

- `pair_id = SHA256(root_A || root_B || nonce_A || nonce_B)` is
  **medium-independent**
- Lives in **both Memorials** until isolate / PHOENIX-LOCK / Scorch /
  operator cut
- Bearer is **hop-only** (`via` on the frame); any currently enabled
  declared bearer may carry the next frame
- `bearer_id` on SEAL is the **path that day**, not a marriage license
- Spiderweb: many pair-ids per live node; forward A→B→C only along
  existing pair edges, APG pass, not isolated/locked, hop bearer enabled
- `hop_max` default **8** + seen hash list; loops drop
- Wi-Fi dies → **path gone, bind remains**; outbox keeps the frame;
  waiting is not death
- Isolation still cuts all pair edges
- Poison / tamper do **not** ride the spiderweb

## Boot and state

```
install_root = SHA256(entropy || nonce || optional_genesis)
```

Two installs → two roots. Resume only from `data/locks/`.

```
COLD → LOCAL → LIVE(operator bearer) → DEGRADED → ISOLATED → PHOENIX_LOCK → SCORCHED
```

No auto-heal. No LIVE from a site ping. Phoenix does not restore a
public hostname, `.uk`, tunnel, or Worker rollup.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate && pip install -e ".[dev]"
python -m qnm doctor
python -m qnm boot
python -m qnm serve
python -m qnsd doctor
python -m qnsd serve
```

Local API binds **127.0.0.1:8891** only:

| Path | Act |
|------|-----|
| `POST /local/boot` | Install or resume from `data/locks/` |
| `GET /local/state` | Posture (not completeness) |
| `POST /local/bearer` | Operator bearer for LIVE |
| `POST /local/tether` | Declare or cut |
| `POST /local/pair` | OFFER / ACCEPT / SEAL / operator cut |
| `GET /local/pairs` | Living pair-ids in this Memorial |
| `POST /local/forward` | Spiderweb hop (APG; hop bearer; hop_max) |
| `POST /local/ingress` | APG then admit |
| `GET /local/outbox` | Visible queue |
| `POST /local/outbox/cut` | Drop one item |
| `POST /local/phoenix/arm` | Wait / re-seal locally (not public hostname restore) |
| `GET /local/receipts` | Disk receipts |
| `POST /local/tick` | Tick plane: presence + tip hash only |
| `POST /local/pull` | Pull payload (never a push) |
| `POST /local/cite` | Hash-absolute cite (prev + lockset) |
| `POST /local/emit` | Announce tip after own verify |
| `POST /local/rejoin` | Cite + operator / lockset (no auto-splice) |
| `GET/POST /local/vault` | Cold replicas / pin / pull-origin |
| `GET /local/wires` | Plane + clock status |
| `POST /local/archive` | Pack / verify / re-expand chain bytes |
| `POST /local/reheal` | Own last good tip, or phoenix-WAIT |
| `POST /local/survive` | Public network dead; local verify / append / archive |
| `GET/POST /local/nolie` | No-lie / no-rewrite status; receipts still hash |
| `POST /local/rewrite` | Always refused (`QNM-NO-REWRITE`) |
| `GET/POST /local/fabric` | Pipeline status / enable (software Channels-ON; OS PHYs LIVE\|ABSENT) / one local pass (never calls AZ Generator) |
| `GET /local/channels` | ALL-CHANNELS audit: software `REAL`; OS radios `LIVE` / `ABSENT` |
| `GET /local/phy` | Cellular / Wi-Fi / BT / GNSS / NFC OS probe cards |
| `POST /local/persist` | Named-host vault-on-transfer. Radio/BT PHY path is LIVE or ABSENT |
| `GET/POST /local/bitmesh` | Internal geohash bind (LIVE GNSS or `RADIO-NO-GNSS`; not public ACT-RECEIPT geo) |
| `GET /local/unkillability` | Architecture vs fielded erasure cost. `score` = fielded (68–70 until hash-verified Plane B shelf + Plane C attest). Zenodo is not required. Hubs must not publish architecture 100. |
| `GET/POST /local/planes` | Plane A/B/C facts. Hash-verified Codeberg/archive/GitFlic shelves count. Plane C attest-before-LIVE. Refuse invented DOI or airgap success. |

`qnsd` adds `POST /local/policy` and `POST /local/declare` on the same
loopback bind (port from `cfg/node.json`, default 8891).

## QNS-CD-1.0 (local qnsd)

Photon is the packet (`QNS1` ver 1.3). QNS is the native medium. Light
is camera-flash OCC. `VIA_ORDER` = lan, wifi, plc, bt, rf, gps, nfc,
light, qns, operator, local. `local` + `qns` + `operator` are always
PRESENT (software). Cellular / Wi-Fi / BT / GNSS / NFC are LIVE OS
bindings or ABSENT. Restriction walks the next class automatically.
`force_via` waits — no silent remap. Packet id does not change across
hops. Sticky-via is banned. SEAL does not require OS BT / Wi-Fi.

OS radios implement `ViaAdapter` against real host tools. Photon
**codec** is REAL; the camera/emitter hook stays HOOK-PENDING. See
[docs/QNS-CD-1.0.md](docs/QNS-CD-1.0.md) and
[docs/RADIO-PHY-1.0.md](docs/RADIO-PHY-1.0.md)
(PDF companion noted there; Worker does not serve it).

## Layout

```
qnm/                 boot, node, chain, apg, bearers, outbox,
                     phoenix, score, memorial, tethers,
                     pairs, spiderweb, wires, coldcopy, archive,
                     nolie, fabric, bitmesh
qnsd/                QNS-CD-1.0 daemon: photon, walker, vias, light,
                     azpipe, policy, sanitize, api (127.0.0.1)
modules/anon-broadcast/   loopback-only style tool (never a publish path)
cfg/node.json
data/{chain,locks,outbox,receipts,witness,vault,archive,bitmesh}
docs/QNM-BUILD-1.0.md
docs/AIH-WP-1.3.md
docs/QNS-CD-1.0.md   (+ PDF companion note)
docs/FABRIC-MESH-PIPELINE-1.0.md
docs/DESIGN-INDEX.md
tests/               QNM §14 + AIH-WP-1.3 + QNS-CD-1.0 §14
                     + fabric pipeline + attack-surface
```

## Tests (§14 + AIH-WP-1.3 + QNS-CD-1.0)

```bash
pip install -e ".[dev]"
python -m pytest -q
```

Offline. Covers radios-off / two roots / lock resume, APG poison,
tamper isolate, PHOENIX-LOCK local wait / re-seal (not public hostname
restore), clean tether cut, no account resurrection, pair survives
bearer off, spiderweb forward
with APG, isolated node has no edges, hop_max / loop drop, and QNS-CD
via Protocol / walker / light OCC / lock-backed outbox wait / pair-cut
emit stop. Also receipts-still-hash, verify-without-voice, no rewrite
key, published-tip immutable, no one-tunnel copies, no lie-to-live
heal, fabric pipeline (three-clock strangers; no AZ Generator call),
and attack-surface (remote off, radio refuse, loopback, APG
size/marker, forbidden live symbols, no public qnsd proxy).

## Cite

Eliab, Aziel. (2026). QNM-BUILD-1.0 Quantum Node Mesh local node
[Software]. Apache-2.0. https://github.com/AzielEliab/qnm-node

Eliab, Aziel. (2026). AIH-WP-1.3 Spiderweb Pair-Bind [Law].
Companion: QNM-BUILD-1.0. Apache-2.0.
https://github.com/AzielEliab/qnm-node

Eliab, Aziel. (2026). QNS-CD-1.0 Quantum Node Signal Coding Design
[Software]. Apache-2.0. https://github.com/AzielEliab/qnm-node

Eliab, Aziel. (2026). NO-LIE-1.0 / NO-REWRITE-1.0 [Law].
Companion: QNM-BUILD-1.0. Apache-2.0.
https://github.com/AzielEliab/qnm-node

Eliab, Aziel. (2026). FABRIC-MESH-PIPELINE-1.0 local fabric mesh
pipeline [Law]. Companion: QNM-BUILD-1.0 · QNS-CD-1.0. Apache-2.0.
https://github.com/AzielEliab/qnm-node

Do not invent a DOI.

See [docs/QNM-BUILD-1.0.md](docs/QNM-BUILD-1.0.md),
[docs/AIH-WP-1.3.md](docs/AIH-WP-1.3.md),
[docs/QNS-CD-1.0.md](docs/QNS-CD-1.0.md),
[docs/FABRIC-MESH-PIPELINE-1.0.md](docs/FABRIC-MESH-PIPELINE-1.0.md),
and [docs/DESIGN-INDEX.md](docs/DESIGN-INDEX.md). AZHub / AZInterface
remain separate software (AIH-WP-1.1). Suite Workers cite/proxy only.
GET /v1/mesh never enables. No Node Gate in qnm-node (Node Gate =
MirageGrid only).
