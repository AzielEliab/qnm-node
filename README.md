# qnm-node

Local **Quantum Node Mesh** process from **[QNM-BUILD-1.0](docs/QNM-BUILD-1.0.md)**
with **[AIH-WP-1.3](docs/AIH-WP-1.3.md)** Spiderweb Pair-Bind
(medium-independent) and **[QNS-CD-1.0](docs/QNS-CD-1.0.md)** local
`qnsd` (photon packet; vias in one program). Hub / Interface law
remains **AIH-WP-1.1**.

**Author:** Aziel Eliab only
**Date:** September 2026 · v1.2.0
**License:** [Apache-2.0](LICENSE)
**Spec:** QNM-BUILD-1.0 · AIH-WP-1.3 · QNS-CD-1.0

> Radios off. Receipts to disk. Poison refused, not interpreted.
> Pair-id outlives the path. Waiting is not death.

**Forks are welcome and always allowed.**

This is a **local node**. It is not AZHub, not AZInterface, not the
hosted suite mesh, and not AnonBroadcast as a Softwares-tab product.
Local **qnsd owns vias**. Suite Workers **cite / proxy only**.
`GET /v1/mesh` **never enables**. There is **no Node Gate**.

## Honest scope

**THIS IS:** a 127.0.0.1 process with APG on every ingress, default-off
bearers, a visible outbox, declared tethers, PHOENIX-LOCK (local wait),
QNM-S (score never reads views), medium-independent pair-ids that
forward only along existing spiderweb edges, and a sibling `qnsd`
process where the photon is the packet and restriction walks the next
via class in one program.

**THIS IS NOT:** a VPN, a radio mesh, Lumen, Mandible, `lattice_online`,
`mesh_complete`, an account system, a publish path, Bell-pair physics,
or a qubit machine.

## Bulletproof law (QNM-BUILD-1.0)

- Local modules run **radios off**
- Receipts to **disk** (`data/receipts/`, `data/chain/`)
- Poison **refused, not interpreted**
- Tamper **isolates**
- PHOENIX-LOCK **waits locally** (no controller hunt)
- Tethers **drop clean**
- **No account resurrection**
- AnonBroadcast is **never a publish path**
- No Lumen / Mandible live symbols
- No `lattice_online` / `mesh_complete`
- Score **never reads views**
- Identity **Aziel Eliab** only

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

No auto-heal. No LIVE from a site ping.

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
| `POST /local/phoenix/arm` | Wait locally |
| `GET /local/receipts` | Disk receipts |

`qnsd` adds `POST /local/policy` and `POST /local/declare` on the same
loopback bind (port from `cfg/node.json`, default 8891).

## QNS-CD-1.0 (local qnsd)

Photon is the packet (`QNS1` ver 1.3). QNS is the native medium. Light
is camera-flash OCC. `VIA_ORDER` = lan, plc, bt, rf, light, qns,
operator, local. `local` + `qns` + `operator` are always PRESENT
(software). rf / plc / light need declare. Restriction walks the next
class automatically. `force_via` waits — no silent remap. Packet id
does not change across hops. Sticky-via is banned. SEAL does not
require OS BT / Wi-Fi.

Device hooks for Bluetooth, RF, and camera may be **mock-backed** and
still implement `ViaAdapter`. See [docs/QNS-CD-1.0.md](docs/QNS-CD-1.0.md)
(PDF companion noted there; Worker does not serve it).

## Layout

```
qnm/                 boot, node, chain, apg, bearers, outbox,
                     phoenix, score, memorial, tethers,
                     pairs, spiderweb
qnsd/                QNS-CD-1.0 daemon: photon, walker, vias, light,
                     azpipe, policy, api (127.0.0.1)
modules/anon-broadcast/   loopback-only style tool (never a publish path)
cfg/node.json
data/{chain,locks,outbox,receipts,witness}
docs/QNM-BUILD-1.0.md
docs/AIH-WP-1.3.md
docs/QNS-CD-1.0.md   (+ PDF companion note)
docs/DESIGN-INDEX.md
tests/               QNM §14 + AIH-WP-1.3 + QNS-CD-1.0 §14
```

## Tests (§14 + AIH-WP-1.3 + QNS-CD-1.0)

```bash
pip install -e ".[dev]"
python -m pytest -q
```

Offline. Covers radios-off / two roots / lock resume, APG poison,
tamper isolate, PHOENIX-LOCK local wait, clean tether cut, no
account resurrection, pair survives bearer off, spiderweb forward
with APG, isolated node has no edges, hop_max / loop drop, and QNS-CD
via Protocol / walker / light OCC / lock-backed outbox wait / pair-cut
emit stop.

## Cite

Eliab, Aziel. (2026). QNM-BUILD-1.0 Quantum Node Mesh local node
[Software]. Apache-2.0. https://github.com/AzielEliab/qnm-node

Eliab, Aziel. (2026). AIH-WP-1.3 Spiderweb Pair-Bind [Law].
Companion: QNM-BUILD-1.0. Apache-2.0.
https://github.com/AzielEliab/qnm-node

Eliab, Aziel. (2026). QNS-CD-1.0 Quantum Node Signal Coding Design
[Software]. Apache-2.0. https://github.com/AzielEliab/qnm-node

Do not invent a DOI.

See [docs/QNM-BUILD-1.0.md](docs/QNM-BUILD-1.0.md),
[docs/AIH-WP-1.3.md](docs/AIH-WP-1.3.md),
[docs/QNS-CD-1.0.md](docs/QNS-CD-1.0.md), and
[docs/DESIGN-INDEX.md](docs/DESIGN-INDEX.md). AZHub / AZInterface remain
separate software (AIH-WP-1.1). Suite Workers cite/proxy only. GET /v1/mesh
never enables. No Node Gate.
