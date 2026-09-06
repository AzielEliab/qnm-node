# qnm-node

Local **Quantum Node Mesh** process from **[QNM-BUILD-1.0](docs/QNM-BUILD-1.0.md)**
with **[AIH-WP-1.3](docs/AIH-WP-1.3.md)** Spiderweb Pair-Bind
(medium-independent). Hub / Interface law remains **AIH-WP-1.1**.

**Author:** Aziel Eliab only
**Date:** September 2026 · v1.1.0
**License:** [Apache-2.0](LICENSE)
**Spec:** QNM-BUILD-1.0 · AIH-WP-1.3

> Radios off. Receipts to disk. Poison refused, not interpreted.
> Pair-id outlives the path. Waiting is not death.

**Forks are welcome and always allowed.**

This is a **local node**. It is not AZHub, not AZInterface, not the
hosted suite mesh, and not AnonBroadcast as a Softwares-tab product.

## Honest scope

**THIS IS:** a 127.0.0.1 process with APG on every ingress, default-off
bearers, a visible outbox, declared tethers, PHOENIX-LOCK (local wait),
QNM-S (score never reads views), and medium-independent pair-ids that
forward only along existing spiderweb edges.

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

## Layout

```
qnm/                 boot, node, chain, apg, bearers, outbox,
                     phoenix, score, memorial, tethers,
                     pairs, spiderweb
modules/anon-broadcast/   loopback-only style tool
cfg/node.json
data/{chain,locks,outbox,receipts,witness}
docs/QNM-BUILD-1.0.md
docs/AIH-WP-1.3.md
tests/               §14 + AIH-WP-1.3
```

## Tests (§14 + AIH-WP-1.3)

```bash
pip install -e ".[dev]"
python -m pytest -q
```

Offline. Covers radios-off / two roots / lock resume, APG poison,
tamper isolate, PHOENIX-LOCK local wait, clean tether cut, no
account resurrection, pair survives bearer off, spiderweb forward
with APG, isolated node has no edges, and hop_max / loop drop.

## Cite

Eliab, Aziel. (2026). QNM-BUILD-1.0 Quantum Node Mesh local node
[Software]. Apache-2.0. https://github.com/AzielEliab/qnm-node

Eliab, Aziel. (2026). AIH-WP-1.3 Spiderweb Pair-Bind [Law].
Companion: QNM-BUILD-1.0. Apache-2.0.
https://github.com/AzielEliab/qnm-node

Do not invent a DOI.

See [docs/QNM-BUILD-1.0.md](docs/QNM-BUILD-1.0.md) and
[docs/AIH-WP-1.3.md](docs/AIH-WP-1.3.md). AZHub / AZInterface remain
separate software (AIH-WP-1.1).
