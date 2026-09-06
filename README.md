# qnm-node

Local **Quantum Node Mesh** process from **[QNM-BUILD-1.0](docs/QNM-BUILD-1.0.md)**
(companion **AIH-WP-1.1**).

**Author:** Aziel Eliab only
**Date:** September 2026 · v1.0.0
**License:** [Apache-2.0](LICENSE)
**Spec:** QNM-BUILD-1.0

> Radios off. Receipts to disk. Poison refused, not interpreted.

**Forks are welcome and always allowed.**

This is a **local node**. It is not AZHub, not AZInterface, not the
hosted suite mesh, and not AnonBroadcast as a Softwares-tab product.

## Honest scope

**THIS IS:** a 127.0.0.1 process with APG on every ingress, default-off
bearers, a visible outbox, declared tethers, PHOENIX-LOCK (local wait),
and QNM-S (score never reads views).

**THIS IS NOT:** a VPN, a radio mesh, Lumen, Mandible, `lattice_online`,
`mesh_complete`, an account system, or a publish path.

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
| `POST /local/ingress` | APG then admit |
| `GET /local/outbox` | Visible queue |
| `POST /local/outbox/cut` | Drop one item |
| `POST /local/phoenix/arm` | Wait locally |
| `GET /local/receipts` | Disk receipts |

## Layout

```
qnm/                 boot, node, chain, apg, bearers, outbox,
                     phoenix, score, memorial, tethers
modules/anon-broadcast/   loopback-only style tool
cfg/node.json
data/{chain,locks,outbox,receipts,witness}
docs/QNM-BUILD-1.0.md
tests/               §14
```

## Tests (§14)

```bash
pip install -e ".[dev]"
python -m pytest -q
```

Offline. Covers radios-off / two roots / lock resume, APG poison,
tamper isolate, PHOENIX-LOCK local wait, clean tether cut, and no
account resurrection.

## Cite

Eliab, Aziel. (2026). QNM-BUILD-1.0 Quantum Node Mesh local node
[Software]. Apache-2.0. https://github.com/AzielEliab/qnm-node

Do not invent a DOI.

See [docs/QNM-BUILD-1.0.md](docs/QNM-BUILD-1.0.md). Companion Hub /
Interface law: AIH-WP-1.1 (AZHub / AZInterface remain separate software).
