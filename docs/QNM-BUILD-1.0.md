# QNM-BUILD-1.0 — Quantum Node Mesh Build Guide

**Author:** Aziel Eliab only
**Companion:** AIH-WP-1.3 (Spiderweb Pair-Bind; medium-independent)
**Hub / Interface law:** AIH-WP-1.1 (AZHub / AZInterface remain separate)
**License:** Apache-2.0
**Date:** September 2026
**Software:** qnm-node 1.1.0

This document is the law for the local node process. Public identity is
**Aziel Eliab** only.

## §1 Identity

Aziel Eliab only. No other author name. No account object. A node is an
`install_root`, not a login.

## §2 Bulletproof law

- Local modules run with **radios off**.
- Receipts go to **disk**.
- Poison is **refused, not interpreted**.
- Tamper **isolates**.
- **PHOENIX-LOCK** waits locally. No controller hunt.
- Tethers **drop clean**.
- **No account resurrection**.
- AnonBroadcast is **never a publish path**.
- No **Lumen** / **Mandible** live symbols.
- No **lattice_online** / **mesh_complete**.
- **Score never reads views**.

## §3 Tree

```
qnm/{boot,node,chain,apg,bearers,outbox,phoenix,score,memorial,tethers,pairs,spiderweb}.py
modules/anon-broadcast/          loopback-only
cfg/node.json
data/{chain,locks,outbox,receipts,witness}
docs/{QNM-BUILD-1.0,AIH-WP-1.3}.md
tests/                           §14 + AIH-WP-1.3
```

## §4 Boot

```
install_root = SHA256(entropy || nonce || optional_genesis)
```

Two installs produce two roots. Resume is allowed **only** from
`data/locks/`. A scorched lock cannot return to LOCAL or LIVE.

## §5 State

```
COLD → LOCAL → LIVE(operator bearer) → DEGRADED → ISOLATED → PHOENIX_LOCK → SCORCHED
```

Forward-only. **No auto-heal.** **No LIVE from site ping.** Local API
binds **127.0.0.1** only:

`/local/boot` `/local/state` `/local/bearer` `/local/tether`
`/local/pair` `/local/pairs` `/local/forward`
`/local/ingress` `/local/outbox` `/local/outbox/cut`
`/local/phoenix/arm` `/local/receipts`

## §6 Bearers

`local` is on. `operator`, `lan`, `radio`, `remote` default off. Radio
and remote cannot be enabled. LIVE requires an explicit operator bearer.

## §7 APG

Every ingress is scanned as raw bytes. Matching a poison marker refuses
the payload without interpreting it.

## §8 Chain and receipts

Append-only JSONL under `data/chain/`. One receipt file per event under
`data/receipts/`. No rewrite.

## §9 Outbox

Visible local queue. Cut drops the item. `publish` is refused.

## §10 Tethers

Declared corridors only (AIH-WP-1.1). Cut leaves no residue and does
not auto-rewire. Stored under `data/witness/`. Pair-bind edges are
**AIH-WP-1.3** (medium-independent spiderweb) — not these tethers.
See [AIH-WP-1.3.md](AIH-WP-1.3.md).

## §11 PHOENIX-LOCK

Operator arm. The node waits on this machine. `hunt_controller` is
refused (`QNM-PHOENIX-LOCAL-WAIT`).

## §12 Score (QNM-S)

Local chain integrity and posture only. Views, downloads, and ranking
are refused.

## §13 Memorial / no resurrection

SCORCHED writes `data/witness/memorial.json`, marks the lock scorched,
clears tethers and outbox. `account_resurrect` / `account_restore` /
`account_create` refuse (`QNM-NO-ACCOUNT`).

## §14 Tests (ship these)

| File | Law |
|------|-----|
| `tests/test_offline.py` | Radios off; two roots; resume locks only; no LIVE from ping; no auto-heal; receipts on disk; 127.0.0.1 API |
| `tests/test_apg.py` | Every ingress through APG; poison refused not interpreted |
| `tests/test_tamper.py` | Tamper isolates; no auto-heal out of ISOLATED |
| `tests/test_phoenix.py` | PHOENIX-LOCK waits locally; no controller hunt |
| `tests/test_tether.py` | Tethers drop clean |
| `tests/test_no_account.py` | No account resurrection; identity Aziel Eliab; score ignores views; anon-broadcast never publishes |
| `tests/test_spiderweb.py` | AIH-WP-1.3: pair survives bearer off; forward along spiderweb with APG; isolated node has no edges; hop_max / loop drop |

## Cite

Eliab, Aziel. (2026). QNM-BUILD-1.0 Quantum Node Mesh local node
[Software]. Apache-2.0. https://github.com/AzielEliab/qnm-node

Eliab, Aziel. (2026). AIH-WP-1.3 Spiderweb Pair-Bind [Law].
Companion: QNM-BUILD-1.0. Apache-2.0.
https://github.com/AzielEliab/qnm-node

Do not invent a DOI.

Apache-2.0. Forks are welcome and always allowed.
