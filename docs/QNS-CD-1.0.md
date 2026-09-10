# QNS-CD-1.0 — Quantum Node Signal Coding Design

**Author:** Aziel Eliab only
**Parents:** QNS-WP-1.3 · QNM-BUILD-1.0 · AIH-WP-1.3 · APG · AZPIPE · ChainLock
**Hub / Interface law:** AIH-WP-1.1 (AZHub / AZInterface remain separate)
**License:** Apache-2.0
**Date:** September 2026
**Software:** qnm-node 1.2.0 · local `qnsd` process

This document is the coding design for the local Quantum Node Signal
daemon. Public identity is **Aziel Eliab** only.

Print twin: `docs/QNS-CD-1.0.pdf` when generated. This markdown is the
law. The Worker does not serve the PDF. Git-hosted companion only.

Local `qnsd` **owns vias**. Suite Workers **cite / proxy only**. This
is **not** a Softwares-tab product. `GET /v1/mesh` **never enables**.
There is **no Node Gate**.

## §1 Identity

Aziel Eliab only. No other author name. No account object. A node is an
`install_root`, not a login.

Photon is the packet. QNS is the native medium. Light is camera-flash
OCC of that same photon — not a second network.

## §2 Sentence

Every send class lives in **one program**. Restriction walks the **next
class** automatically. The packet id **does not change** across hops.
Sticky-via is banned. SEAL does not marry OS Bluetooth or Wi-Fi.
Anon-broadcast stays a loopback sibling — never a publish path.

## §3 What this is not

- Not a Softwares-tab engine. Not FragGate-live catalog software.
- Not enabled by `GET /v1/mesh`. Not a Node Gate / IP panel.
- Not a VPN, radio mesh claim, qubit machine, or Bell-pair physics.
- Not Lumen / Mandible / `lattice_online` / `mesh_complete`.
- Device hooks for Bluetooth, RF, and camera may be **mock** and still
  implement the Protocol. Mock is honest. Invented hardware is not.

## §4 Tree

```
qnsd/{boot,node,photon,outbox,walker,translate,apg,azpipe,
      chain,receipts,pairs,memorial,policy,api}.py
qnsd/vias/{base,lan,plc,bt,rf,light,qns,operator,local}.py
qnsd/light/{codec,camera,emitter}.py
qnm/                 QNM-BUILD-1.0 (reused; not replaced)
modules/anon-broadcast/   loopback sibling — never a publish path
cfg/node.json
data/{chain,locks,outbox,receipts,witness}
docs/QNS-CD-1.0.md
docs/QNS-CD-1.0.pdf      print companion (git-hosted; Worker does not serve)
tests/test_qnsd.py       §14
```

Reuse `qnm/*` (apg, chain, pairs, memorial, phoenix, boot locks) where
it matches. Do not break QNM-BUILD-1.0.

## §5 Boot

```
install_root = SHA256(entropy || nonce || optional_genesis)
```

Two installs produce two roots. Resume is allowed **only** from
`data/locks/`. Outbox wait is lock-backed (`data/locks/wait.jsonl`) so
a restart restores the queue. A scorched lock cannot return to LOCAL
or LIVE.

## §6 State

```
COLD → LOCAL → LIVE → DEGRADED → ISOLATED → PHOENIX_LOCK → SCORCHED
```

Forward-only. **No auto-heal.** **No LIVE from site ping.** LIVE is an
operator act (`POST /local/policy` with `operator: true` or declare
`operator`). COLD walker may use **local** only.

## §7 Photon (QNS1 ver 1.3)

Magic `QNS1`. Version `1.3`. Canonical dumps/loads (sorted keys, tight
separators).

`PHOTON_FIELDS` =

`magic, ver, photon_id, pair_id, src, dst, via, via_in, via_out,
translate, hop, hop_max, seen, payload, utc, author, spec`

```
photon_id = SHA256(canonical({magic, ver, src, dst, pair_id, payload}))
pair_id   = SHA256(root_A || root_B || nonce_A || nonce_B)   # AIH-WP-1.3
```

`via`, `hop`, `seen`, and `translate` are hop-mutable. They **must not**
enter `photon_id`. Admit on one class and emit on another sets
`translate=true` and keeps the same `photon_id`.

## §8 Vias

```
VIA_ORDER = lan, plc, bt, rf, light, qns, operator, local
```

Every module implements `ViaAdapter` (Protocol): `presence`, `admit`,
`emit`. All eight are importable.

| Class | Presence |
|-------|----------|
| `local`, `qns`, `operator` | always PRESENT (software) |
| `lan`, `bt` | PRESENT (software). LAN emit fails without a declared link. |
| `plc` | ABSENT without declared `domain` |
| `rf` | ABSENT without declared `profile` |
| `light` | ABSENT without declare. Camera deny is PERM (walk next). |

Device hooks (`bt`, `rf`, camera, emitter) may be mock-backed. The
Protocol is real. Sticky-via is banned — the last success is never the
next default.

**Restriction.** COLD → local only. `always_try` walks `VIA_ORDER`; a
fail / absent / PERM advances to the next class **inside the same
call** (no second API). `force_via` restricted ⇒ **wait** in the
outbox. No silent remap.

**Drops.** `hop_max` (default 8). Loop in `seen`. Pair cut ⇒ no further
emit. APG poison ⇒ **no walk**.

## §9 Light (OCC)

Preamble OOK (`10101010 11110000`) then length, payload, SHA-256 of
payload. Encode / decode roundtrip preserves `photon_id` and the hash.
Bits **without** the preamble are a **probe, not a photon**. Camera
deny is a permanent restriction of that class; the walker continues.

## §10 APG and AZPIPE

APG scans **raw bytes** first. Poison is refused, not interpreted. A
poison refuse stops the walker.

AZPIPE inbound hops (AP-WP-0.2):

```
frag → sweep → fold → static → fold → entry
```

If `foldlock.py` is missing, fld3-wire still folds block-keys and
off-origin URLs, and **fold receipts are skipped**. ChainLock entry
still appends when a receipt is written.

## §11 Chain, receipts, pairs, memorial, policy

Append-only JSONL under `data/chain/`. One receipt leaf per event under
`data/receipts/`. Pair handshake is OFFER / ACCEPT / SEAL (AIH-WP-1.3).
SEAL is medium-independent — it does not require OS BT or Wi-Fi.
`bearer_id` is the path that day, not a marriage license. Memorial
holds living pair-ids until isolate / PHOENIX-LOCK / Scorch / operator
cut. Policy stores `always_try`, `force_via`, `hop_max`; `sticky_via`
refuses (`QNS-STICKY-VIA`).

## §12 Local API

Binds **127.0.0.1 only**. Port from `cfg/node.json` (default **8891**).

| Path | Act |
|------|-----|
| `POST /local/boot` | Install or resume from `data/locks/` |
| `GET /local/state` | Posture (not completeness) |
| `POST /local/policy` | always_try / force_via / operator LIVE |
| `POST /local/declare` | Via declare (plc domain, rf profile, light, lan link) |
| `POST /local/pair` | OFFER / ACCEPT / SEAL / operator cut |
| `POST /local/ingress` | APG + AZPIPE then admit |
| `POST /local/forward` | Walker emit (one call walks classes) |
| `GET /local/outbox` | Visible queue |
| `POST /local/outbox/cut` | Drop one item |
| `GET /local/receipts` | Disk receipts |
| `POST /local/phoenix/arm` | Wait locally |

No `/mesh` enable. No Node Gate. Faces do not proxy this port.

## §13 Laws

- API localhost only
- Sticky-via banned
- SEAL independent of OS BT / Wi-Fi
- Anon-broadcast stays loopback sibling — never a publish path
- Public identity Aziel Eliab only
- GET /v1/mesh never enables
- Suite Workers cite / proxy only
- Not a Softwares-tab product
- No Node Gate

## §14 Tests (ship these)

| # | Law |
|---|-----|
| 1 | All eight vias import + Protocol |
| 2 | COLD walker only local |
| 3 | LIVE + always_try walks lan fail → next class without a second API call |
| 4 | force_via restricted ⇒ wait, no silent remap |
| 5 | Light encode / decode roundtrip + hash |
| 6 | Light without preamble ⇒ probe not photon |
| 7 | Admit bt emit lan ⇒ translate=true same photon_id |
| 8 | APG poison ⇒ no walk |
| 9 | hop_max drop |
| 10 | Loop in seen drop |
| 11 | PLC without domain ⇒ absent |
| 12 | RF without profile ⇒ absent |
| 13 | Camera deny ⇒ perm walk next |
| 14 | Outbox wait survives restart from locks |
| 15 | Pair cut ⇒ no further emit |

File: `tests/test_qnsd.py`. Offline. pytest.

## Cite

Eliab, Aziel. (2026). QNS-CD-1.0 Quantum Node Signal Coding Design
[Software]. Apache-2.0. https://github.com/AzielEliab/qnm-node

Parents: QNS-WP-1.3 · QNM-BUILD-1.0 · AIH-WP-1.3 · APG · AZPIPE ·
ChainLock. Companion print: QNS-CD-1.0.pdf (git-hosted).

Do not invent a DOI.

Apache-2.0. Forks are welcome and always allowed.
