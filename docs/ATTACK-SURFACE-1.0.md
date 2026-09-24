# ATTACK-SURFACE-1.0

**Author:** Aziel Eliab only
**Date:** 2026-09-14
**Software:** qnm-node 1.6.0
**Companion:** [REDLINE-1.0](REDLINE-1.0.md)
**License:** Apache-2.0

Public identity is **Aziel Eliab** only.

## Listen binds

| Process | Bind | Port | Default | Public | Role |
| --- | --- | --- | --- | --- | --- |
| `qnm` | `127.0.0.1` | 8891 | **yes** | no | local control plane |
| `qnsd` | `127.0.0.1` | 8891 | **no** (`--operator-extra-door`) | no | extra operator door |

WAN (`0.0.0.0`, `::`, `*`) refuses. `localhost` is remapped to
`127.0.0.1`. Remote TLS is operator kit, not a default listen.

## Public vs local API

**Public API:** none. Faces do not proxy this port.

**Local API:** `/local/*` only (see `qnm.surface.LOCAL_CONTROL_PATHS`).
Unknown paths refuse (`QNM-LOOPBACK-ONLY`). Mesh routes are not local
and never enable.

## Radio enable path

```
POST /local/fabric  { "op": "enable" }
  → Channels-ON software path
  → OS PHY LIVE only when an adapter is present (RADIO-PHY-1.0)
  → emit without hardware = RADIO-NO-* / QNS-RADIO-NOT-LIVE
```

`POST /local/bearer { "name": "radio", "on": true }` still refuses
until fabric enable (`QNM-RADIO-OFF`). Fabric enable does **not**
invent PRESENT.

## Mesh enable path

**None.** `GET` / `POST` `/v1/mesh`, `/mesh`, `/v1/mesh/enable`,
`/v1/mesh?enable=1` return `QNM-MESH-NEVER-ENABLES` and do not change
bearers or radios.

`/v1/fedmesh/*` and `/local/fedmesh` are a different prefix. They share
this same 127.0.0.1 listener. Relay hosting, direct inbox, LAN UDP
discovery, and edge compute are off until an Admin POST. `GET
/v1/fedmesh/health` and `GET /local/fedmesh` do not flip those flags.
There is no WAN listen and no NAT traversal. LAN discovery UDP binds
127.0.0.1 by default. Bluetooth remains an opt-in PHY bearer and is
not a mesh transport. See [FED-MESH-1.0](FED-MESH-1.0.md).

## Monolith-or-split decision

**Consolidate.** Two HTTP servers on the same loopback port is a
second door. qnm is THE listen. qnsd stays an engine (photon / vias /
AZPIPE). `python -m qnsd serve` is opt-in extra door, still
127.0.0.1-only.

## Encrypt / TLS

- Cold-shelf tip packs: operator key (`QNM_SHELF_KEY`). No key in git.
- Wrap: `hmac-sha256-ctr` (stdlib, honest) or AES-256-GCM when
  `cryptography` is installed.
- Local plaintext under `data/archive/` is allowed.
- Non-local plaintext export refuses without
  `operator_plaintext_export` and TLS (`QNM-NO-PLAINTEXT-REMOTE`).

## FoldLock

Sister product on FragGate (`foldlock`, digest
`1034d5924b88878918986abe260338b0aff0117bc6f9c4d4a01a41d843cfa0a8`).
In-repo: fld3-wire. Engine SLOT unless `foldlock.py` exists. Do not
invent FoldLock.

## Scores

`architecture_score` may be high. `fielded_score` / `score` is the
hub-safe number (68–70 until Plane B hash-verified shelf + Plane C
attest). Never publish fielded 100.

`GET /local/surface` returns this map as JSON.

Specified 2026-09-14. Author: Aziel Eliab only.
