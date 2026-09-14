# REDLINE-1.0

**Author:** Aziel Eliab only
**Date:** 2026-09-14
**Software:** qnm-node 1.6.0 · local `qnm` control plane + sibling `qnsd` engine
**Parents:** [ATTACK-SURFACE-1.0](ATTACK-SURFACE-1.0.md) · [RADIO-PHY-1.0](RADIO-PHY-1.0.md) · [FABRIC-MESH-PIPELINE-1.0](FABRIC-MESH-PIPELINE-1.0.md) · [NODE-OPS-1.0](NODE-OPS-1.0.md) · [NO-LIE-1.0](NO-LIE-1.0.md) · [NO-REWRITE-1.0](NO-REWRITE-1.0.md)
**License:** Apache-2.0

Public identity is **Aziel Eliab** only.

NO-LIE / NO-FAN / Lamb Lens Service→Clarity→Peace. This paper is the
written security redline after LIVE radio #12 / shelves preempt.

## Checklist

| # | Redline | Refuse / law |
| --- | --- | --- |
| 1 | **Auth** | Default auth is the 127.0.0.1 bind. Optional `QNM_LOCAL_TOKEN` from the operator environment. Loopback clients without a token when the env is unset. |
| 2 | **Token never in git** | No operator token, shelf key, or rewrite key is committed. Placeholder keys (`test`, `changeme`, `secret`, all-zero) refuse. Env names only: `QNM_LOCAL_TOKEN`, `QNM_SHELF_KEY`, `QNM_SHELF_KEY_FILE`. |
| 3 | **Mesh GET never enables** | `GET` / `POST` `/v1/mesh` (and `/mesh`, `?enable=1`) never enable radios or mesh (`QNM-MESH-NEVER-ENABLES`). |
| 4 | **AZ Generator not callable** | No `call_az_generator` path. `QNM-NO-AZ-GENERATOR`. Node Gate is MirageGrid only. |
| 5 | **Radio LIVE only on presence** | OS PHYs stamp LIVE \| ABSENT \| REFUSED from host probes. Fake LIVE without an adapter refuses (`QNS-RADIO-NOT-LIVE` / `RADIO-NO-*`). Fabric enable does not invent PRESENT. |
| 6 | **Poison refuse** | APG scans raw bytes first. Poison is refused, not interpreted (`QNM-APG-POISON`). |
| 7 | **No rewrite** | No rewrite key. Published tip cannot be mutated (`QNM-NO-REWRITE`). |

Also locked here:

- Default bind **127.0.0.1**. WAN / `0.0.0.0` / `::` refuse (`QNM-LOOPBACK-ONLY`).
- Plaintext tip export over non-local refuses without `operator_plaintext_export` **and** TLS (`QNM-NO-PLAINTEXT-REMOTE`).
- Cold-shelf packs at rest use an **operator key**. No invented key in git. Stdlib wrap is `hmac-sha256-ctr` (honest, not AES). AES-256-GCM only if the optional `cryptography` extra is present.
- FoldLock is a citeable sister (FragGate slug `foldlock`, digest `1034d5924b88878918986abe260338b0aff0117bc6f9c4d4a01a41d843cfa0a8`). In-repo engine is **SLOT** unless `foldlock.py` is importable. Sensitive exports fold via **fld3-wire**. Do not invent a FoldLock engine.
- `architecture_score` ≠ `fielded_score`. Hubs must **not** publish fielded 100 or architecture 100.

## One door

qnm is the local control plane. qnsd is an in-process via/photon engine.
`python -m qnsd serve` is an extra operator door and requires
`--operator-extra-door`. Splitting HTTP would increase doors; this
repo consolidates.

`GET /local/redline` and `GET /local/surface` expose the checklist and
the listen map.

## Attack simulations (CI, no hardware)

File: `tests/test_redline_sim.py`. Each attempt **REFUSES**:

1. Mesh enable via GET
2. Fake LIVE radio without adapter
3. Invented Plane B DOI / URL
4. Unsigned tip restore
5. Neighbor vote-to-fix

ABSENT radio paths must pass on hosts without hardware.

Specified 2026-09-14. Author: Aziel Eliab only.
