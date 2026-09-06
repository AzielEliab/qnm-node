# AIH-WP-1.3 — Spiderweb Pair-Bind (medium-independent)

**Author:** Aziel Eliab only
**Companion node law:** [QNM-BUILD-1.0](QNM-BUILD-1.0.md)
**Hub / Interface law (unchanged):** AIH-WP-1.1
**Supersedes:** AIH-WP-1.2 §2.3–§3.3 (one-bearer seal / pair dies with Wi-Fi)
**License:** Apache-2.0
**Date:** September 2026
**Software:** qnm-node 1.1.0

Public identity is **Aziel Eliab** only.

THIS IS NOT Bell-pair physics. No qubit claims.

## §1 Why 1.3

AIH-WP-1.2 sealed a pair to one bearer. When Wi-Fi died, the bind
died with the path.

**1.3 cuts that marriage.** The bind is medium-independent. The bearer
is hop-only.

## §2 pair_id

```
pair_id = SHA256(root_A || root_B || nonce_A || nonce_B)
```

Roots are ordered so both Memorials compute the same id. `pair_id`
lives in both Memorials (`data/witness/pair_memorial.jsonl`) until:

- isolate
- PHOENIX-LOCK
- Scorch
- operator cut

Wi-Fi dying is **not** on that list.

## §3 Handshake (OFFER / ACCEPT / SEAL)

The handshake stays.

1. **OFFER** — `root_A`, `nonce_A`, optional `via`
2. **ACCEPT** — `root_B`, `nonce_B`, optional `via`
3. **SEAL** — both sides write `pair_id`

`bearer_id` on SEAL is the **path that day**, not a marriage license.
`medium_independent` is true. `marriage_license` is false.

## §4 Bearer is hop-only

A frame carries `via`. Any currently enabled declared bearer may carry
the next hop (`local`, `operator`, or `lan` when on). Radio and remote
stay off (QNM-BUILD-1.0).

The pair does not store a required medium.

## §5 Spiderweb

A live node may hold **many** pair-ids.

Forward **A→B→C** only when every hop:

- walks an **existing pair edge**
- **APG** passes (poison refused, not interpreted)
- the hop node is **not** isolated / PHOENIX-LOCK / scorched
- the hop bearer (`via`) is **enabled**

`hop_max` default **8**. Each frame carries a **seen hash list**.
Loops drop (`AIH-LOOP-DROP`). Over-length paths drop (`AIH-HOP-MAX`).

## §6 Path gone is not death

Wi-Fi dies → the **path** is gone. The **bind** remains.

The outbox keeps the frame. Waiting is not death
(`AIH-PATH-WAIT`, `death: false`, `bind_remains: true`).

## §7 Isolation still cuts

Isolation cuts **all** pair edges on that node. PHOENIX-LOCK and Scorch
do the same. Poison and tamper do **not** ride the spiderweb.

Tethers (AIH-WP-1.1 declared corridors) stay a separate ledger.

## §8 Honesty

- Not a VPN, radio mesh, login mesh, or publish path.
- AnonBroadcast is still never a publish path.
- Local API binds **127.0.0.1** only.
- QNM bulletproof law is unchanged (radios off, receipts to disk,
  no auto-heal, no account resurrection, score never reads views).
- AZHub and AZInterface remain separate software (AIH-WP-1.1).

## §9 Local API (added)

`POST /local/pair` · `GET /local/pairs` · `POST /local/forward`

## Cite

Eliab, Aziel. (2026). AIH-WP-1.3 Spiderweb Pair-Bind
[Law]. Companion: QNM-BUILD-1.0. Apache-2.0.
https://github.com/AzielEliab/qnm-node

Do not invent a DOI.
