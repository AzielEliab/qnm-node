# SPLIT-WIRES-1.0

**Author:** Aziel Eliab only
**Companion:** [COLD-COPY-1.0](COLD-COPY-1.0.md) · [QNM-BUILD-1.0](QNM-BUILD-1.0.md)
**License:** Apache-2.0
**Date:** September 2026

Public identity is **Aziel Eliab** only.

Phoenix wait / re-seal and public-surface **die-with-the-pull** stay as
already locked on main. This paper does not restore a hostname.

## Locked law

### Split the wires

- Fast **0.5–1s** tick: **presence + tip hash only**. Fixed-size. **No
  body, no diff, no file** on that plane.
- Payload lives on a **second plane the receiver PULLS** — never a push
  the sender fans out.

### Update is a proof, not a timer

- Receiver already holds **prev** and the **lockset**.
- New tip must **cite that prev**, **match lockset**, **verify
  fail-closed**.
- **777s** is **dwell after a valid cite** — not “wait then take
  whatever arrived.”
- **Clock desync is not a yes.** Ambiguous tip is **isolate, not merge**.

### Equivocation ends the peer, not the chain

- Same prev, two different tips from one node → that node
  **locked / isolated**. No vote-to-reconcile.
- Quorum cannot outvote a broken hash. **Majority is not truth.**

### Emit last, locally

- Announce tip only after **own verify** passes.
- Phoenix is **local** reboot / WAIT for the failed node. Neighbors do
  **not** phoenix because a neighbor phoenix’d. Phoenix does not restore
  a public hostname. Public tunnels and sites **die with the pull**.
- **No unsend** — nothing leaving the box is an unverified body.

### Partition rules

- Split brain: each island keeps its own chain; **no auto-splice** on
  reconnect.
- Rejoin is **cite + human/operator or lockset gate**, same as first
  ingest.
- Heartbeat loss ≠ poison. Heartbeat loss ≠ apply last packet.

### Short version

Pull-only payloads. Hash-absolute ingest. Equivocation = death of that
peer. Two clocks that never share a socket. The **1s loop** and the
**777s gate** stay strangers.

## Close tests

- Tick plane refuses body / diff / file and is fixed-size.
- Push payload refused (`QNM-WIRES-PULL-ONLY`).
- Cite fail-closed on wrong prev or missing lockset.
- 777s dwell will not apply a different tip that arrived during wait.
- Clock-as-authorization refused.
- Ambiguous tip isolates; does not merge.
- Equivocation locks the peer; chain continues; quorum cannot outvote.
- Emit refused until local verify passes. Unsend refused.
- Neighbor phoenix refused. Local phoenix remains wait / re-seal.
- Splice refused. Rejoin without cite + operator/lockset refused.
- Three missed heartbeats = suspect, not poison, not apply.

Specified 2026-09-14. Author: Aziel Eliab only.
