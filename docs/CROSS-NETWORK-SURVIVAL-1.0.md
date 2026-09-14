# CROSS-NETWORK-SURVIVAL-1.0

**Author:** Aziel Eliab only
**Umbrella for:** [SPLIT-WIRES-1.0](SPLIT-WIRES-1.0.md) · [COLD-COPY-1.0](COLD-COPY-1.0.md) · [RE-EXPAND-1.0](RE-EXPAND-1.0.md) · [REHEAL-1.0](REHEAL-1.0.md)
**Companion:** [QNM-BUILD-1.0](QNM-BUILD-1.0.md)
**License:** Apache-2.0
**Date:** September 2026

Public identity is **Aziel Eliab** only.

Keep die-with-the-pull. Phoenix is still local wait / re-seal — not
public hostname restore.

## Locked mandate

If the public network and live data die tomorrow, the **chain still
survives**.

Survival is not a live replica set and not a neighbor vote. It is:

- **Cold copies** — N named replicas; pulling origin / Worker / DNS
  does not erase them.
- **Archive re-expand** — bytes of the chain, not summaries; verify +
  a new local node on that tip.
- **Self-reheal** — own last good tip + verified pull of bytes already
  trusted, or phoenix-WAIT. Not listening to neighbors.

The local node **must keep verifying and appending offline**. The mesh
**does not need the public network to preserve tips**.

Refuse any act that makes tip preservation depend on a live Worker,
public hostname, live body sync, or neighbor fanfic.

## Close tests

- After origin/Worker/DNS pull: chain verify + append still succeed.
- `require_public_network` / `require_live_data` refused
  (`QNM-SURVIVE-OFFLINE`).
- Archive pack still holds chain bytes after the pull.
- Last-good bytes remain locally for reheal.

Specified 2026-09-14. Author: Aziel Eliab only.
