# REHEAL-1.0

**Author:** Aziel Eliab only
**Companion:** [SPLIT-WIRES-1.0](SPLIT-WIRES-1.0.md) · [RE-EXPAND-1.0](RE-EXPAND-1.0.md) · [QNM-BUILD-1.0](QNM-BUILD-1.0.md)
**License:** Apache-2.0
**Date:** September 2026

Public identity is **Aziel Eliab** only.

Keep split-the-wires, cold-copy, re-expand, and die-with-the-pull.

## Locked law

A poisoned node heals from **its own last good tip** plus a **verified
pull of bytes it already trusted** — or it **phoenix-WAITs**.

- It does **not** heal by listening to neighbors.
- Allowed chatter: `live` / `locked` / `isolated` / `tip-hash`.
- Forbidden: bodies, diffs, “here’s what you should be,” vote-to-fix.
- Isolate, **drop tether**, local phoenix. Other nodes **keep their
  chain**.
- **No majority fanfic reheal.** Quorum cannot outvote a broken hash.

`heal()` stays refused (`QNM-NO-AUTO-HEAL`). That is not this path.
`reheal()` is the named local act. Phoenix remains wait / re-seal on
this machine — not public hostname restore.

## Close tests

- After poison: isolate drops tethers; reheal restores own last good
  bytes; a neighbor’s tip is unchanged.
- Neighbor / should-be / vote-to-fix refused.
- Chatter admits only status + tip-hash.
- Missing trusted bytes → PHOENIX-LOCK local wait.

Specified 2026-09-14. Author: Aziel Eliab only.
