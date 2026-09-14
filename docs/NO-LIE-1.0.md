# NO-LIE-1.0

**Author:** Aziel Eliab only
**Companion:** [NO-REWRITE-1.0](NO-REWRITE-1.0.md) · [REHEAL-1.0](REHEAL-1.0.md) · [QNM-BUILD-1.0](QNM-BUILD-1.0.md)
**License:** Apache-2.0
**Date:** September 2026

Public identity is **Aziel Eliab** only.

Keep split-the-wires, cold-copy, re-expand, reheal, cross-network
survival, and die-with-the-pull.

## Locked law

The network **never lies**. Not to a peer. Not to itself. Not to stay
alive, adapt, or prevent death.

### Receipts that still hash

A receipt is a content-addressed act. Recompute the digest. If it does
not match, the file was rewritten — **refuse**. Do not “heal” by
editing the receipt so the numbers look live.

### Verify-without-voice

Hash is the yes. Voice, testimony, spoken confirm, or “I say this tip
is good” is **not** a yes. `require_voice` / `voice_confirm` refuse
(`QNM-VERIFY-WITHOUT-VOICE`). Verify stays silent and local.

### No lie to stay alive

A heal that would emit a false tip, fake a receipt, or mutate a
published tip so the node looks live is a **lie**. Refuse
(`QNM-NO-LIE-TO-LIVE`). Phoenix-WAIT instead.

Self-preserve, adapt, and prevent-death are **not** exceptions. The
mesh does not lie to itself to survive.

`heal()` stays refused (`QNM-NO-AUTO-HEAL`). `reheal()` remains own
last good tip + trusted pull, or phoenix-WAIT — never a rewritten
story.

## Close tests

- Written receipts recompute to the same digest (`receipts_still_hash`).
- Tampered receipt fails verify; rewrite-receipt refused.
- `require_voice` / `voice_confirm` refused.
- Verify succeeds with hash only — no voice, no testimony.
- `lie_to_stay_alive` / `lie_to_adapt` / `lie_to_prevent_death` refused.
- Reheal cannot fake a tip or mutate a published tip to look healthy.
- Isolate + false emit to look LIVE refused.

Specified 2026-09-14. Author: Aziel Eliab only.
