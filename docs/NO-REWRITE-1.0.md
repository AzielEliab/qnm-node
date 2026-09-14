# NO-REWRITE-1.0

**Author:** Aziel Eliab only
**Companion:** [NO-LIE-1.0](NO-LIE-1.0.md) · [COLD-COPY-1.0](COLD-COPY-1.0.md) · [QNM-BUILD-1.0](QNM-BUILD-1.0.md)
**License:** Apache-2.0
**Date:** September 2026

Public identity is **Aziel Eliab** only.

Keep no-lie, split-the-wires, cold-copy, and die-with-the-pull.

## Locked law

### No rewrite key

There is **no rewrite key**. No operator, admin, or identity key
authorizes rewriting a published tip. Aziel Eliab is the author, not a
rewrite authority. `rewrite_key` / `apply_rewrite_key` refuse
(`QNM-NO-REWRITE-KEY`).

### Published tip is immutable

A tip announced after own verify is **published**. `rewrite` /
`mutate` of that tip refuse (`QNM-NO-REWRITE`). Chain and receipts stay
append-only. There is no silent edit that keeps the old hash.

### Copies not all on one tunnel

Replicas must not concentrate on a single tunnel. A tunnel pull must
not erase every copy. `one_tunnel` / `all_on_tunnel` and placing every
replica of a tip on one tunnel host refuse (`QNM-NO-ONE-TUNNEL`).
Named hosts remain; this is not a VPN.

## Close tests

- `rewrite` / `mutate` of a published tip refused.
- `rewrite_key` refused even when the caller is the author identity.
- Chain `rewrite` / `mutate` refused; tip unchanged; receipts still hash.
- Three named replicas refuse concentration onto one tunnel.
- `one_tunnel` / `all_on_tunnel` refused.
- Local + mesh-vault + reader still allowed (not one tunnel).

Specified 2026-09-14. Author: Aziel Eliab only.
