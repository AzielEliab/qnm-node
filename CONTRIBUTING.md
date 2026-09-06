# Contributing to qnm-node

**Forks are first-class.** Apache-2.0. You do not need permission to
fork, patch, or redistribute.

**Forks are welcome and always allowed.**

## How to run tests

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest -q
```

Python 3.10+. Core is stdlib only. pytest is the dev extra. No network.

## Ground rules (QNM-BUILD-1.0)

1. **Identity is Aziel Eliab only.**
2. Radios stay off. Local API binds 127.0.0.1 only.
3. Receipts go to disk. Chain is append-only.
4. Poison is refused, not interpreted (APG).
5. Tamper isolates. No auto-heal.
6. PHOENIX-LOCK waits locally. No controller hunt.
7. Tethers drop clean. No auto-rewire.
8. No account resurrection.
9. AnonBroadcast is never a publish path.
10. No Lumen / Mandible live symbols. No `lattice_online` / `mesh_complete`.
11. Score never reads views.
12. New behavior needs a §14 test that fails without the change.

## License of contributions

By submitting a change you agree it is licensed under Apache-2.0.
Author: Aziel Eliab only.
