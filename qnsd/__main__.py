"""python -m qnsd — local signal daemon (127.0.0.1 only)."""

from __future__ import annotations

from qnsd.api import main

if __name__ == "__main__":
    raise SystemExit(main())
