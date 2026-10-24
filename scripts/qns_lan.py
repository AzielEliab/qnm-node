"""LAN operator CLI.

Imports ``qnm`` before ``qnsd``. ``python -m qnsd`` and
``python -m qnsd.lan`` hit a pre-existing import cycle
(``qnsd`` boot ↔ vias). This file does not change that cycle.

Usage: ``python scripts/qns_lan.py --data-dir DIR COMMAND``
"""

from __future__ import annotations

import sys

import qnm  # noqa: F401  — must load before qnsd

from qnsd.lan.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
