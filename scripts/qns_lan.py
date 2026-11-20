"""LAN operator CLI.

Imports ``qnm`` before ``qnsd``. ``python -m qnsd`` and
``python -m qnsd.lan`` hit a pre-existing import cycle
(``qnsd`` boot ↔ vias). This file does not change that cycle.

``python scripts/qns_lan.py`` puts ``scripts/`` on ``sys.path``, not the
repo root. A fresh clone has no installed package, so the root is
inserted before the imports. ``PYTHONPATH`` is not required.

Usage: ``python scripts/qns_lan.py --data-dir DIR COMMAND``
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_root = str(_REPO_ROOT)
if _root not in sys.path:
    sys.path.insert(0, _root)

import qnm  # noqa: F401  — must load before qnsd

from qnsd.lan.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
