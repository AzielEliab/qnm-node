"""FoldLock cite + sensitive-export fold — no invented engine.

FoldLock is a citeable sister on the FragGate door (slug foldlock,
digest 1034d5924b88878918986abe260338b0aff0117bc6f9c4d4a01a41d843cfa0a8).
This repo does not invent a FoldLock engine. In-repo fold is fld3-wire
from qnsd.azpipe (AZPIPE-0.2). If foldlock.py is importable, it is
used; otherwise the cite is SLOT and fld3-wire still folds.

Author: Aziel Eliab only.
"""

from __future__ import annotations

from typing import Any

from qnm.boot import AUTHOR, SPEC


def _azpipe():
    from qnsd.azpipe import fld3_wire, foldlock_available

    return fld3_wire, foldlock_available

FOLD_SPEC = "FOLD-EXPORT-1.0"
FOLDLOCK_SLUG = "foldlock"
FOLDLOCK_DIGEST = "1034d5924b88878918986abe260338b0aff0117bc6f9c4d4a01a41d843cfa0a8"
FOLDLOCK_ONE_LINE = "Algorithmic tether-word suppression on UTF-8 text. Not zip."


def foldlock_cite() -> dict[str, Any]:
    _fld3, available = _azpipe()
    _ = _fld3
    have = available()
    return {
        "slug": FOLDLOCK_SLUG,
        "digest": FOLDLOCK_DIGEST,
        "one_line": FOLDLOCK_ONE_LINE,
        "sister": True,
        "engine_in_repo": have,
        "status": "foldlock.py" if have else "SLOT",
        "teth": "foldlock.py" if have else "fld3-wire",
        "invented": False,
        "spec": FOLD_SPEC,
        "build": SPEC,
        "author": AUTHOR,
    }


def fold_sensitive(payload: dict[str, Any]) -> dict[str, Any]:
    """Fold secrets / off-origin URLs on export. Refuse is APG's job."""
    fld3_wire, _available = _azpipe()
    folded = fld3_wire(dict(payload))
    cite = foldlock_cite()
    return {
        "ok": True,
        "inner": folded,
        "foldlock": cite,
        "teth": cite["teth"],
        "engine": cite["status"],
        "spec": FOLD_SPEC,
        "author": AUTHOR,
    }
