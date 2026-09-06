"""QNM-S local score — QNM-BUILD-1.0 §12.

Score never reads views. Downloads, rankings, and site pings are not
inputs. Only local chain integrity and posture.
"""

from __future__ import annotations

from typing import Any, Mapping

from qnm.boot import AUTHOR, SPEC, QNMRefuse


def score_local(
    *,
    chain_ok: bool,
    chain_length: int,
    isolated: bool,
    phoenix: bool,
    scorched: bool,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if extra and "views" in extra:
        raise QNMRefuse("QNM-SCORE-NO-VIEWS", "score never reads views")
    if extra:
        for banned in ("downloads", "ranking", "lattice_online", "mesh_complete"):
            if banned in extra:
                raise QNMRefuse("QNM-SCORE-NO-VIEWS", f"score refuses {banned}")
    if scorched:
        value = 0
        posture = "SCORCHED"
    elif phoenix:
        value = 1
        posture = "PHOENIX_LOCK"
    elif isolated:
        value = 2
        posture = "ISOLATED"
    elif not chain_ok:
        value = 3
        posture = "DEGRADED"
    else:
        value = min(100, 10 + int(chain_length))
        posture = "LOCAL"
    return {
        "ok": True,
        "score": value,
        "posture": posture,
        "views_read": False,
        "inputs": {
            "chain_ok": chain_ok,
            "chain_length": chain_length,
            "isolated": isolated,
            "phoenix": phoenix,
            "scorched": scorched,
        },
        "spec": SPEC,
        "author": AUTHOR,
    }
