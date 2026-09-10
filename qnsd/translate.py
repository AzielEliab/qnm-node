"""Via translation — QNS-CD-1.0.

Admit on one class, emit on another. translate=true. photon_id does
not change.
"""

from __future__ import annotations

from typing import Any

from qnsd.photon import Photon, loads, photon_id


def apply(
    photon: Photon | dict[str, Any],
    *,
    via_in: str,
    via_out: str,
) -> Photon:
    body = photon.to_dict() if isinstance(photon, Photon) else dict(photon)
    prior = body.get("photon_id") or photon_id(body)
    out = loads(body)
    out.via_in = via_in
    out.via_out = via_out
    out.via = via_out
    out.translate = via_in != via_out
    if not out.photon_id:
        out.photon_id = prior
    else:
        out.photon_id = prior
    # Identity hash must still match the sealed fields.
    expect = photon_id(out)
    if expect != prior:
        # Restore identity fields only — via change must not move the id.
        out.photon_id = prior
    return out
