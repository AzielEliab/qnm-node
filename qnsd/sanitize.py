"""Via payload sanitize-refuse — FABRIC-MESH-PIPELINE-1.0 / QNS-CD-1.0.

Refuse-first. Does not rewrite a sealed photon (NO-REWRITE-1.0).
Drops remote-bearer, Node Gate, AZ Generator, mesh-enable, sticky-via,
public qnsd proxy, and forbidden live symbols off the via plane.
"""

from __future__ import annotations

from typing import Any

from qnm.boot import FORBIDDEN_LIVE_SYMBOLS
from qnsd.boot import AUTHOR, SPEC, QNSRefuse

BANNED_KEYS = frozenset(
    {
        "sticky_via",
        "az_generator",
        "call_az_generator",
        "node_gate",
        "mesh_enable",
        "enable_mesh",
        "mesh_complete",
        "lattice_online",
        "lumen",
        "mandible",
        "public_qnsd",
        "qnsd_proxy",
        "public_qnsd_proxy",
        "remote_bearer",
        "rewrite_key",
        "miragegrid_call",
        "back_gate",
        "geohash",
        "lat",
        "lon",
        "latitude",
        "longitude",
        "user",
        "user_id",
        "client_ip",
    }
)

BANNED_VALUES = frozenset(
    s.lower() for s in FORBIDDEN_LIVE_SYMBOLS
) | frozenset(
    {
        "lumen",
        "mandible",
        "lattice_online",
        "mesh_complete",
    }
)


def _walk_strings(obj: Any) -> list[str]:
    found: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            found.append(str(key))
            found.extend(_walk_strings(value))
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            found.extend(_walk_strings(item))
    else:
        found.append(str(obj))
    return found


def sanitize_via_payload(payload: dict[str, Any] | None) -> dict[str, Any]:
    """Refuse a via payload that carries a banned key or live symbol.

    Returns the same mapping on success. Never mutates sealed identity
    fields; callers must refuse rather than rewrite photon_id material.
    """
    body = dict(payload or {})
    keys = {str(key).lower() for key in body}
    if keys & BANNED_KEYS:
        raise QNSRefuse("QNS-VIA-SANITIZE", "via payload refused")
    for token in _walk_strings(body):
        if token.lower() in BANNED_VALUES or token.lower() in BANNED_KEYS:
            raise QNSRefuse("QNS-VIA-SANITIZE", "via payload refused")
    return body


def sanitize_photon(photon: dict[str, Any]) -> dict[str, Any]:
    """Scan hop-carried payload. photon_id fields are not rewritten."""
    inner = photon.get("payload")
    if isinstance(inner, dict):
        sanitize_via_payload(inner)
    else:
        sanitize_via_payload({"payload": inner} if inner not in (None, "") else {})
    hop_keys = {str(key).lower() for key in photon}
    if hop_keys & BANNED_KEYS:
        raise QNSRefuse("QNS-VIA-SANITIZE", "via photon refused")
    return photon


def sanitize_status() -> dict[str, Any]:
    return {
        "ok": True,
        "rewrite": False,
        "public_qnsd_proxy": False,
        "spec": SPEC,
        "author": AUTHOR,
        "banned": sorted(BANNED_KEYS),
    }
