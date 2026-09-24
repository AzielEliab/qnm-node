"""Roles on the loopback API.

Admin manages tenants, quotas, relay/discovery/edge opt-in, and multisig.
Admin cannot decrypt another identity's keystore.

Developer submits tasks and joins rollups within quota, and can message.

Guest can message and read the public routes only.

A missing role token on 127.0.0.1 is the host owner (Admin). A presented
token is enforced on every local route. In-process ``handle()`` without
an actor stays the owner path used by the existing local tests.

Author: Aziel Eliab only.
"""

from __future__ import annotations

import json
from typing import Any

from qnm.boot import QNMRefuse

ROLES = ("admin", "developer", "guest")

GUEST_GET = frozenset(
    {
        "/local/state",
        "/local/receipts",
        "/local/outbox",
        "/local/pairs",
        "/local/wires",
        "/local/vault",
        "/local/nolie",
        "/local/fabric",
        "/local/bitmesh",
        "/local/unkillability",
        "/local/channels",
        "/local/phy",
        "/local/planes",
        "/local/surface",
        "/local/redline",
        "/local/fedmesh",
        "/local/design",
    }
)

GUEST_OPS = frozenset(
    {"message", "file", "inbox", "poll", "unlock", "fetch", "trust", "design_status", "mirror_status", "mirror_serve"}
)
DEVELOPER_OPS = GUEST_OPS | frozenset(
    {
        "task",
        "edge",
        "rollup",
        "push_rollup",
        "put",
        "push",
        "share",
        "sync",
        "sign_rollup",
        "airlock_promote",
        "pull_hops",
        "pull_blinds",
        "design_challenge",
        "design_unlock",
        "design_put",
        "design_move",
        "design_preview",
        "design_publish",
        "appeal",
    }
)


class Actor:
    def __init__(self, role: str, handle: str, *, via: str) -> None:
        if role not in ROLES:
            raise QNMRefuse("FED-ROLE", "unknown role")
        self.role = role
        self.handle = handle
        self.via = via

    def as_dict(self) -> dict[str, Any]:
        return {"role": self.role, "handle": self.handle, "via": self.via}


def _op(body: bytes) -> str:
    if not body:
        return ""
    try:
        payload = json.loads(body.decode("utf-8") or "{}")
    except Exception as exc:  # noqa: BLE001
        raise QNMRefuse("FED-ROLE", "role check refused a non-JSON body") from exc
    if not isinstance(payload, dict):
        raise QNMRefuse("FED-ROLE", "role check refused a non-object body")
    return str(payload.get("op") or "")


def authorize(actor: Actor, method: str, route: str, body: bytes = b"") -> None:
    """Refuse when this role cannot call this route. Admin passes."""
    if actor.role == "admin":
        return
    if method == "GET" and route in GUEST_GET:
        return
    if route == "/local/fedmesh" and method == "POST":
        op = _op(body)
        allowed = DEVELOPER_OPS if actor.role == "developer" else GUEST_OPS
        if op in allowed:
            return
    raise QNMRefuse("FED-ROLE", f"{actor.role} cannot {method} {route}")
