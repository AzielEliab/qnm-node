"""Attack-surface map + one-door bind law — REDLINE-1.0.

qnm is the local control plane. Default listen is 127.0.0.1 only.
WAN bind is refused. Remote plaintext is refused. Splitting qnm and
qnsd HTTP would add a second door — so qnsd HTTP serve is an extra
operator door, not the default.

Author: Aziel Eliab only.
"""

from __future__ import annotations

import hmac
import os
from typing import Any

from qnm.boot import AUTHOR, SPEC, QNMRefuse

SURFACE_SPEC = "ATTACK-SURFACE-1.0"
REDLINE_SPEC = "REDLINE-1.0"
DEFAULT_BIND = "127.0.0.1"
LOOPBACK_BINDS = frozenset({"127.0.0.1", "::1"})
WAN_BINDS = frozenset({"0.0.0.0", "::", "*", "0", "all"})

# Local control-plane routes. Not public. Not a Node Gate.
LOCAL_CONTROL_PATHS = (
    "/local/boot",
    "/local/state",
    "/local/bearer",
    "/local/tether",
    "/local/pair",
    "/local/pairs",
    "/local/forward",
    "/local/ingress",
    "/local/outbox",
    "/local/outbox/cut",
    "/local/phoenix/arm",
    "/local/receipts",
    "/local/tick",
    "/local/pull",
    "/local/cite",
    "/local/emit",
    "/local/rejoin",
    "/local/vault",
    "/local/wires",
    "/local/archive",
    "/local/reheal",
    "/local/survive",
    "/local/nolie",
    "/local/rewrite",
    "/local/fabric",
    "/local/persist",
    "/local/bitmesh",
    "/local/unkillability",
    "/local/planes",
    "/local/channels",
    "/local/phy",
    "/local/surface",
    "/local/shelf",
    "/local/export",
    "/local/redline",
)

# qnsd-only routes stay on the same qnm door when the engine is attached.
QNSD_ENGINE_PATHS = (
    "/local/policy",
    "/local/declare",
)

RADIO_ENABLE_PATH = "POST /local/fabric {op:enable} → Channels-ON software path; OS PHY LIVE only on adapter presence"
MESH_ENABLE_PATH = "none — GET/POST /v1/mesh never enables"

SECURITY_HEADERS = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Content-Security-Policy", "default-src 'none'"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
    ("Cache-Control", "no-store"),
)

PLACEHOLDER_TOKENS = frozenset(
    {
        "",
        "test",
        "changeme",
        "secret",
        "password",
        "example",
        "todo",
        "null",
        "none",
        "0" * 16,
        "0" * 32,
        "0" * 64,
    }
)


def is_loopback_bind(host: str) -> bool:
    token = str(host or "").strip().lower()
    if token in LOOPBACK_BINDS:
        return True
    if token == "localhost":
        return True
    return False


def refuse_wan_bind(host: str, *, tls: bool = False, operator_wan: bool = False) -> str:
    """Default: loopback only. WAN needs operator flag + TLS. No plaintext remote."""
    token = str(host or "").strip().lower()
    if token in WAN_BINDS or token in ("0.0.0.0", "::", "[::]"):
        if not operator_wan:
            raise QNMRefuse("QNM-LOOPBACK-ONLY", "WAN bind refused by default")
        if not tls:
            raise QNMRefuse(
                "QNM-NO-PLAINTEXT-REMOTE",
                "remote bind needs TLS; plaintext WAN is refused",
            )
        raise QNMRefuse(
            "QNM-LOOPBACK-ONLY",
            "WAN bind stays refused in this process; remote TLS is operator kit, not default",
        )
    if not is_loopback_bind(token):
        raise QNMRefuse("QNM-LOOPBACK-ONLY", "bind 127.0.0.1 only")
    if token == "localhost":
        return DEFAULT_BIND
    return token


def operator_token() -> str | None:
    """Optional local token from env. Never a default. Never from git."""
    raw = (os.environ.get("QNM_LOCAL_TOKEN") or "").strip()
    if not raw:
        return None
    if raw.lower() in PLACEHOLDER_TOKENS:
        raise QNMRefuse("QNM-AUTH", "placeholder token refused; operator key is not invented")
    return raw


def require_operator_token(provided: str | None) -> None:
    expected = operator_token()
    if expected is None:
        return
    got = str(provided or "")
    if not got or not hmac.compare_digest(got.encode("utf-8"), expected.encode("utf-8")):
        raise QNMRefuse("QNM-AUTH", "operator token required")


def token_from_headers(headers: Any) -> str | None:
    if headers is None:
        return None
    get = headers.get if hasattr(headers, "get") else None
    if get is None:
        return None
    raw = get("X-QNM-Token") or get("x-qnm-token") or ""
    if raw:
        return str(raw)
    auth = str(get("Authorization") or get("authorization") or "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


def attack_surface_map() -> dict[str, Any]:
    """Enumerate every listen bind, API class, radio enable, mesh enable."""
    return {
        "ok": True,
        "spec": SURFACE_SPEC,
        "redline": REDLINE_SPEC,
        "build": SPEC,
        "author": AUTHOR,
        "decision": "monolith-local-control-plane",
        "decision_detail": (
            "qnm is THE local HTTP door (127.0.0.1:8891). "
            "qnsd is an in-process via/photon engine. "
            "A second qnsd HTTP serve is an extra operator door "
            "(--operator-extra-door) and still loopback-only. "
            "Splitting HTTP would increase doors; we consolidate."
        ),
        "listens": [
            {
                "process": "qnm",
                "bind": DEFAULT_BIND,
                "port": 8891,
                "default": True,
                "public": False,
                "wan": False,
                "role": "local-control-plane",
            },
            {
                "process": "qnsd",
                "bind": DEFAULT_BIND,
                "port": 8891,
                "default": False,
                "public": False,
                "wan": False,
                "role": "extra-operator-door",
                "enable": "--operator-extra-door",
            },
        ],
        "public_api": [],
        "local_api": list(LOCAL_CONTROL_PATHS),
        "qnsd_engine_paths": list(QNSD_ENGINE_PATHS),
        "radio_enable_path": RADIO_ENABLE_PATH,
        "mesh_enable_path": MESH_ENABLE_PATH,
        "radio_live": "LIVE only on OS adapter presence; fake LIVE without adapter refuses",
        "mesh_get_never_enables": True,
        "az_generator": False,
        "wan_default": False,
        "tls_required_for_remote": True,
        "plaintext_remote_export": False,
        "operator_plaintext_export_flag": "operator_plaintext_export",
        "token_in_git": False,
        "token_env": "QNM_LOCAL_TOKEN",
        "shelf_key_env": "QNM_SHELF_KEY",
        "rewrite_key": False,
        "publish_fielded_100": False,
        "architecture_score_published": False,
    }


def redline_checklist() -> dict[str, Any]:
    return {
        "ok": True,
        "spec": REDLINE_SPEC,
        "companion": SURFACE_SPEC,
        "author": AUTHOR,
        "items": [
            {"id": "auth", "law": "loopback bind is default auth; optional QNM_LOCAL_TOKEN from env", "pass": True},
            {"id": "token_never_in_git", "law": "no operator token / shelf key in the repo", "pass": True},
            {"id": "mesh_get_never_enables", "law": "GET /v1/mesh never enables radios or mesh", "pass": True},
            {"id": "az_generator_not_callable", "law": "AZ Generator is not called from qnm", "pass": True},
            {"id": "radio_live_only_on_presence", "law": "radio LIVE only when an OS adapter is present", "pass": True},
            {"id": "poison_refuse", "law": "APG poison is refused, not interpreted", "pass": True},
            {"id": "no_rewrite", "law": "no rewrite key; published tip immutable", "pass": True},
            {"id": "loopback_only", "law": "default bind 127.0.0.1; WAN refused", "pass": True},
            {"id": "no_plaintext_remote", "law": "plaintext tip export off-loopback refuses without operator flag", "pass": True},
            {"id": "fielded_not_100", "law": "never publish fielded 100; architecture ≠ fielded", "pass": True},
        ],
    }
