"""Pissed-off-gov unkillability — FABRIC-MESH-PIPELINE-1.0.

How expensive it is to erase the chain if a government pulls the
public origin, seizes one server, jams one medium, or demands a
rewrite / lie.

This is an architecture + copy-cost score. It is **not** a live RF
mesh claim. PHY without a driver stays HOOK-PENDING (MOCK). Photon
codec stays REAL. Score never reads views.

Author: Aziel Eliab only.
"""

from __future__ import annotations

from typing import Any

from qnm.boot import AUTHOR, SPEC, QNMRefuse
from qnm.coldcopy import DEVICE_CLASSES
from qnsd.vias import CHANNELS_ON, PHYSICAL_HOOK

UNKILL_SPEC = "UNKILLABILITY-1.0"
TARGET = 80
MAX_SCORE = 100

# Law that is true of this process even before fabric enable.
_LAW_POINTS = (
    ("die_with_pull", 10, "REAL", "public origin/Worker/DNS pull does not erase copies"),
    ("no_live_sync", 6, "REAL", "refuse live body sync"),
    ("no_rewrite", 6, "REAL", "no rewrite key; published tip immutable"),
    ("no_one_tunnel", 6, "REAL", "copies are not all on one tunnel"),
    ("offline_survive", 8, "REAL", "verify/append without the public network"),
    ("archive_reexpand", 6, "REAL", "bytes of the chain, not summaries"),
    ("self_reheal", 6, "REAL", "own last good tip or phoenix-WAIT"),
    ("public_receipt_no_geo", 4, "REAL", "public receipts stay no user/geo"),
    ("honest_hooks", 6, "LAW", "HOOK-PENDING; no invented live PHY"),
    ("mesh_never_enables", 2, "LAW", "GET /v1/mesh never enables suite radios"),
    ("no_az_generator", 2, "LAW", "AZ Generator is MirageGrid FRONT only"),
)

_FABRIC_POINTS = (
    ("channels_armed", 12, "LAW", "RF/BT/Wi-Fi/photon armed ON (PHY may be MOCK)"),
    ("photon_real", 6, "REAL", "QNS1 codec is real"),
)

def _factor(name: str, points: int, kind: str, detail: str, *, on: bool) -> dict[str, Any]:
    return {
        "name": name,
        "points": points if on else 0,
        "max": points,
        "on": on,
        "kind": kind,
        "detail": detail,
    }


def compute_unkillability(
    *,
    fabric_enabled: bool,
    persist_devices: bool,
    replica_n: int,
    bitmesh_binds: int,
    live_rf_mesh: bool = False,
    live_phy: bool = False,
    views: Any = None,
) -> dict[str, Any]:
    """Score 0–100. Target 80+ when fabric is armed. Never a live-PHY claim."""
    if views is not None:
        raise QNMRefuse("QNM-SCORE-NO-VIEWS", "unkillability never reads views")
    if live_rf_mesh or live_phy:
        raise QNMRefuse(
            "QNS-HOOK-PENDING",
            "unkillability refuses invented live PHY as a score input",
        )

    factors: list[dict[str, Any]] = []
    for name, points, kind, detail in _LAW_POINTS:
        factors.append(_factor(name, points, kind, detail, on=True))
    for name, points, kind, detail in _FABRIC_POINTS:
        on = bool(fabric_enabled)
        factors.append(_factor(name, points, kind, detail, on=on))
    factors.append(
        _factor(
            "device_class_paths",
            8,
            "REAL",
            "laptop/phone/watch/radio/bluetooth vault-on-transfer",
            on=persist_devices,
        )
    )
    factors.append(
        _factor(
            "replicas_n",
            6,
            "REAL",
            "N named cold replicas",
            on=replica_n >= 3,
        )
    )
    factors.append(
        _factor(
            "bitmesh_internal",
            6,
            "REAL",
            "internal geohash plane; not ACT-RECEIPT geo",
            on=bitmesh_binds >= 0 and fabric_enabled,
        )
    )

    value = min(MAX_SCORE, sum(int(row["points"]) for row in factors))
    phy = {name: "HOOK-PENDING" if fabric_enabled else "mock" for name in PHYSICAL_HOOK}
    return {
        "ok": True,
        "score": value,
        "target": TARGET,
        "meets_target": value >= TARGET,
        "label": "pissed-off-gov",
        "spec": UNKILL_SPEC,
        "build": SPEC,
        "author": AUTHOR,
        "factors": factors,
        "real_mock": {
            "photon": "REAL",
            "cold_copy": "REAL",
            "persist_transfer": "REAL" if persist_devices else "READY",
            "bitmesh_geo": "REAL-internal",
            "public_receipt_geo": False,
            "physical_vias": phy,
            "live_rf_mesh": False,
            "live_bt_link": False,
            "live_wifi_link": False,
            "live_flash": False,
        },
        "channels_on": list(CHANNELS_ON) if fabric_enabled else [],
        "device_classes": list(DEVICE_CLASSES),
        "replicas": replica_n,
        "single_server_unkillable": replica_n >= 2,
        "public_pull_unkillable": True,
        "rewrite_unkillable": True,
        "one_medium_jam_unkillable": fabric_enabled,
        "views_read": False,
        "az_generator": False,
        "mesh_enable": False,
        "call_az_generator": False,
        "live_rf_mesh": False,
    }
