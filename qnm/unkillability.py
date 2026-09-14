"""Pissed-off-gov unkillability — FABRIC-MESH-PIPELINE-1.0.

Architecture score (law + armed channels) is not the fielded score.

Fielded band today is Cap-7 live + MOCK soft-radio hooks (~68–70)
until Plane B has a real Zenodo DOI and Plane C has an operator
offline-verify / attest receipt. Architecture alone must not claim
the fielded target or 100.

Hubs must not publish architecture_score / 100.

This is **not** a live RF mesh claim. Soft RF / BT / Wi-Fi / photon /
bitmesh stay **MOCK** until real PHY is fielded. Photon codec stays
REAL. Score never reads views.

Author: Aziel Eliab only.
"""

from __future__ import annotations

from typing import Any

from qnm.boot import AUTHOR, SPEC, QNMRefuse
from qnm.coldcopy import DEVICE_CLASSES
from qnm.planes import valid_zenodo_doi
from qnsd.vias import CHANNELS_ON, MOCK, physical_via_stamps

UNKILL_SPEC = "UNKILLABILITY-1.1"
TARGET = 80
MAX_SCORE = 100
FIELDED_BAND = (68, 70)
FIELDED_UNARMED = 68
FIELDED_ARMED = 70
PLANE_B_POINTS = 8
PLANE_C_POINTS = 8

# Law that is true of this process even before fabric enable.
_LAW_POINTS = (
    ("die_with_pull", 10, "REAL", "public origin/Worker/DNS pull does not erase copies"),
    ("no_live_sync", 6, "REAL", "refuse live body sync"),
    ("no_rewrite", 6, "REAL", "no rewrite key; published tip immutable"),
    ("no_one_tunnel", 6, "LAW", "law forbids one-tunnel copies; Plane A is same-CF-tunnel today"),
    ("offline_survive", 8, "REAL", "verify/append without the public network"),
    ("archive_reexpand", 6, "REAL", "bytes of the chain, not summaries"),
    ("self_reheal", 6, "REAL", "own last good tip or phoenix-WAIT"),
    ("public_receipt_no_geo", 4, "REAL", "public receipts stay no user/geo"),
    ("honest_hooks", 6, "LAW", "MOCK; no invented live PHY"),
    ("mesh_never_enables", 2, "LAW", "GET /v1/mesh never enables suite radios"),
    ("no_az_generator", 2, "LAW", "AZ Generator is MirageGrid FRONT only"),
)

_FABRIC_POINTS = (
    ("channels_armed", 12, "LAW", "software path ON; not fielded radios (MOCK)"),
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
    plane_b_doi: str | None = None,
    plane_c_offline_verify: bool = False,
    planes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Architecture and fielded scores. Target 80+ is fielded-only."""
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

    architecture = min(MAX_SCORE, sum(int(row["points"]) for row in factors))
    doi_ok = valid_zenodo_doi(plane_b_doi)
    c_ok = bool(plane_c_offline_verify)
    fielded = FIELDED_ARMED if fabric_enabled else FIELDED_UNARMED
    if doi_ok:
        fielded += PLANE_B_POINTS
    if c_ok:
        fielded += PLANE_C_POINTS
    fielded = min(MAX_SCORE, fielded)
    gates = bool(doi_ok and c_ok)
    meets = bool(gates and fielded >= TARGET)
    phy = physical_via_stamps()
    band = list(FIELDED_BAND) if not gates else [fielded, fielded]
    return {
        "ok": True,
        "score": fielded,
        "architecture_score": architecture,
        "architecture_only": not gates,
        "fielded_score": fielded,
        "fielded_band": band,
        "fielded_band_default": list(FIELDED_BAND),
        "target": TARGET,
        "meets_target": meets,
        "publish_to_hubs": False,
        "hubs_must_not_publish_100": True,
        "hubs_must_not_publish_architecture": True,
        "label": "pissed-off-gov",
        "spec": UNKILL_SPEC,
        "build": SPEC,
        "author": AUTHOR,
        "factors": factors,
        "planes": planes
        or {
            "plane_b_doi": plane_b_doi,
            "plane_c_offline_verify": c_ok,
        },
        "gates": {
            "plane_b_doi": doi_ok,
            "plane_c_offline_verify": c_ok,
            "fielded_ready": gates,
        },
        "real_mock": {
            "photon": "REAL",
            "photon_channel": MOCK,
            "cold_copy": "REAL",
            "persist_transfer": "REAL" if persist_devices else "READY",
            "bitmesh_geo": MOCK,
            "bitmesh_channel": MOCK,
            "public_receipt_geo": False,
            "physical_vias": phy,
            "live_rf_mesh": False,
            "live_bt_link": False,
            "live_wifi_link": False,
            "live_flash": False,
            "plane_a_independent": False,
            "plane_b_doi": "REAL" if doi_ok else "SLOT",
            "plane_c_offline_verify": "REAL" if c_ok else "READY",
        },
        "channels_on": list(CHANNELS_ON) if fabric_enabled else [],
        "channels_on_means": "software path allowed; not fielded PHY",
        "radios_fielded": False,
        "radios_status": MOCK,
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
