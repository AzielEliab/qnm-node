"""Pissed-off-gov unkillability — FABRIC-MESH-PIPELINE-1.0.

Architecture score (law + armed channels) is not the fielded score.

Fielded band today is Cap-7 live + OS PHY ABSENT/LIVE facts (~68–70)
until Plane B has a hash-verified shelf (Codeberg / archive.org /
GitFlic) and Plane C has an operator offline-verify / attest receipt.
Zenodo is IP-banned and is **not required**. A format-only DOI is
not a gate. Architecture alone must not claim the fielded target or 100.

Hubs must not publish architecture_score / 100.

OS radios stamp LIVE | ABSENT | REFUSED from real host probes.
Invented live RF mesh is refused. Photon codec stays REAL. Score
never reads views. Plane C attest-before-LIVE: a LIVE adapter fact
is not a fielded suite-LIVE claim.

Author: Aziel Eliab only.
"""

from __future__ import annotations

from typing import Any

from qnm.boot import AUTHOR, SPEC, QNMRefuse
from qnm.coldcopy import DEVICE_CLASSES
from qnm.planes import plane_b_is_verified
from qnsd.vias import CHANNELS_ON, OS_PHY
from qnsd.vias.base import FIELDING_ABSENT, FIELDING_LIVE, FIELDING_OFF

UNKILL_SPEC = "UNKILLABILITY-1.2"
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
    ("honest_hooks", 6, "LAW", "LIVE|ABSENT|REFUSED OS PHYs; no invented live PHY"),
    ("mesh_never_enables", 2, "LAW", "GET /v1/mesh never enables suite radios"),
    ("no_az_generator", 2, "LAW", "AZ Generator is MirageGrid FRONT only"),
)

_FABRIC_POINTS = (
    ("channels_armed", 12, "LAW", "software path ON; OS PHYs LIVE only when adapters present"),
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
    plane_b_verified: bool | None = None,
    plane_c_offline_verify: bool = False,
    planes: dict[str, Any] | None = None,
    gps_driver: bool = False,
    physical_vias: dict[str, str] | None = None,
    os_phy: dict[str, str] | None = None,
    persist_phy: str | None = None,
) -> dict[str, Any]:
    """Architecture and fielded scores. Target 80+ is fielded-only."""
    _ = plane_b_doi
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
            "named-host vault-on-transfer (radio/bluetooth PHY are LIVE or ABSENT)",
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
            "LAW",
            "internal geohash plane; GNSS LIVE or RADIO-NO-GNSS; not ACT-RECEIPT geo",
            on=bool(fabric_enabled),
        )
    )

    architecture = min(MAX_SCORE, sum(int(row["points"]) for row in factors))
    b_ok = bool(plane_b_verified) if plane_b_verified is not None else plane_b_is_verified(planes=planes)
    c_ok = bool(plane_c_offline_verify)
    fielded = FIELDED_ARMED if fabric_enabled else FIELDED_UNARMED
    if b_ok:
        fielded += PLANE_B_POINTS
    if c_ok:
        fielded += PLANE_C_POINTS
    fielded = min(MAX_SCORE, fielded)
    gates = bool(b_ok and c_ok)
    meets = bool(gates and fielded >= TARGET)
    phy = dict(physical_vias or os_phy or {})
    if not phy:
        phy = {name: FIELDING_ABSENT for name in OS_PHY}
        phy["light"] = FIELDING_OFF if not fabric_enabled else FIELDING_ABSENT
    if gps_driver or phy.get("gps") == FIELDING_LIVE:
        geo_fielding = FIELDING_LIVE
    elif bitmesh_binds > 0:
        geo_fielding = FIELDING_ABSENT
    else:
        geo_fielding = FIELDING_OFF
    wifi_bt = {phy.get("wifi"), phy.get("bt")}
    persist_stamp = persist_phy
    if persist_stamp is None:
        if FIELDING_LIVE in wifi_bt:
            persist_stamp = FIELDING_LIVE
        else:
            persist_stamp = FIELDING_ABSENT if fabric_enabled else FIELDING_OFF
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
            "plane_b_verified": b_ok,
            "plane_c_offline_verify": c_ok,
        },
        "zenodo_required": False,
        "zenodo_ip_banned": True,
        "plane_c_attest_before_live": True,
        "gates": {
            "plane_b_doi": False,
            "plane_b_verified": b_ok,
            "plane_c_offline_verify": c_ok,
            "fielded_ready": gates,
            "zenodo_required": False,
            "plane_c_attest_before_live": True,
        },
        "real_mock": {
            "photon": "REAL",
            "photon_channel": FIELDING_ABSENT,
            "cold_copy": "REAL",
            "persist_transfer": "REAL" if persist_devices else "OFF",
            "persist_phy": persist_stamp,
            "bitmesh_geo": geo_fielding,
            "bitmesh_channel": geo_fielding,
            "public_receipt_geo": False,
            "physical_vias": phy,
            "live_rf_mesh": False,
            "live_bt_link": phy.get("bt") == FIELDING_LIVE,
            "live_wifi_link": phy.get("wifi") == FIELDING_LIVE,
            "live_cellular": phy.get("rf") == FIELDING_LIVE or phy.get("cellular") == FIELDING_LIVE,
            "live_gnss": phy.get("gps") == FIELDING_LIVE,
            "live_nfc": phy.get("nfc") == FIELDING_LIVE,
            "live_flash": False,
            "plane_a_independent": False,
            "plane_b_doi": "SLOT",
            "plane_b_shelf": "REAL" if b_ok else "SLOT",
            "plane_c_offline_verify": "REAL" if c_ok else "READY",
        },
        "channels_on": list(CHANNELS_ON) if fabric_enabled else [],
        "channels_on_means": "software path allowed; OS PHYs LIVE|ABSENT|REFUSED",
        "radios_fielded": False,
        "radios_status": FIELDING_ABSENT
        if not any(label == FIELDING_LIVE for label in phy.values())
        else FIELDING_LIVE,
        "device_classes": list(DEVICE_CLASSES),
        "replicas": replica_n,
        "single_server_unkillable": replica_n >= 2,
        "public_pull_unkillable": True,
        "rewrite_unkillable": True,
        "one_medium_jam_unkillable": False,
        "views_read": False,
        "az_generator": False,
        "mesh_enable": False,
        "call_az_generator": False,
        "live_rf_mesh": False,
    }
