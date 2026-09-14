"""ALL-CHANNELS-ON + persist-across-device + bitmesh-geo-only.

Operator override of fabric posture. Author: Aziel Eliab only.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from qnm.bitmesh import geohash, public_receipt_has_geo, refuse_public_geo
from qnm.boot import QNMRefuse
from qnm.coldcopy import DEVICE_CLASSES
from qnm.fabric import CHANNELS_ON, FABRIC_SPEC
from qnm.unkillability import FIELDED_BAND, TARGET, compute_unkillability
from qnm.node import Node
from qnsd.boot import QNSRefuse
from qnsd.node import Node as QnsdNode
from qnsd.photon import make_photon
from qnsd.sanitize import sanitize_via_payload
from qnsd.vias.base import HOOK_PENDING, PRESENT


def _boot(root: Path) -> Node:
    node = Node(root)
    node.boot(entropy=b"e", nonce=b"n")
    return node


def test_fabric_enable_arms_rf_bt_wifi_photon(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    qnsd = QnsdNode(tmp_path / "q")
    qnsd.boot(entropy=b"qe", nonce=b"qn")
    node.qnsd = qnsd
    assert node.snapshot()["radios"] == "off"
    armed = node.enable_fabric()
    assert armed["spec"] == FABRIC_SPEC
    assert armed["enabled"] is True
    assert armed["radios"] == "armed"
    assert armed["all_channels_on"] is True
    for name in ("rf", "bt", "wifi", "light"):
        assert name in armed["channels_on"]
        assert armed["physical_vias"][name] == "HOOK-PENDING"
    assert armed["photon"] == "REAL"
    assert armed["live_rf_mesh"] is False
    assert armed["live_bt_link"] is False
    assert armed["live_wifi_link"] is False
    assert armed["live_flash"] is False
    assert set(CHANNELS_ON) <= set(armed["channels_on"])
    assert node.bearers.is_on("radio") is True
    assert node.bearers.is_on("wifi") is True
    assert node.bearers.is_on("bt") is True
    assert qnsd.fabric_armed is True
    ctx = qnsd.ctx()
    for name in ("rf", "bt", "wifi", "light", "lan", "plc"):
        assert qnsd.stack.adapters[name].presence(ctx) == PRESENT
    code, status = node.handle("GET", "/local/fabric", b"")
    assert code == 200
    assert status["enabled"] is True
    assert status["call_az_generator"] is False
    kill = node.unkillability()
    assert kill["architecture_score"] >= TARGET
    assert kill["architecture_only"] is True
    assert kill["meets_target"] is False
    assert kill["fielded_score"] <= FIELDED_BAND[1]
    assert kill["score"] == kill["fielded_score"]
    assert kill["label"] == "pissed-off-gov"
    assert kill["real_mock"]["photon"] == "REAL"
    assert kill["real_mock"]["live_rf_mesh"] is False
    for name in ("bt", "rf", "wifi", "light"):
        assert kill["real_mock"]["physical_vias"][name] == "HOOK-PENDING"
    assert armed["unkillability"]["architecture_score"] >= TARGET
    assert armed["unkillability"]["meets_target"] is False


def test_phy_emit_is_hook_pending_not_live_success(tmp_path: Path) -> None:
    qnsd = QnsdNode(tmp_path)
    qnsd.boot(entropy=b"e", nonce=b"n")
    qnsd.arm_fabric()
    photon = make_photon(src=qnsd.install_root or "a", dst="b", payload={"op": "note"})
    for name in ("bt", "rf", "wifi"):
        result = qnsd.stack.adapters[name].emit(photon.to_dict(), qnsd.ctx())
        assert result.ok is False
        assert result.kind == HOOK_PENDING
        assert result.hook_pending is True
        assert result.live_link is False
        assert result.code == "QNS-HOOK-PENDING"
    light = qnsd.stack.adapters["light"].emit(photon.to_dict(), qnsd.ctx())
    assert light.ok is True
    assert light.hook_pending is True
    assert light.live_link is False
    assert light.detail.startswith("light protocol emit")


def test_persist_across_device_class_survives_pull(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    stored = node.vault_act({"body": "carry-me", "host": "local"})
    tip = stored["tip"]
    out = node.persist_transfer({"tip": tip, "prove_pull": True})
    for device in DEVICE_CLASSES:
        assert device in out["devices"]
    assert out["erased"] is False
    assert out["pull_erases_tip"] is False
    assert out["offline_hop_erases_tip"] is False
    assert out["after_pull"]["erased"] is False
    assert out["after_pull"]["cold_copies_remain"] is True
    assert node.vault.replica_count(tip) >= len(DEVICE_CLASSES)
    pulled = node.survive_network_death()
    assert pulled["die_with_pull"] is True
    assert node.vault.replica_count(tip) >= len(DEVICE_CLASSES)
    assert (node.vault.objects / tip).is_file()
    queued = [item for item in node.outbox.list() if item["kind"] == "persist-transfer"]
    assert queued


def test_bitmesh_geo_is_internal_not_public_receipt(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    tip = node.chain.tip
    bound = node.bind_bitmesh({"tip": tip, "lat": 51.5074, "lon": -0.1278})
    assert bound["plane"] == "bitmesh-internal"
    assert bound["public"] is False
    assert bound["act_receipt_geo"] is False
    assert bound["geohash"] == geohash(51.5074, -0.1278)
    assert node.bitmesh.route_token(tip) == bound["geohash"]
    for receipt in node.receipts():
        assert public_receipt_has_geo(receipt) is False
        blob = str(receipt)
        assert "51.5074" not in blob
        assert bound["geohash"] not in blob
        assert "geohash" not in receipt
        assert "lat" not in receipt
        assert "user" not in receipt
    with pytest.raises(QNMRefuse) as exc:
        node.bind_bitmesh({"tip": tip, "lat": 1.0, "lon": 2.0, "public": True})
    assert exc.value.code == "QNM-NO-PUBLIC-GEO"
    with pytest.raises(QNMRefuse) as rxc:
        refuse_public_geo({"op": "note", "geohash": "gcpvj0e5"})
    assert rxc.value.code == "QNM-NO-PUBLIC-GEO"
    with pytest.raises(QNMRefuse):
        node._write_receipt("note", {"lat": 1.0, "lon": 2.0})
    with pytest.raises(QNSRefuse):
        sanitize_via_payload({"op": "note", "lat": 51.5, "lon": -0.1})


def test_mesh_get_never_enables_and_no_az_generator(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    node.enable_fabric()
    for path in ("/v1/mesh", "/mesh", "/v1/mesh/enable"):
        code, payload = node.handle("GET", path, b"")
        assert code == 403
        assert payload["code"] == "QNM-MESH-NEVER-ENABLES"
        assert node.snapshot()["mesh_enable"] is False
    qnsd = QnsdNode(tmp_path / "q")
    qnsd.boot(entropy=b"q", nonce=b"n")
    qnsd.arm_fabric()
    code, payload = qnsd.handle("GET", "/v1/mesh", b"")
    assert code == 403
    assert payload["code"] == "QNM-MESH-NEVER-ENABLES"
    with pytest.raises(QNMRefuse) as exc:
        node.fabric.call_az_generator()
    assert exc.value.code == "QNM-NO-AZ-GENERATOR"
    snap = node.snapshot()
    assert snap["az_generator"] is False
    assert snap["call_az_generator"] is False
    assert snap["node_gate"] is False
    assert "invoke_az_generator(" not in Path(__file__).resolve().parents[1].joinpath(
        "qnm", "fabric.py"
    ).read_text(encoding="utf-8")


def test_architecture_high_fielded_gated_without_b_and_c(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    cold = node.unkillability()
    assert cold["views_read"] is False
    assert cold["az_generator"] is False
    assert cold["live_rf_mesh"] is False
    assert cold["real_mock"]["live_rf_mesh"] is False
    assert cold["planes"]["plane_b"]["doi"] is None
    assert cold["planes"]["plane_c"]["offline_verify"] is False
    assert cold["planes"]["plane_c"]["status"] == "READY"
    assert cold["planes"]["plane_a"]["independent"] is False
    armed = node.enable_fabric()
    kill = armed["unkillability"]
    assert kill["architecture_score"] >= 80
    assert kill["architecture_score"] <= 100
    assert kill["fielded_score"] == 70
    assert kill["score"] == 70
    assert kill["fielded_band"] == [68, 70]
    assert kill["meets_target"] is False
    assert kill["architecture_only"] is True
    assert kill["publish_to_hubs"] is False
    assert kill["hubs_must_not_publish_100"] is True
    kinds = {row["name"]: row["kind"] for row in kill["factors"]}
    assert kinds["photon_real"] == "REAL"
    assert kinds["channels_armed"] == "LAW"
    assert kinds["honest_hooks"] == "LAW"
    assert kinds["no_one_tunnel"] == "LAW"
    assert kill["real_mock"]["physical_vias"]["rf"] == "HOOK-PENDING"
    assert kill["real_mock"]["plane_b_doi"] == "SLOT"
    assert kill["real_mock"]["plane_c_offline_verify"] == "READY"
    with pytest.raises(QNMRefuse) as vxc:
        node.unkillability({"views": 99})
    assert vxc.value.code == "QNM-SCORE-NO-VIEWS"
    with pytest.raises(QNMRefuse) as pxc:
        compute_unkillability(
            fabric_enabled=True,
            persist_devices=True,
            replica_n=6,
            bitmesh_binds=1,
            live_rf_mesh=True,
        )
    assert pxc.value.code == "QNS-HOOK-PENDING"
    code, api = node.handle("GET", "/local/unkillability", b"")
    assert code == 200
    assert api["score"] == api["fielded_score"]
    assert api["meets_target"] is False
    assert api["call_az_generator"] is False
    snap = node.snapshot()["unkillability"]
    assert snap["score"] == 70
    assert snap["architecture_score"] >= 80
    assert snap["meets_target"] is False


def test_fielded_meets_target_only_with_honest_b_and_c(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    node.enable_fabric()
    with pytest.raises(QNMRefuse) as dxc:
        node.planes_act({"op": "doi", "doi": None})
    assert dxc.value.code == "QNM-NO-FAN-DOI"
    with pytest.raises(QNMRefuse):
        node.planes_act({"op": "invent_doi"})
    with pytest.raises(QNMRefuse) as cxc:
        node.planes_act({"op": "verify_c", "body": ""})
    assert cxc.value.code == "QNM-NO-FAN-AIRGAP"
    with pytest.raises(QNMRefuse):
        node.planes_act({"op": "fake_verify"})
    still = node.unkillability()
    assert still["meets_target"] is False
    assert still["planes"]["plane_b"]["doi"] is None
    seated = node.planes_act({"op": "doi", "doi": "10.5281/zenodo.9999999"})
    assert seated["doi"] == "10.5281/zenodo.9999999"
    mid = node.unkillability()
    assert mid["gates"]["plane_b_doi"] is True
    assert mid["meets_target"] is False
    verified = node.planes_act({"op": "verify_c", "body": "usb-airgap-pack"})
    assert verified["offline_verify"] is True
    assert len(verified["pack_tip"]) == 64
    done = node.unkillability()
    assert done["gates"]["fielded_ready"] is True
    assert done["architecture_only"] is False
    assert done["meets_target"] is True
    assert done["fielded_score"] >= TARGET
    assert done["score"] == done["fielded_score"]
    assert done["real_mock"]["plane_b_doi"] == "REAL"
    assert done["real_mock"]["plane_c_offline_verify"] == "REAL"
    assert done["publish_to_hubs"] is False
    assert done["hubs_must_not_publish_100"] is True
    code, planes = node.handle("GET", "/local/planes", b"")
    assert code == 200
    assert planes["gates"]["fielded_ready"] is True


def test_unarmed_radio_still_refuses_until_fabric(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    with pytest.raises(QNMRefuse) as exc:
        node.set_bearer("radio", True)
    assert exc.value.code == "QNM-RADIO-OFF"
    node.enable_fabric()
    armed = node.set_bearer("radio", True)
    assert armed["on"] is True
    assert armed["live_link"] is False
    assert node.snapshot()["fabric"]["live_rf_mesh"] is False
