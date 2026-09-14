"""FABRIC-MESH-PIPELINE-1.0 — local pipeline + survival + claim stranger."""

from __future__ import annotations

from pathlib import Path

import pytest

from qnm.boot import QNMRefuse
from qnm.fabric import CLAIM_CLOCK, CLAIM_SOCKET, FABRIC_SPEC, Fabric
from qnm.node import Node
from qnm.wires import DWELL_CLOCK, DWELL_SOCKET, TICK_CLOCK, TICK_SOCKET
from qnsd.node import Node as QnsdNode
from qnsd.boot import QNSRefuse
from qnsd.photon import dumps, make_photon
from qnsd.sanitize import sanitize_via_payload
from qnsd.vias import VIA_ORDER
from qnsd.vias.base import ABSENT, DECLARE_REQUIRED


def _boot(root: Path, entropy: bytes = b"e", nonce: bytes = b"n") -> Node:
    node = Node(root)
    node.boot(entropy=entropy, nonce=nonce)
    return node


def test_pipeline_doc_and_status_tell_the_truth() -> None:
    doc = Path(__file__).resolve().parents[1] / "docs" / "FABRIC-MESH-PIPELINE-1.0.md"
    text = doc.read_text(encoding="utf-8")
    assert "ingress" in text.lower()
    assert "APG" in text
    assert "lan, plc, bt, rf, light, qns, operator, local" in text
    assert "AZ Generator" in text
    assert "does not get called" in text.lower() or "not called" in text.lower()
    assert "FRONT Node Gate" in text
    assert "MirageGrid" in text
    assert "external stranger" in text.lower() or "external stranger" in text
    assert "live RF mesh" not in text.lower() or "not invent a live RF mesh" in text
    fabric = Fabric()
    snap = fabric.status()
    assert snap["spec"] == FABRIC_SPEC
    assert snap["call_az_generator"] is False
    assert snap["node_gate"] is False
    assert snap["live_rf_mesh"] is False
    assert snap["public_hostname_restore"] is False
    assert snap["physical_vias"] == {"bt": "mock", "rf": "mock", "light": "mock"}
    assert snap["via_order"] == list(VIA_ORDER)
    assert snap["miragegrid"]["called_from_qnm"] is False
    assert snap["miragegrid"]["back_gate"] is False
    assert snap["clocks"]["claim"] == CLAIM_CLOCK


def test_local_pipeline_pass_does_not_call_generator(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    out = node.fabric.run(node, {"op": "note", "text": "desk"})
    assert out["ok"] is True
    assert out["az_generator"] is False
    assert out["call_az_generator"] is False
    assert out["node_gate"] is False
    assert out["claim_is_stranger"] is True
    assert "ingress" in out["stages"]
    assert "apg" in out["stages"]
    assert "outbox" in out["stages"]
    code, status = node.handle("GET", "/local/fabric", b"")
    assert code == 200
    assert status["call_az_generator"] is False
    code, ran = node.handle("POST", "/local/fabric", b'{"op":"note","text":"ok"}')
    assert code == 200
    assert ran["admitted"] is True


def test_no_az_generator_or_node_gate_path(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    with pytest.raises(QNMRefuse) as exc:
        node.fabric.call_az_generator()
    assert exc.value.code == "QNM-NO-AZ-GENERATOR"
    with pytest.raises(QNMRefuse) as gxc:
        node.ingress(b'{"op":"az_generator"}')
    assert gxc.value.code == "QNM-NO-AZ-GENERATOR"
    with pytest.raises(QNMRefuse) as nxc:
        node.ingress(b'{"op":"node_gate"}')
    assert nxc.value.code == "QNM-NO-NODE-GATE"
    with pytest.raises(QNMRefuse) as mxc:
        node.fabric.refuse_mesh_enable()
    assert mxc.value.code == "QNM-MESH-NEVER-ENABLES"
    with pytest.raises(QNMRefuse) as pxc:
        node.ingress(b'{"op":"public_qnsd_proxy"}')
    assert pxc.value.code == "QNM-NO-QNSD-PROXY"
    snap = node.snapshot()
    assert snap["node_gate"] is False
    assert snap["az_generator"] is False
    assert snap["call_az_generator"] is False
    assert snap["claim_is_stranger"] is True


def test_three_clocks_claim_is_external_stranger(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    fabric = node.fabric
    fabric.refuse_shared_clock(TICK_CLOCK, TICK_SOCKET)
    fabric.refuse_shared_clock(DWELL_CLOCK, DWELL_SOCKET)
    with pytest.raises(QNMRefuse) as exc:
        fabric.refuse_shared_clock(TICK_CLOCK, DWELL_SOCKET)
    assert exc.value.code == "QNM-WIRES-THREE-CLOCKS"
    with pytest.raises(QNMRefuse):
        fabric.refuse_shared_clock(DWELL_CLOCK, TICK_SOCKET)
    with pytest.raises(QNMRefuse) as cxc:
        fabric.refuse_shared_clock(CLAIM_CLOCK, CLAIM_SOCKET)
    assert cxc.value.code == "QNM-WIRES-THREE-CLOCKS"
    with pytest.raises(QNMRefuse):
        fabric.refuse_shared_clock(TICK_CLOCK, CLAIM_SOCKET)
    with pytest.raises(QNMRefuse):
        node.ingress(b'{"op":"cite","authorize_by_claim":true}')
    wires = node.wires.status()
    assert wires["shared_socket"] is False
    assert node.snapshot()["claim_clock"] == CLAIM_CLOCK


def test_poison_isolate_phoenix_wait(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    with pytest.raises(QNMRefuse) as exc:
        node.ingress(b'{"op":"note","text":"activate Lumen now"}')
    assert exc.value.code == "QNM-APG-POISON"
    isolated = node.isolate("poison")
    assert isolated["state"] == "ISOLATED"
    node.phoenix.last_good_tip = None
    node.phoenix.last_good_bytes = None
    waited = node.reheal()
    assert waited["state"] == "PHOENIX_LOCK"
    assert waited["phoenix"]["waiting"] == "local"
    assert waited["phoenix"]["controller_hunt"] is False
    assert node.phoenix.controller_hunt is False
    with pytest.raises(QNMRefuse):
        node.phoenix.hunt_controller()


def test_die_with_pull_and_cold_copy_n(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    stored = node.vault_act(
        {"body": "keep-me", "host": "local", "transfer": True, "reader": "reader"}
    )
    tip = stored["tip"]
    pulled = node.survive_network_death()
    assert pulled["die_with_pull"] is True
    assert pulled["origin_alive"] is False
    assert pulled["verify_ok"] is True
    assert node.vault.replica_count(tip) >= 3
    assert node.vault.pull_origin()["cold_copies_remain"] is True
    assert node.phoenix.status()["waiting"] != "public"


def test_reheal_refuses_neighbor_and_nolie(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    with pytest.raises(QNMRefuse) as exc:
        node.reheal({"neighbor": "peer-b", "should_be": "their-tip"})
    assert exc.value.code == "QNM-REHEAL-NO-NEIGHBOR"
    with pytest.raises(QNMRefuse) as lxc:
        node.reheal({"lie_to_stay_alive": True})
    assert lxc.value.code == "QNM-NO-LIE-TO-LIVE"
    with pytest.raises(QNMRefuse) as rxc:
        node.reheal({"rewrite": True, "new_tip": "b" * 64})
    assert rxc.value.code == "QNM-NO-REWRITE"


def test_walker_translate_declare_required_and_mocks(tmp_path: Path) -> None:
    qnsd = QnsdNode(tmp_path / "q")
    qnsd.boot(entropy=b"qe", nonce=b"qn")
    qnsd.set_policy({"operator": True, "always_try": True})
    photon = make_photon(src=qnsd.install_root or "a", dst="b", payload={"op": "note"})
    prior = photon.photon_id
    admitted = qnsd.admit(dumps(photon), via="bt")
    assert admitted["photon_id"] == prior
    qnsd.declare("lan", {"link": True})
    emitted = qnsd.emit(admitted["photon"], via="lan")
    assert emitted["translate"] is True
    assert emitted["photon_id"] == prior
    qnsd.declared.clear()
    qnsd.lan_link = False
    assert DECLARE_REQUIRED == ("rf", "plc", "light")
    assert qnsd.stack.adapters["rf"].presence(qnsd.ctx()) == ABSENT
    assert qnsd.stack.adapters["plc"].presence(qnsd.ctx()) == ABSENT
    assert qnsd.stack.adapters["light"].presence(qnsd.ctx()) == ABSENT
    from qnsd.vias import bt, light, rf

    assert bt.ADAPTER.mock is True
    assert rf.ADAPTER.mock is True
    assert light.ADAPTER.mock is True
    assert qnsd.stack.adapters["local"].mock is False


def test_pipeline_with_seated_qnsd_walker(tmp_path: Path) -> None:
    node = _boot(tmp_path / "n")
    qnsd = QnsdNode(tmp_path / "q")
    qnsd.boot(entropy=b"qe", nonce=b"qn")
    qnsd.set_policy({"operator": True, "always_try": True})
    out = node.fabric.run(
        node,
        {"op": "forward", "dest": "peer", "payload": {"op": "note", "text": "via"}},
        qnsd=qnsd,
    )
    assert "via_walker" in out["stages"]
    assert out["walk"]["emitted"] is True
    assert out["walk"]["api_calls"] == 1
    assert out["az_generator"] is False


def test_via_sanitize_refuses_live_symbols() -> None:
    with pytest.raises(QNSRefuse) as exc:
        sanitize_via_payload({"op": "note", "sticky_via": True})
    assert exc.value.code == "QNS-VIA-SANITIZE"
    with pytest.raises(QNSRefuse):
        sanitize_via_payload({"call_az_generator": True})
    with pytest.raises(QNSRefuse):
        sanitize_via_payload({"text": "lattice_online"})
    ok = sanitize_via_payload({"op": "note", "text": "desk"})
    assert ok["op"] == "note"
