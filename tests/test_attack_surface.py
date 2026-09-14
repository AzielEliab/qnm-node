"""Attack-surface checklist — FABRIC-MESH-PIPELINE-1.0."""

from __future__ import annotations

from pathlib import Path

import pytest

from qnm.apg import MAX_INGRESS_BYTES, APG
from qnm.boot import FORBIDDEN_LIVE_SYMBOLS, QNMRefuse
from qnm.node import DEFAULT_BIND, Node, serve
from qnsd.boot import QNSRefuse
from qnsd.node import Node as QnsdNode
from qnsd.photon import make_photon
from qnsd.vias import VIA_ORDER


def _boot(root: Path) -> Node:
    node = Node(root)
    node.boot(entropy=b"e", nonce=b"n")
    return node


def test_remote_bearer_stays_off(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    assert node.bearers.is_on("remote") is False
    with pytest.raises(QNMRefuse) as exc:
        node.set_bearer("remote", True)
    assert exc.value.code == "QNM-BEARER-OFF"
    assert node.bearers.snapshot()["remote"] is False


def test_radio_enable_refused(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    with pytest.raises(QNMRefuse) as exc:
        node.set_bearer("radio", True)
    assert exc.value.code == "QNM-RADIO-OFF"
    assert node.snapshot()["radios"] == "off"


def test_loopback_bind_only(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    with pytest.raises(QNMRefuse) as exc:
        serve(node, host="0.0.0.0", port=0)
    assert exc.value.code == "QNM-LOOPBACK-ONLY"
    assert node.snapshot()["bind"] == DEFAULT_BIND
    qnsd = QnsdNode(tmp_path / "q")
    from qnsd.api import serve as qnsd_serve

    with pytest.raises((QNSRefuse, QNMRefuse)) as qxc:
        qnsd_serve(qnsd, host="0.0.0.0", port=0)
    assert qxc.value.code == "QNM-LOOPBACK-ONLY"


def test_apg_size_and_marker_refuse() -> None:
    apg = APG()
    with pytest.raises(QNMRefuse) as exc:
        apg.scan_raw(b"x" * (MAX_INGRESS_BYTES + 1))
    assert exc.value.code == "QNM-APG-POISON"
    assert "too large" in exc.value.detail
    for marker in (
        b"Lumen",
        b"Mandible",
        b"lattice_online",
        b"mesh_complete",
        b"controller_hunt",
        b"anon-broadcast/publish",
    ):
        with pytest.raises(QNMRefuse) as mxc:
            APG().scan_raw(marker)
        assert mxc.value.code == "QNM-APG-POISON"
        assert mxc.value.as_dict().get("interpreted") is not True


def test_forbidden_live_symbols_never_success(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    snap = node.snapshot()
    for symbol in FORBIDDEN_LIVE_SYMBOLS:
        assert snap.get("state") != symbol
        assert symbol not in (snap.get("bearers") or {})
    with pytest.raises(QNMRefuse) as exc:
        node.ingress(b'{"op":"mesh_complete"}')
    assert exc.value.code == "QNM-APG-POISON"
    cfg = Path(__file__).resolve().parents[1] / "cfg" / "node.json"
    text = cfg.read_text(encoding="utf-8")
    for symbol in FORBIDDEN_LIVE_SYMBOLS:
        assert symbol in text
    assert '"az_generator": false' in text
    assert '"call_az_generator": false' in text
    assert '"public_qnsd_proxy": false' in text


def test_mesh_get_never_enables(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    for path in ("/v1/mesh", "/mesh", "/v1/mesh/enable"):
        code, payload = node.handle("GET", path, b"")
        assert code == 403
        assert payload["code"] == "QNM-MESH-NEVER-ENABLES"
        assert node.snapshot()["mesh_enable"] is False
    qnsd = QnsdNode(tmp_path / "q")
    qnsd.boot(entropy=b"q", nonce=b"n")
    code, payload = qnsd.handle("GET", "/v1/mesh", b"")
    assert code == 403
    assert payload["code"] == "QNM-MESH-NEVER-ENABLES"


def test_hop_max_and_seen_loop_and_sticky(tmp_path: Path) -> None:
    qnsd = QnsdNode(tmp_path)
    qnsd.boot(entropy=b"e", nonce=b"n")
    qnsd.set_policy({"operator": True, "always_try": True})
    dropped = qnsd.forward("peer", {"op": "note", "text": "far"}, hop_max=0)
    assert dropped["dropped"] is True
    assert dropped["code"] == "QNS-HOP-MAX"
    photon = make_photon(
        src=qnsd.install_root or "a",
        dst="peer",
        payload={"op": "note", "text": "loop"},
    )
    looped = qnsd.forward_photon(photon, seen=[photon.photon_id])
    assert looped["code"] == "QNS-LOOP-DROP"
    with pytest.raises((QNSRefuse, QNMRefuse)) as exc:
        qnsd.set_policy({"sticky_via": True})
    assert exc.value.code == "QNS-STICKY-VIA"


def test_via_payload_sanitize_and_no_public_proxy(tmp_path: Path) -> None:
    qnsd = QnsdNode(tmp_path)
    qnsd.boot(entropy=b"e", nonce=b"n")
    qnsd.set_policy({"operator": True, "always_try": True})
    with pytest.raises(QNSRefuse) as exc:
        qnsd.forward("peer", {"op": "note", "sticky_via": True})
    assert exc.value.code == "QNS-VIA-SANITIZE"
    with pytest.raises(QNSRefuse):
        qnsd.forward("peer", {"op": "note", "node_gate": True})
    node = _boot(tmp_path / "n")
    with pytest.raises(QNMRefuse) as pxc:
        node.fabric.refuse_public_qnsd_proxy()
    assert pxc.value.code == "QNM-NO-QNSD-PROXY"
    assert VIA_ORDER[0] == "lan"


def test_source_has_no_lumen_success_or_generator_call() -> None:
    root = Path(__file__).resolve().parents[1]
    banned = (
        'state = "lattice_online"',
        'state = "mesh_complete"',
        "bell_pair = True",
        "qubit = True",
        "invoke_az_generator(",
        "http://az-generator",
        "https://az-generator",
    )
    files = list((root / "qnm").rglob("*.py")) + list((root / "qnsd").rglob("*.py"))
    for path in files:
        text = path.read_text(encoding="utf-8")
        for token in banned:
            assert token not in text, f"{path} contains {token}"
    fabric = (root / "qnm" / "fabric.py").read_text(encoding="utf-8")
    assert "def refuse_az_generator" in fabric
    assert "called_from_qnm" in fabric
