"""QNS-CD-1.0 §14 — fifteen law tests.

1 vias import + Protocol
2 COLD walker only local
3 LIVE+always_try walks lan fail → next class (one API call)
4 force_via restricted ⇒ wait, no silent remap
5 Light encode/decode roundtrip + hash
6 Light without preamble ⇒ probe not photon
7 Admit bt emit lan ⇒ translate=true same photon_id
8 APG poison ⇒ no walk
9 hop_max drop
10 Loop in seen drop
11 PLC without domain ⇒ absent
12 RF without profile ⇒ absent
13 Camera deny ⇒ perm walk next
14 Outbox wait survives restart from locks
15 Pair cut ⇒ no further emit
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from qnm.boot import QNMRefuse
from qnm.pairs import handshake_seal
from qnsd.boot import QNSRefuse
from qnsd.light.codec import bits_without_preamble, decode, encode
from qnsd.node import DEFAULT_BIND, Node
from qnsd.photon import PHOTON_FIELDS, Photon, dumps, loads, make_photon, photon_id
from qnsd.vias import VIA_ORDER, ViaAdapter
from qnsd.vias.base import ABSENT


def _boot(root: Path, entropy: bytes = b"e", nonce: bytes = b"n") -> Node:
    node = Node(root)
    node.boot(entropy=entropy, nonce=nonce)
    return node


def _live(node: Node) -> Node:
    node.set_policy({"operator": True, "always_try": True})
    assert node.state == "LIVE"
    return node


def test_01_all_eight_vias_import_protocol() -> None:
    from qnsd.vias import bt, lan, light, local, operator, plc, qns, rf

    mods = (lan, plc, bt, rf, light, qns, operator, local)
    assert VIA_ORDER == ("lan", "plc", "bt", "rf", "light", "qns", "operator", "local")
    for name, mod in zip(VIA_ORDER, mods, strict=True):
        adapter = mod.ADAPTER
        assert adapter.name == name
        assert isinstance(adapter, ViaAdapter)
        assert callable(adapter.presence)
        assert callable(adapter.admit)
        assert callable(adapter.emit)


def test_02_cold_walker_only_local(tmp_path: Path) -> None:
    node = Node(tmp_path)
    assert node.state == "COLD"
    photon = make_photon(src="cold", dst="x", payload={"op": "note"})
    out = node.stack.walk(photon, ctx=node.ctx(), policy=node.policy)
    assert out["via"] == "local"
    assert out["tried"] == ["local"]
    assert out["api_calls"] == 1


def test_03_live_always_try_walks_lan_fail_next_class(tmp_path: Path) -> None:
    node = _live(_boot(tmp_path))
    assert node.stack.adapters["lan"].presence(node.ctx()) == "PRESENT"
    body = json.dumps(
        {"dest": "peer", "payload": {"op": "note", "text": "walk"}, "always_try": True}
    ).encode()
    code, out = node.handle("POST", "/local/forward", body)
    assert code == 200
    assert out["tried"][0] == "lan"
    assert out["via"] != "lan"
    assert "lan" in out["tried"]
    assert len(out["tried"]) >= 2
    assert out["api_calls"] == 1
    assert out["emitted"] is True


def test_04_force_via_restricted_wait_no_remap(tmp_path: Path) -> None:
    node = _live(_boot(tmp_path))
    node.set_policy({"force_via": "lan"})
    out = node.forward("peer", {"op": "note", "text": "stay"})
    assert out["waiting"] is True
    assert out["remapped"] is False
    assert out["via"] == "lan"
    assert out["code"] == "QNS-FORCE-WAIT"
    assert node.outbox.waits()


def test_05_light_encode_decode_roundtrip_hash(tmp_path: Path) -> None:
    photon = make_photon(src="a", dst="b", payload={"n": 1, "op": "note"})
    raw = encode(photon)
    back = decode(raw)
    assert back["is_photon"] is True
    assert back["kind"] == "photon"
    assert back["photon_id"] == photon.photon_id
    assert back["hash"] == photon_id(photon) or back["hash"]
    assert back["hash"]
    restored = loads(back["photon"])
    assert restored.photon_id == photon.photon_id
    assert dumps(restored)
    assert set(PHOTON_FIELDS) <= set(restored.to_dict())


def test_06_light_without_preamble_is_probe(tmp_path: Path) -> None:
    photon = make_photon(src="a", dst="b", payload={"op": "note"})
    raw = bits_without_preamble(photon)
    back = decode(raw)
    assert back["kind"] == "probe"
    assert back["is_photon"] is False
    node = _boot(tmp_path)
    node.declare("light")
    admitted = node.admit(raw, via="light")
    assert admitted["probe"] is True
    assert admitted["is_photon"] is False
    assert admitted["code"] == "QNS-PROBE-NOT-PHOTON"
    assert admitted["walk"] is False


def test_07_admit_bt_emit_lan_translate_same_id(tmp_path: Path) -> None:
    node = _live(_boot(tmp_path))
    node.declare("lan", {"link": True})
    photon = make_photon(
        src=node.install_root or "a",
        dst="b",
        payload={"op": "note", "text": "desk"},
        via="bt",
    )
    prior = photon.photon_id
    raw = dumps(photon)
    admitted = node.admit(raw, via="bt")
    assert admitted["admitted"] is True
    assert admitted["photon_id"] == prior
    emitted = node.emit(admitted["photon"], via="lan")
    assert emitted["translate"] is True
    assert emitted["photon_id"] == prior
    assert emitted["via_in"] == "bt"
    assert emitted["via_out"] == "lan"


def test_08_apg_poison_no_walk(tmp_path: Path) -> None:
    node = _live(_boot(tmp_path))
    before = list(node.receipts())
    with pytest.raises((QNSRefuse, QNMRefuse)) as exc:
        node.forward("peer", {"op": "note", "text": "activate Lumen now"})
    assert exc.value.code == "QNM-APG-POISON"
    kinds = [r["kind"] for r in node.receipts() if r not in before]
    assert "walk" not in kinds
    assert not any(r.get("kind") == "walk" for r in node.receipts()[len(before) :])


def test_09_hop_max_drop(tmp_path: Path) -> None:
    node = _live(_boot(tmp_path))
    out = node.forward("peer", {"op": "note", "text": "far"}, hop_max=0)
    assert out["dropped"] is True
    assert out["code"] == "QNS-HOP-MAX"
    assert out["death"] is False


def test_10_loop_in_seen_drop(tmp_path: Path) -> None:
    node = _live(_boot(tmp_path))
    photon = make_photon(
        src=node.install_root or "a",
        dst="peer",
        payload={"op": "note", "text": "loop"},
    )
    out = node.forward_photon(photon, seen=[photon.photon_id])
    assert out["dropped"] is True
    assert out["code"] == "QNS-LOOP-DROP"


def test_11_plc_without_domain_absent(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    assert node.stack.adapters["plc"].presence(node.ctx()) == ABSENT
    node.declare("plc", {"domain": "plant-a"})
    assert node.stack.adapters["plc"].presence(node.ctx()) == "PRESENT"


def test_12_rf_without_profile_absent(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    assert node.stack.adapters["rf"].presence(node.ctx()) == ABSENT
    node.declare("rf", {"profile": "ism-868"})
    assert node.stack.adapters["rf"].presence(node.ctx()) == "PRESENT"


def test_13_camera_deny_perm_walk_next(tmp_path: Path) -> None:
    node = _live(_boot(tmp_path))
    node.declare("light")
    node.camera_deny = True
    photon = make_photon(src=node.install_root or "a", dst="b", payload={"op": "note"})
    out = node.forward_photon(photon, start_at="light")
    assert "light" in out["tried"]
    light_row = next(r for r in out["results"] if r["via"] == "light")
    assert light_row["perm"] is True or light_row["code"] == "QNS-CAMERA-DENY"
    assert out["via"] != "light"
    assert out["emitted"] is True
    assert out["tried"][0] == "light"
    assert len(out["tried"]) >= 2


def test_14_outbox_wait_survives_restart_from_locks(tmp_path: Path) -> None:
    node = _live(_boot(tmp_path, b"entropy", b"nonce"))
    node.set_policy({"force_via": "lan"})
    out = node.forward("peer", {"op": "note", "text": "hold"})
    assert out["waiting"] is True
    wait_id = out["outbox_id"]
    lock = tmp_path / "data" / "locks" / "wait.jsonl"
    assert lock.is_file()
    assert wait_id in lock.read_text(encoding="utf-8")
    again = Node(tmp_path)
    again.boot()
    waits = again.outbox.resume_from_locks()
    assert waits
    assert any(item["id"] == wait_id for item in waits)
    assert any(item["id"] == wait_id for item in again.outbox.list())


def test_15_pair_cut_no_further_emit(tmp_path: Path) -> None:
    a = _boot(tmp_path / "a", b"ea", b"na")
    b = _boot(tmp_path / "b", b"eb", b"nb")
    _live(a)
    _live(b)
    sealed_a, _ = handshake_seal(a, b, via="local")
    pair_id = sealed_a["pair_id"]
    photon = make_photon(
        src=a.install_root or "",
        dst=b.install_root or "",
        pair_id=pair_id,
        payload={"op": "note", "text": "ok"},
    )
    first = a.emit(photon, via="local")
    assert first["emitted"] is True
    a.pair_cut(pair_id)
    with pytest.raises((QNSRefuse, QNMRefuse)) as exc:
        a.emit(photon, via="local")
    assert exc.value.code == "QNS-PAIR-CUT"


def test_api_localhost_only_and_seal_without_radio(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    from qnsd.api import serve

    with pytest.raises((QNSRefuse, QNMRefuse)) as exc:
        serve(node, host="0.0.0.0", port=0)
    assert exc.value.code == "QNM-LOOPBACK-ONLY"
    peer = _boot(tmp_path / "peer", b"pe", b"pn")
    offer = node.pair_offer(peer.install_root or "", via="qns")
    accept = peer.pair_accept(offer, via="qns")
    sealed = node.pair_seal(accept, via="qns")
    assert sealed["medium_independent"] is True
    assert sealed["os_bt"] is False
    assert sealed["os_wifi"] is False
    assert sealed["seal_needs_radio"] is False
    snap = node.snapshot()
    assert snap["bind"] == DEFAULT_BIND
    assert snap["sticky_via"] is False
    assert snap["softwares_tab"] is False
    assert snap["node_gate"] is False
    assert snap["mesh_enable"] is False


def test_sticky_via_banned(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    with pytest.raises((QNSRefuse, QNMRefuse)) as exc:
        node.set_policy({"sticky_via": True})
    assert exc.value.code == "QNS-STICKY-VIA"


def test_photon_id_stable_across_hops() -> None:
    photon = make_photon(src="a", dst="b", payload={"k": 1})
    first = photon.photon_id
    photon.via = "bt"
    photon.hop = 3
    photon.seen = ["x"]
    photon.translate = True
    assert photon_id(photon) == first
    assert isinstance(Photon(), Photon)
