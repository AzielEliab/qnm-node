"""AIH-WP-1.3 — pair survives bearer off; spiderweb forward + APG;
isolated node has no edges; hop_max / loop drop.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from qnm.boot import QNMRefuse
from qnm.node import Node
from qnm.pairs import compute_pair_id, handshake_seal
from qnm.spiderweb import Spiderweb, frame_id


def _boot(root: Path, entropy: bytes, nonce: bytes) -> Node:
    node = Node(root)
    node.boot(entropy=entropy, nonce=nonce)
    return node


def _live_lan(*nodes: Node) -> None:
    for node in nodes:
        node.set_bearer("operator", True)
        node.set_bearer("lan", True)


def test_pair_id_formula_both_memorials(tmp_path: Path) -> None:
    a = _boot(tmp_path / "a", b"entropy-a", b"nonce-a")
    b = _boot(tmp_path / "b", b"entropy-b", b"nonce-b")
    na, nb = b"nA" * 8, b"nB" * 8
    sealed_a, sealed_b = handshake_seal(a, b, via="lan", nonce_a=na, nonce_b=nb)
    expect = compute_pair_id(a.install_root or "", b.install_root or "", na, nb)
    assert sealed_a["pair_id"] == sealed_b["pair_id"] == expect
    assert sealed_a["medium_independent"] is True
    assert sealed_a["marriage_license"] is False
    assert sealed_a["bell_pair"] is False
    assert sealed_a["qubit"] is False
    assert sealed_a["bearer_id"] == "lan"
    disk_a = (tmp_path / "a" / "data" / "witness" / "pair_memorial.jsonl").read_text(
        encoding="utf-8"
    )
    disk_b = (tmp_path / "b" / "data" / "witness" / "pair_memorial.jsonl").read_text(
        encoding="utf-8"
    )
    assert expect in disk_a and expect in disk_b


def test_pair_survives_bearer_off(tmp_path: Path) -> None:
    a = _boot(tmp_path / "a", b"ea", b"na")
    b = _boot(tmp_path / "b", b"eb", b"nb")
    _live_lan(a, b)
    sealed_a, _ = handshake_seal(a, b, via="lan")
    pair_id = sealed_a["pair_id"]
    a.set_bearer("lan", False)
    assert a.bearers.is_on("lan") is False
    assert a.pairs.get(pair_id) is not None
    assert a.pairs.has_edge(b.install_root or "")
    web = Spiderweb()
    web.attach(a)
    web.attach(b)
    out = a.forward(
        b.install_root or "",
        {"op": "note", "text": "desk"},
        via="lan",
        mesh=web,
    )
    assert out["waiting"] is True
    assert out["death"] is False
    assert out["bind_remains"] is True
    assert out["path"] == "gone"
    assert out["code"] == "AIH-PATH-WAIT"
    assert a.outbox.list()
    assert a.pairs.get(pair_id) is not None
    assert pair_id in a.pairs.ids()


def test_forward_along_spiderweb_with_apg(tmp_path: Path) -> None:
    a = _boot(tmp_path / "a", b"ea", b"na")
    b = _boot(tmp_path / "b", b"eb", b"nb")
    c = _boot(tmp_path / "c", b"ec", b"nc")
    _live_lan(a, b, c)
    handshake_seal(a, b, via="lan")
    handshake_seal(b, c, via="lan")
    assert len(b.pairs.list()) == 2
    web = Spiderweb()
    web.attach(a)
    web.attach(b)
    web.attach(c)
    delivered = a.forward(
        c.install_root or "",
        {"op": "note", "text": "along the web"},
        via="lan",
        mesh=web,
    )
    assert delivered["delivered"] is True
    assert delivered["at"] == (c.install_root or "").lower()
    assert delivered["hops"] == 2
    assert delivered["death"] is False
    assert len(delivered["pair_path"]) == 2
    kinds = [r["kind"] for r in a.receipts()]
    assert "spiderweb_hop" in kinds
    assert any(r["kind"] == "spiderweb_deliver" for r in c.receipts())
    with pytest.raises(QNMRefuse) as exc:
        a.forward(
            c.install_root or "",
            {"op": "note", "text": "activate Lumen now"},
            via="lan",
            mesh=web,
        )
    assert exc.value.code == "QNM-APG-POISON"


def test_isolated_node_has_no_edges(tmp_path: Path) -> None:
    a = _boot(tmp_path / "a", b"ea", b"na")
    b = _boot(tmp_path / "b", b"eb", b"nb")
    handshake_seal(a, b, via="local")
    assert a.pairs.list()
    a.isolate("probe")
    assert a.state == "ISOLATED"
    assert a.pairs.list() == []
    assert a.pairs.peers() == set()
    assert a.snapshot()["pairs"] == []
    with pytest.raises(QNMRefuse) as exc:
        a.forward(b.install_root or "", {"op": "note", "text": "no"}, via="local")
    assert exc.value.code == "AIH-NO-EDGES"
    with pytest.raises(QNMRefuse) as exc2:
        a.pair_offer(b.install_root or "")
    assert exc2.value.code == "AIH-NO-EDGES"


def test_hop_max_and_loop_drop(tmp_path: Path) -> None:
    a = _boot(tmp_path / "a", b"ea", b"na")
    b = _boot(tmp_path / "b", b"eb", b"nb")
    c = _boot(tmp_path / "c", b"ec", b"nc")
    _live_lan(a, b, c)
    handshake_seal(a, b, via="lan")
    handshake_seal(b, c, via="lan")
    web = Spiderweb()
    web.attach(a)
    web.attach(b)
    web.attach(c)
    over = a.forward(
        c.install_root or "",
        {"op": "note", "text": "too far"},
        via="lan",
        hop_max=1,
        mesh=web,
    )
    assert over["dropped"] is True
    assert over["code"] == "AIH-HOP-MAX"
    assert over["death"] is False
    loop = a.forward(
        b.install_root or "",
        {"op": "note", "text": "revisit"},
        via="lan",
        mesh=web,
        seen=[(b.install_root or "").lower()],
    )
    assert loop["dropped"] is True
    assert loop["code"] == "AIH-LOOP-DROP"
    fid = frame_id(
        (a.install_root or "").lower(),
        (b.install_root or "").lower(),
        {"op": "note", "text": "seen-hash"},
        "",
    )
    hashed = a.forward(
        b.install_root or "",
        {"op": "note", "text": "seen-hash"},
        via="lan",
        mesh=web,
        seen=[fid],
    )
    assert hashed["dropped"] is True
    assert hashed["code"] == "AIH-LOOP-DROP"


def test_operator_cut_and_phoenix_cut(tmp_path: Path) -> None:
    a = _boot(tmp_path / "a", b"ea", b"na")
    b = _boot(tmp_path / "b", b"eb", b"nb")
    c = _boot(tmp_path / "c", b"ec", b"nc")
    sealed, _ = handshake_seal(a, b, via="local")
    handshake_seal(a, c, via="local")
    assert len(a.pairs.list()) == 2
    a.pair_cut(sealed["pair_id"])
    assert a.pairs.get(sealed["pair_id"]) is None
    assert len(a.pairs.list()) == 1
    a.arm_phoenix()
    assert a.state == "PHOENIX_LOCK"
    assert a.pairs.list() == []


def test_not_bell_pair(tmp_path: Path) -> None:
    a = _boot(tmp_path / "a", b"ea", b"na")
    with pytest.raises(QNMRefuse) as exc:
        a.forward(a.install_root or "", {"op": "entangle", "qubit": True})
    assert exc.value.code == "AIH-NOT-BELL"


def test_api_pair_and_pairs_list(tmp_path: Path) -> None:
    a = _boot(tmp_path / "a", b"ea", b"na")
    b = _boot(tmp_path / "b", b"eb", b"nb")
    code, offer = a.handle(
        "POST",
        "/local/pair",
        (
            '{"op":"offer","peer":"' + (b.install_root or "") + '","via":"local"}'
        ).encode(),
    )
    assert code == 200
    assert offer["phase"] == "OFFER"
    import json

    accept_body = json.dumps({"op": "accept", "offer": offer, "via": "local"}).encode()
    code, accept = b.handle("POST", "/local/pair", accept_body)
    assert code == 200
    seal_body = json.dumps({"op": "seal", "accept": accept, "via": "local"}).encode()
    code, sealed = a.handle("POST", "/local/pair", seal_body)
    assert code == 200
    code, also = b.handle("POST", "/local/pair", seal_body)
    assert code == 200
    assert sealed["pair_id"] == also["pair_id"]
    code, listed = a.handle("GET", "/local/pairs", b"")
    assert code == 200
    assert listed["pairs"]
    assert listed["bell_pair"] is False
    assert listed["spec"] == "AIH-WP-1.3"
