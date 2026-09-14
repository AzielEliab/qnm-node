"""SPLIT-WIRES-1.0 — pull-only payloads, hash-absolute ingest, two clocks."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from qnm.boot import QNMRefuse, sha256_hex
from qnm.node import Node
from qnm.wires import (
    DWELL_S,
    DWELL_CLOCK,
    DWELL_SOCKET,
    TICK_CLOCK,
    TICK_SIZE,
    TICK_SOCKET,
    Wires,
    canonical_hash,
    pack_tick,
)


def _future(seconds: int = DWELL_S) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def test_tick_is_fixed_size_presence_and_tip_only() -> None:
    wires = Wires()
    tip = sha256_hex(b"tip-one")
    frame = pack_tick("desk", tip)
    assert len(frame) == TICK_SIZE
    admitted = wires.admit_tick({"presence": "desk", "tip_hash": tip})
    assert admitted["tip_hash"] == tip
    assert "body" not in admitted
    with pytest.raises(QNMRefuse) as exc:
        wires.admit_tick({"presence": "desk", "tip_hash": tip, "body": "nope"})
    assert exc.value.code == "QNM-WIRES-TICK-PLANE"
    with pytest.raises(QNMRefuse):
        wires.admit_tick({"presence": "desk", "tip_hash": tip, "diff": "x"})
    with pytest.raises(QNMRefuse):
        wires.admit_tick({"presence": "desk", "tip_hash": tip, "file": "x"})
    with pytest.raises(QNMRefuse):
        wires.admit_tick(b"not-a-tick-frame-and-not-fixed")


def test_payload_is_pull_only_never_push() -> None:
    wires = Wires()
    body = b'{"kind":"note"}'
    tip = wires.store_for_pull(body)
    pulled = wires.pull_payload(tip)
    assert pulled["plane"] == "payload"
    assert pulled["pushed"] is False
    assert pulled["verified"] is True
    with pytest.raises(QNMRefuse) as exc:
        wires.push_payload(body)
    assert exc.value.code == "QNM-WIRES-PULL-ONLY"


def test_cite_is_proof_not_a_timer() -> None:
    wires = Wires()
    prev = wires.held_prev
    tip = sha256_hex(b"next-tip")
    cited = wires.cite(prev=prev, tip=tip, peer="a")
    assert cited["cited"] is True
    assert cited["applied"] is False
    assert cited["dwell_is_timer_to_take_whatever"] is False
    too_soon = wires.apply_cited()
    assert too_soon["applied"] is False
    other = sha256_hex(b"whatever-arrived")
    with pytest.raises(QNMRefuse) as exc:
        wires.apply_cited(now=_future(), arrived_tip=other)
    assert exc.value.code == "QNM-WIRES-DWELL-CITE"
    applied = wires.apply_cited(now=_future())
    assert applied["applied"] is True
    assert applied["tip"] == tip
    assert wires.lockset.holds(tip)


def test_clock_desync_is_not_a_yes() -> None:
    wires = Wires()
    with pytest.raises(QNMRefuse) as exc:
        wires.cite(
            prev=wires.held_prev,
            tip=sha256_hex(b"clocked"),
            authorize_by_clock=True,
        )
    assert exc.value.code == "QNM-WIRES-CLOCK-DESYNC"
    with pytest.raises(QNMRefuse):
        wires.time_is_not_authorization(authorize_by_clock=True)


def test_ambiguous_tip_isolates_not_merge() -> None:
    wires = Wires()
    a = sha256_hex(b"a")
    b = sha256_hex(b"b")
    out = wires.isolate_ambiguous("peer-x", [a, b])
    assert out["isolated"] is True
    assert out["merged"] is False
    assert wires.peers["peer-x"].status == "isolated"


def test_equivocation_ends_the_peer_not_the_chain() -> None:
    wires = Wires()
    prev = "0" * 64
    t1 = sha256_hex(b"one")
    t2 = sha256_hex(b"two")
    first = wires.note_peer_tip("n1", prev, t1)
    assert first["ok"] is True
    second = wires.note_peer_tip("n1", prev, t2)
    assert second["code"] == "QNM-WIRES-EQUIVOCATION"
    assert second["chain_ends"] is False
    assert second["vote_to_reconcile"] is False
    assert wires.peers["n1"].status == "locked"
    with pytest.raises(QNMRefuse) as exc:
        wires.quorum_cannot_outvote(t2, votes=99, broken=True)
    assert exc.value.code == "QNM-WIRES-HASH-ABSOLUTE"


def test_emit_last_and_no_unsend(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    emitted = node.emit_tip()
    assert emitted["verified"] is True
    assert emitted["body"] is False
    assert len(bytes.fromhex(emitted["tick"])) == TICK_SIZE
    with pytest.raises(QNMRefuse) as exc:
        node.wires.unsend(emitted)
    assert exc.value.code == "QNM-WIRES-NO-UNSEND"
    with pytest.raises(QNMRefuse):
        node.wires.leave_box({"body": True, "verified": False})


def test_neighbor_does_not_phoenix(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    with pytest.raises(QNMRefuse) as exc:
        node.wires.neighbor_phoenix("other")
    assert exc.value.code == "QNM-PHOENIX-LOCAL-WAIT"
    assert node.state != "PHOENIX_LOCK"
    node.arm_phoenix()
    assert node.state == "PHOENIX_LOCK"
    assert node.phoenix.status()["waiting"] == "local"


def test_partition_no_autosplice_rejoin_is_cite(tmp_path: Path) -> None:
    wires = Wires(tmp_path)
    genesis = wires.held_prev
    a = sha256_hex(b"island-a")
    b = sha256_hex(b"island-b")
    wires.keep_island("east", a)
    wires.keep_island("west", b)
    with pytest.raises(QNMRefuse) as exc:
        wires.splice("east", "west")
    assert exc.value.code == "QNM-WIRES-NO-SPLICE"
    with pytest.raises(QNMRefuse) as rxc:
        wires.rejoin(prev=genesis, tip=sha256_hex(b"rejoin"))
    assert rxc.value.code == "QNM-WIRES-REJOIN-CITE"
    out = wires.rejoin(prev=genesis, tip=sha256_hex(b"rejoin"), operator=True)
    assert out["cited"] is True


def test_heartbeat_loss_is_not_poison_or_apply() -> None:
    wires = Wires()
    one = wires.heartbeat_miss("n2")
    two = wires.heartbeat_miss("n2")
    three = wires.heartbeat_miss("n2")
    assert one["poison"] is False
    assert two["applied_last_packet"] is False
    assert three["suspect"] is True
    assert three["poison"] is False
    with pytest.raises(QNMRefuse) as exc:
        wires.apply_last_on_heartbeat_loss("n2")
    assert exc.value.code == "QNM-WIRES-HEARTBEAT"


def test_two_clocks_never_share_a_socket() -> None:
    wires = Wires()
    wires.refuse_shared_socket(TICK_CLOCK, TICK_SOCKET)
    wires.refuse_shared_socket(DWELL_CLOCK, DWELL_SOCKET)
    with pytest.raises(QNMRefuse) as exc:
        wires.refuse_shared_socket(TICK_CLOCK, DWELL_SOCKET)
    assert exc.value.code == "QNM-WIRES-TWO-CLOCKS"
    with pytest.raises(QNMRefuse):
        wires.refuse_shared_socket(DWELL_CLOCK, TICK_SOCKET)


def test_fail_closed_bad_prev_or_lockset() -> None:
    wires = Wires()
    tip = sha256_hex(b"x")
    with pytest.raises(QNMRefuse) as exc:
        wires.cite(prev=sha256_hex(b"wrong-prev"), tip=tip)
    assert exc.value.code == "QNM-WIRES-FAIL-CLOSED"
    with pytest.raises(QNMRefuse):
        wires.cite(prev=wires.held_prev, tip=tip, lockset=wires.lockset.__class__.from_iterable([]))


def test_node_api_tick_cite_emit(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    tip = sha256_hex(b"api-tip")
    code, tick = node.handle(
        "POST",
        "/local/tick",
        ('{"presence":"desk","tip_hash":"%s"}' % tip).encode(),
    )
    assert code == 200
    assert tick["tip_hash"] == tip
    code, cited = node.handle(
        "POST",
        "/local/cite",
        (
            '{"prev":"%s","tip":"%s"}'
            % (node.wires.held_prev, sha256_hex(b"cited-api"))
        ).encode(),
    )
    assert code == 200
    assert cited["cited"] is True
    code, emitted = node.handle("POST", "/local/emit", b"{}")
    assert code == 200
    assert emitted["verified"] is True
    code, status = node.handle("GET", "/local/wires", b"")
    assert code == 200
    assert status["dwell_s"] == DWELL_S
    assert status["shared_socket"] is False
    assert status["majority_is_truth"] is False


def test_canonical_hash_fail_closed() -> None:
    with pytest.raises(QNMRefuse):
        canonical_hash("not-hex")
    with pytest.raises(QNMRefuse):
        canonical_hash("abcd")
