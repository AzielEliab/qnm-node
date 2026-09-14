"""§15 SPLIT THE WIRES.

Tick is presence + tip only. Payload is receiver-pull. Update is a
proof, not a timer. Equivocation locks the peer. Phoenix is local
WAIT for the failed node only. Partition does not auto-splice.
Author: Aziel Eliab only.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from qnm.apg import APG
from qnm.boot import QNMRefuse
from qnm.node import Node
from qnm.wires import (
    CITE_SOCKET,
    DWELL_S,
    TICK_BYTES,
    TICK_SOCKET,
    Wires,
    decode_tick,
    encode_tick,
)

PREV = "0" * 64
TIP_A = "a" * 64
TIP_B = "b" * 64


def _lockset(tip: str = TIP_A) -> dict[str, str]:
    return {"lock": "L1", "prev": PREV, "tip": tip}


def _booted(tmp_path: Path) -> Node:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    return node


def test_tick_fixed_size_presence_and_tip_only() -> None:
    frame = encode_tick(True, "peer-1", TIP_A)
    assert len(frame) == TICK_BYTES
    decoded = decode_tick(frame)
    assert decoded["presence"] is True
    assert decoded["tip"] == TIP_A
    with pytest.raises(QNMRefuse) as exc:
        decode_tick(frame[:-1] + b"X")
    assert exc.value.code == "QNM-WIRES-TICK"


def test_tick_refuses_body_diff_file(tmp_path: Path) -> None:
    wires = Wires(tmp_path)
    with pytest.raises(QNMRefuse) as exc:
        wires.tick(peer="p", tip=TIP_A, extra={"body": "nope"})
    assert exc.value.code == "QNM-WIRES-TICK"
    assert "no body/diff/file" in exc.value.detail
    node = _booted(tmp_path / "n")
    with pytest.raises(QNMRefuse) as exc2:
        node.tick(extra={"diff": "x"})
    assert exc2.value.code == "QNM-WIRES-TICK"


def test_payload_is_receiver_pull_never_fanout(tmp_path: Path) -> None:
    node = _booted(tmp_path)
    stashed = node.stash_payload({"note": "pull-me"})
    pulled = node.pull_payload(stashed["id"])
    assert pulled["pulled"] is True
    assert pulled["pushed"] is False
    assert pulled["body"]["note"] == "pull-me"
    with pytest.raises(QNMRefuse) as exc:
        node.fanout_push({"note": "nope"})
    assert exc.value.code == "QNM-WIRES-NO-PUSH"
    assert "PULLS" in exc.value.detail
    with pytest.raises(QNMRefuse) as exc2:
        node.queue_outbox("fanout-push", {"text": "nope"})
    assert exc2.value.code == "QNM-WIRES-NO-PUSH"


def test_cite_is_proof_not_timer_and_777_is_dwell(tmp_path: Path) -> None:
    wires = Wires(tmp_path, now=lambda: 0.0)
    rec = wires.cite(prev=PREV, tip=TIP_A, lockset=_lockset(), peer="p1", now=0.0)
    assert rec["verified"] is True
    assert rec["accepted"] is True
    assert rec["wait_then_accept"] is False
    assert rec["dwell_s"] == DWELL_S
    early = wires.apply_cited(rec["id"], now=1.0)
    assert early["dwelling"] is True
    assert early["applied"] is False
    later = wires.apply_cited(rec["id"], now=float(DWELL_S))
    assert later["applied"] is True
    with pytest.raises(QNMRefuse) as exc:
        wires.wait_then_accept(777)
    assert exc.value.code == "QNM-WIRES-PROOF"
    assert "not wait-then-accept" in exc.value.detail


def test_cite_fail_closed_and_clock_desync_is_not_yes(tmp_path: Path) -> None:
    wires = Wires(tmp_path)
    with pytest.raises(QNMRefuse) as exc:
        wires.cite(prev=PREV, tip=TIP_A, lockset={}, peer="p")
    assert exc.value.code == "QNM-WIRES-PROOF"
    with pytest.raises(QNMRefuse) as exc2:
        wires.cite(
            prev=PREV,
            tip=TIP_A,
            lockset={"lock": "L1", "hash_ok": False},
            peer="p",
        )
    assert exc2.value.code == "QNM-WIRES-PROOF"
    with pytest.raises(QNMRefuse) as exc3:
        wires.cite(
            prev=PREV,
            tip=TIP_A,
            lockset=_lockset(),
            peer="p",
            clock_skew_s=31,
        )
    assert exc3.value.code == "QNM-WIRES-CLOCK"
    assert "clock desync ≠ yes" in exc3.value.detail


def test_equivocation_locks_peer_no_vote_no_quorum(tmp_path: Path) -> None:
    node = _booted(tmp_path)
    node.cite_update(prev=PREV, tip=TIP_A, lockset=_lockset(TIP_A), peer="peer-x")
    with pytest.raises(QNMRefuse) as exc:
        node.cite_update(prev=PREV, tip=TIP_B, lockset=_lockset(TIP_B), peer="peer-x")
    assert exc.value.code == "QNM-WIRES-EQUIVOCATION"
    assert "peer-x" in node.wires.locked_peers
    assert node.state == "LOCAL"
    assert node.phoenix.armed is False
    with pytest.raises(QNMRefuse) as exc2:
        node.wires.vote_reconcile(votes=3)
    assert exc2.value.code == "QNM-WIRES-EQUIVOCATION"
    with pytest.raises(QNMRefuse) as exc3:
        node.wires.quorum_override(votes=99)
    assert exc3.value.code == "QNM-WIRES-QUORUM"
    assert "cannot outvote a broken hash" in exc3.value.detail


def test_ambiguous_tip_isolates_not_merge(tmp_path: Path) -> None:
    node = _booted(tmp_path)
    with pytest.raises(QNMRefuse) as exc:
        node.merge_tips(TIP_A, TIP_B)
    assert exc.value.code == "QNM-WIRES-AMBIGUOUS"
    assert node.state == "ISOLATED"


def test_emit_last_after_own_verify_and_no_unsend(tmp_path: Path) -> None:
    node = _booted(tmp_path)
    rec = node.announce_tip()
    assert rec["fixed"] is True
    assert rec["body"] is False
    with pytest.raises(QNMRefuse) as exc:
        node.wires.announce(peer="p", tip=TIP_A, verified=False)
    assert exc.value.code == "QNM-WIRES-EMIT-LAST"
    with pytest.raises(QNMRefuse) as exc2:
        node.wires.unsend({"body": "unverified"})
    assert exc2.value.code == "QNM-WIRES-NO-UNSEND"


def test_neighbor_does_not_phoenix(tmp_path: Path) -> None:
    node = _booted(tmp_path)
    with pytest.raises(QNMRefuse) as exc:
        node.neighbor_phoenix("other-root")
    assert exc.value.code == "QNM-PHOENIX-LOCAL-WAIT"
    assert "neighbors do not phoenix" in exc.value.detail
    assert node.state == "LOCAL"
    assert node.phoenix.armed is False


def test_self_equivocation_phoenix_is_local_wait_only(tmp_path: Path) -> None:
    node = _booted(tmp_path)
    me = node.install_root or ""
    node.cite_update(prev=PREV, tip=TIP_A, lockset=_lockset(TIP_A), peer=me)
    with pytest.raises(QNMRefuse) as exc:
        node.cite_update(prev=PREV, tip=TIP_B, lockset=_lockset(TIP_B), peer=me)
    assert exc.value.code == "QNM-WIRES-EQUIVOCATION"
    assert node.state == "PHOENIX_LOCK"
    assert node.phoenix.status()["waiting"] == "local"
    assert node.phoenix.status()["public_restore"] is False


def test_partition_no_autosplice_rejoin_needs_cite_and_operator(tmp_path: Path) -> None:
    node = _booted(tmp_path)
    with pytest.raises(QNMRefuse) as exc:
        node.splice_chains(TIP_B)
    assert exc.value.code == "QNM-WIRES-NO-SPLICE"
    with pytest.raises(QNMRefuse) as exc2:
        node.rejoin_partition(
            prev=PREV,
            tip=TIP_A,
            lockset=_lockset(),
            peer="p",
            operator=False,
        )
    assert exc2.value.code == "QNM-WIRES-REJOIN"
    rec = node.rejoin_partition(
        prev=PREV,
        tip=TIP_A,
        lockset=_lockset(),
        peer="p",
        operator=True,
        now=0.0,
    )
    assert rec["rejoin"] is True
    assert rec["verified"] is True


def test_heartbeat_loss_is_not_poison_or_apply(tmp_path: Path) -> None:
    node = _booted(tmp_path)
    rec = node.heartbeat_miss("peer-z", misses=3)
    assert rec["suspect"] is True
    assert rec["poison"] is False
    assert rec["applied"] is False
    assert rec["isolate"] is False
    assert rec["phoenix"] is False
    assert node.state == "LOCAL"
    with pytest.raises(QNMRefuse) as exc:
        node.wires.apply_last_on_heartbeat_loss()
    assert exc.value.code == "QNM-WIRES-HEARTBEAT"
    with pytest.raises(QNMRefuse) as exc2:
        node.wires.poison_on_heartbeat_loss()
    assert exc2.value.code == "QNM-WIRES-HEARTBEAT"


def test_tick_and_cite_never_share_a_socket(tmp_path: Path) -> None:
    wires = Wires(tmp_path)
    assert wires.tick_socket != wires.cite_socket
    with pytest.raises(QNMRefuse) as exc:
        wires.bind_sockets("shared", "shared")
    assert exc.value.code == "QNM-WIRES-SPLIT"
    with pytest.raises(QNMRefuse) as exc2:
        wires.send(CITE_SOCKET, "tick", peer="p", tip=TIP_A)
    assert exc2.value.code == "QNM-WIRES-SPLIT"
    with pytest.raises(QNMRefuse) as exc3:
        wires.send(TICK_SOCKET, "cite", prev=PREV, tip=TIP_A)
    assert exc3.value.code == "QNM-WIRES-SPLIT"
    with pytest.raises(QNMRefuse) as exc4:
        wires.cite(prev=PREV, tip=TIP_A, lockset=_lockset(), peer="p", socket=TICK_SOCKET)
    assert exc4.value.code == "QNM-WIRES-SPLIT"


def test_api_tick_cite_pull(tmp_path: Path) -> None:
    node = _booted(tmp_path)
    code, tick = node.handle("POST", "/local/tick", b"{}")
    assert code == 200
    assert tick["bytes"] == TICK_BYTES
    assert tick["body"] is False
    stash = node.stash_payload({"k": 1})
    import json

    code, pulled = node.handle(
        "POST",
        "/local/payload/pull",
        json.dumps({"id": stash["id"]}).encode(),
    )
    assert code == 200
    assert pulled["pulled"] is True
    code, cited = node.handle(
        "POST",
        "/local/cite",
        json.dumps(
            {"prev": PREV, "tip": TIP_A, "lockset": _lockset(), "peer": "api-peer"}
        ).encode(),
    )
    assert code == 200
    assert cited["verified"] is True


def test_apg_refuses_fanout_and_vote_markers() -> None:
    apg = APG()
    for marker in (b"fanout_push", b"vote_reconcile", b"auto_splice"):
        with pytest.raises(QNMRefuse) as exc:
            apg.scan_raw(marker)
        assert exc.value.code == "QNM-APG-POISON"


def test_snapshot_exposes_split_wires(tmp_path: Path) -> None:
    node = _booted(tmp_path)
    snap = node.snapshot()
    assert snap["wires"]["split"] is True
    assert snap["wires"]["tick_socket"] == TICK_SOCKET
    assert snap["wires"]["cite_socket"] == CITE_SOCKET
    assert snap["wires"]["dwell_s"] == DWELL_S
