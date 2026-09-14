"""REHEAL-1.0 — own last good tip + trusted pull, or phoenix-WAIT."""

from __future__ import annotations

from pathlib import Path

import pytest

from qnm.boot import QNMRefuse
from qnm.node import Node


def test_reheal_from_own_last_good_not_neighbor(tmp_path: Path) -> None:
    poisoned = Node(tmp_path / "a")
    other = Node(tmp_path / "b")
    poisoned.boot(entropy=b"a", nonce=b"a")
    other.boot(entropy=b"b", nonce=b"b")
    poisoned.declare_tether("a", "b")
    last = poisoned.phoenix.last_good_tip
    other_tip = other.chain.tip
    chain = tmp_path / "a" / "data" / "chain" / "node.jsonl"
    chain.write_text(chain.read_text(encoding="utf-8").replace('"boot"', '"BOOT"'), encoding="utf-8")
    poisoned.chain._load()
    poisoned.isolate("poison")
    assert poisoned.state == "ISOLATED"
    assert poisoned.tethers.list() == []
    out = poisoned.reheal()
    assert out["reheal"]["healed"] is True
    assert out["reheal"]["from"] == "own-last-good"
    assert out["reheal"]["neighbor"] is False
    assert out["reheal"]["majority"] is False
    assert poisoned.chain.verify()["ok"] is True
    assert last in {poisoned.phoenix.last_good_tip, poisoned.chain.tip}
    assert other.chain.tip == other_tip
    assert other.chain.verify()["ok"] is True


def test_reheal_does_not_listen_to_neighbors(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    with pytest.raises(QNMRefuse) as exc:
        node.reheal({"neighbor": "peer-b", "should_be": "their-tip"})
    assert exc.value.code == "QNM-REHEAL-NO-NEIGHBOR"
    with pytest.raises(QNMRefuse) as vxc:
        node.reheal({"vote": 12, "majority": True})
    assert vxc.value.code == "QNM-REHEAL-NO-MAJORITY"
    with pytest.raises(QNMRefuse):
        node.phoenix.neighbor_heal()
    with pytest.raises(QNMRefuse):
        node.heal()
    with pytest.raises(QNMRefuse):
        node.tethers.neighbor_rewire()


def test_chatter_status_and_tip_hash_only(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    ok = node.chatter({"status": "live", "tip_hash": node.chain.tip})
    assert ok["body"] is False
    assert ok["heal"] is False
    for banned in (
        {"status": "live", "body": "x"},
        {"status": "live", "diff": "x"},
        {"status": "live", "should_be": node.chain.tip},
        {"status": "live", "vote": 3},
        {"status": "forming", "tip_hash": node.chain.tip},
    ):
        with pytest.raises(QNMRefuse) as exc:
            node.chatter(banned)
        assert exc.value.code == "QNM-REHEAL-CHATTER"


def test_reheal_without_trusted_bytes_phoenix_waits(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    node.phoenix.last_good_bytes = None
    node.phoenix.last_good_tip = None
    out = node.reheal()
    assert out["state"] == "PHOENIX_LOCK"
    assert out["phoenix"]["waiting"] == "local"
    assert node.phoenix.controller_hunt is False


def test_api_reheal(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    code, payload = node.handle("POST", "/local/reheal", b"{}")
    assert code == 200
    assert payload["reheal"]["healed"] is True
    assert payload["heal_from_neighbor"] is False
