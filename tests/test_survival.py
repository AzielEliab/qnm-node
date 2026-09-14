"""CROSS-NETWORK-SURVIVAL-1.0 — tips survive if the public network dies."""

from __future__ import annotations

from pathlib import Path

import pytest

from qnm.boot import QNMRefuse
from qnm.node import Node


def test_offline_verify_append_after_public_death(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    before = node.chain.verify()
    assert before["ok"] is True
    out = node.survive_network_death()
    assert out["die_with_pull"] is True
    assert out["origin_alive"] is False
    assert out["verify_ok"] is True
    assert out["appended"] is True
    assert out["public_network_required"] is False
    assert node.chain.verify()["ok"] is True
    assert node.chain.verify()["length"] > before["length"]
    assert (tmp_path / "data" / "vault" / "objects").exists()
    assert node.phoenix.last_good_tip == node.chain.tip


def test_refuse_need_public_network_or_live_data(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    with pytest.raises(QNMRefuse) as exc:
        node.require_public_network()
    assert exc.value.code == "QNM-SURVIVE-OFFLINE"
    with pytest.raises(QNMRefuse) as lxc:
        node.require_live_data()
    assert lxc.value.code == "QNM-SURVIVE-OFFLINE"
    with pytest.raises(QNMRefuse) as ixc:
        node.ingress(b'{"op":"need_network"}')
    assert ixc.value.code == "QNM-SURVIVE-OFFLINE"
    snap = node.snapshot()
    assert snap["public_network_required"] is False
    assert snap["tips_need_live_data"] is False
    assert snap["cross_network_survival"] is True


def test_cfg_survival_flags() -> None:
    cfg = Path(__file__).resolve().parents[1] / "cfg" / "node.json"
    text = cfg.read_text(encoding="utf-8")
    assert '"public_network_required": false' in text
    assert '"tips_need_live_data": false' in text
    assert '"cross_network_survival": true' in text
