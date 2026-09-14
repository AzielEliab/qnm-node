"""COLD-COPY-1.0 — N cold replicas; no live body sync; die-with-pull keeps copies."""

from __future__ import annotations

from pathlib import Path

import pytest

from qnm.boot import QNMRefuse, sha256_hex
from qnm.node import Node
from qnm.coldcopy import ColdCopy


def _seed_three(vault: ColdCopy, body: bytes = b"receipt-body") -> str:
    stored = vault.store(body, host="local")
    tip = stored["tip"]
    vault.transfer(tip, host="mesh-vault")
    vault.transfer(tip, host="reader")
    return tip


def test_n_cold_replicas_survive_origin_pull(tmp_path: Path) -> None:
    vault = ColdCopy(tmp_path)
    tip = _seed_three(vault)
    cost = vault.expensive_to_erase(tip)
    assert cost["replicas"] >= 3
    assert cost["single_server_unkillable"] is True
    pulled = vault.pull_origin()
    assert pulled["die_with_pull"] is True
    assert pulled["cold_copies_remain"] is True
    assert pulled["origin_alive"] is False
    assert pulled["worker_alive"] is False
    assert pulled["dns_alive"] is False
    assert pulled["public_restore"] is False
    assert vault.replica_count(tip) >= 3
    assert (tmp_path / "data" / "vault" / "objects" / tip).is_file()
    verified = vault.verify(tip, creator_online=False)
    assert verified["verified"] is True
    assert verified["creator_required"] is False


def test_public_rollup_dies_records_remain(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    stored = node.vault_act(
        {
            "body": "tip-record",
            "transfer": True,
            "reader": "reader",
            "host": "local",
        }
    )
    tip = stored["tip"]
    out = node.vault_act({"action": "pull_origin"})
    assert out["die_with_pull"] is True
    assert out["cold_copies_remain"] is True
    assert node.vault.verify(tip)["ok"] is True
    assert node.chain.verify()["ok"] is True
    node._write_receipt("still_append", {"after_pull": True})
    assert node.chain.verify()["ok"] is True
    snap = node.snapshot()
    assert snap["vault"]["die_with_pull"] is True
    assert snap["phoenix"]["waiting"] != "public"


def test_no_live_body_sync_and_hash_absolute(tmp_path: Path) -> None:
    vault = ColdCopy(tmp_path)
    with pytest.raises(QNMRefuse) as exc:
        vault.live_sync(b"poison-body")
    assert exc.value.code == "QNM-COLD-NO-LIVE-SYNC"
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    with pytest.raises(QNMRefuse) as ixc:
        node.ingress(b'{"op":"live_sync","body":"spray"}')
    assert ixc.value.code == "QNM-COLD-NO-LIVE-SYNC"
    with pytest.raises(QNMRefuse) as qxc:
        node.wires.quorum_cannot_outvote(sha256_hex(b"broken"), votes=12, broken=True)
    assert qxc.value.code == "QNM-WIRES-HASH-ABSOLUTE"


def test_outlives_creator_no_session(tmp_path: Path) -> None:
    vault = ColdCopy(tmp_path)
    tip = vault.store(b"creator-left", host="local")["tip"]
    out = vault.verify(tip, creator_online=False)
    assert out["verified"] is True
    with pytest.raises(QNMRefuse) as exc:
        vault.verify(tip, require_creator=True)
    assert exc.value.code == "QNM-COLD-NO-CREATOR"


def test_named_hosts_only_no_hydra_no_vpn(tmp_path: Path) -> None:
    vault = ColdCopy(tmp_path)
    tip = vault.store(b"x", host="local")["tip"]
    with pytest.raises(QNMRefuse) as hxc:
        vault.transfer(tip, host="*")
    assert hxc.value.code == "QNM-COLD-NAMED-HOSTS"
    with pytest.raises(QNMRefuse):
        vault.transfer(tip, host="hydra")
    with pytest.raises(QNMRefuse) as vxc:
        vault.transfer(tip, host="vpn-tunnel")
    assert vxc.value.code == "QNM-COLD-NO-VPN"
    with pytest.raises(QNMRefuse):
        vault.unmarked_hydra()
    with pytest.raises(QNMRefuse):
        vault.vpn_conceal()


def test_pin_public_hash_is_hash_only(tmp_path: Path) -> None:
    vault = ColdCopy(tmp_path)
    tip = sha256_hex(b"already-public")
    pin = vault.pin_public(tip, kind="receipt")
    assert pin["body"] is False
    assert pin["public"] is True
    assert pin["tip"] == tip


def test_payload_plane_stays_pull_only_with_vault(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    stored = node.vault_act({"body": "pull-me", "host": "local"})
    code, pulled = node.handle(
        "POST",
        "/local/pull",
        ('{"tip":"%s"}' % stored["tip"]).encode(),
    )
    assert code == 200
    assert pulled["plane"] == "payload"
    assert pulled["pushed"] is False
    with pytest.raises(QNMRefuse) as exc:
        node.wires.push_payload(b"fan-out")
    assert exc.value.code == "QNM-WIRES-PULL-ONLY"


def test_api_vault_and_cfg_flags(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    code, stored = node.handle(
        "POST",
        "/local/vault",
        b'{"body":"desk","host":"local","transfer":true,"reader":"reader"}',
    )
    assert code == 200
    assert stored["content_addressed"] is True
    code, status = node.handle("GET", "/local/vault", b"")
    assert code == 200
    assert status["live_body_sync"] is False
    assert status["named_hosts_only"] is True
    assert status["unmarked_hydra"] is False
    assert status["vpn_concealment"] is False
    cfg = Path(__file__).resolve().parents[1] / "cfg" / "node.json"
    text = cfg.read_text(encoding="utf-8")
    assert '"live_body_sync": false' in text
    assert '"named_hosts_only": true' in text
    assert '"unmarked_hydra": false' in text
    assert '"vpn_concealment": false' in text
    assert '"cold_copy_n": 3' in text
