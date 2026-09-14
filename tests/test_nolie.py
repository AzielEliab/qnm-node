"""NO-LIE-1.0 / NO-REWRITE-1.0 — receipts hash; no rewrite; no lie-to-live."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from qnm.boot import QNMRefuse
from qnm.coldcopy import ColdCopy
from qnm.nolie import receipt_digest
from qnm.node import Node


def test_receipts_still_hash(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    verified = node.verify_receipts()
    assert verified["ok"] is True
    assert verified["voice"] is False
    assert verified["count"] >= 1
    for receipt in node.receipts():
        assert receipt["receipt_hash"] == receipt_digest(receipt)


def test_tampered_receipt_fails_and_rewrite_refused(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    log = tmp_path / "data" / "receipts" / "receipts.jsonl"
    rows = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]
    rows[0]["body"] = {"rewritten": True}
    log.write_text(
        json.dumps(rows[0], sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(QNMRefuse) as exc:
        node.verify_receipts()
    assert exc.value.code == "QNM-RECEIPT-HASH"
    with pytest.raises(QNMRefuse) as rxc:
        node.rewrite_receipt()
    assert rxc.value.code == "QNM-NO-REWRITE"


def test_verify_without_voice(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    ok = node.verify_receipts()
    assert ok["voice"] is False
    with pytest.raises(QNMRefuse) as exc:
        node.verify_receipts(require_voice=True)
    assert exc.value.code == "QNM-VERIFY-WITHOUT-VOICE"
    with pytest.raises(QNMRefuse) as vxc:
        node.nolie.require_voice()
    assert vxc.value.code == "QNM-VERIFY-WITHOUT-VOICE"
    with pytest.raises(QNMRefuse):
        node.ingress(b'{"op":"require_voice"}')
    with pytest.raises(QNMRefuse):
        node.ingress(b'{"op":"voice_confirm"}')


def test_no_rewrite_key_or_published_mutate(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    emitted = node.emit_tip()
    tip = emitted["tip_hash"]
    assert tip in node.nolie.published()
    with pytest.raises(QNMRefuse) as exc:
        node.rewrite_published(tip, "a" * 64)
    assert exc.value.code == "QNM-NO-REWRITE"
    with pytest.raises(QNMRefuse):
        node.nolie.mutate_published(tip)
    with pytest.raises(QNMRefuse) as kxc:
        node.rewrite_key("Aziel Eliab")
    assert kxc.value.code == "QNM-NO-REWRITE-KEY"
    with pytest.raises(QNMRefuse):
        node.chain.rewrite()
    with pytest.raises(QNMRefuse):
        node.chain.mutate()
    with pytest.raises(QNMRefuse):
        node.chain.rewrite_key()
    assert tip in node.nolie.published()
    assert node.chain.verify()["ok"] is True
    assert node.verify_receipts()["ok"] is True


def test_copies_not_all_on_one_tunnel(tmp_path: Path) -> None:
    vault = ColdCopy(tmp_path)
    tip = vault.store(b"spread", host="local")["tip"]
    vault.transfer(tip, host="mesh-vault")
    vault.transfer(tip, host="reader")
    assert vault.replica_count(tip) >= 3
    with pytest.raises(QNMRefuse) as exc:
        vault.store(b"only-tunnel", host="cf-tunnel")
    assert exc.value.code == "QNM-NO-ONE-TUNNEL"
    with pytest.raises(QNMRefuse):
        vault.one_tunnel()
    node = Node(tmp_path / "n")
    node.boot(entropy=b"e", nonce=b"n")
    with pytest.raises(QNMRefuse) as nxc:
        node.vault_act({"action": "one_tunnel"})
    assert nxc.value.code == "QNM-NO-ONE-TUNNEL"
    with pytest.raises(QNMRefuse):
        node.ingress(b'{"op":"all_on_tunnel"}')


def test_lie_to_stay_alive_heal_refused(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    node.emit_tip()
    with pytest.raises(QNMRefuse) as exc:
        node.reheal({"lie_to_stay_alive": True})
    assert exc.value.code == "QNM-NO-LIE-TO-LIVE"
    with pytest.raises(QNMRefuse) as axc:
        node.reheal({"lie_to_adapt": True})
    assert axc.value.code == "QNM-NO-LIE-TO-LIVE"
    with pytest.raises(QNMRefuse) as dxc:
        node.reheal({"lie_to_prevent_death": True})
    assert dxc.value.code == "QNM-NO-LIE-TO-LIVE"
    with pytest.raises(QNMRefuse):
        node.phoenix.lie_to_stay_alive()
    with pytest.raises(QNMRefuse) as rxc:
        node.reheal({"rewrite": True, "new_tip": "b" * 64})
    assert rxc.value.code == "QNM-NO-REWRITE"
    with pytest.raises(QNMRefuse) as fxc:
        node.emit_false()
    assert fxc.value.code == "QNM-NO-LIE-TO-LIVE"
    node.isolate("probe")
    with pytest.raises(QNMRefuse):
        node.ingress(b'{"op":"lie_to_stay_alive"}')


def test_api_nolie_and_rewrite_and_cfg(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    code, status = node.handle("GET", "/local/nolie", b"")
    assert code == 200
    assert status["no_lie"] is True
    assert status["no_rewrite"] is True
    assert status["rewrite_key"] is False
    assert status["verify_without_voice"] is True
    assert status["copies_one_tunnel"] is False
    code, verified = node.handle("POST", "/local/nolie", b'{"op":"verify"}')
    assert code == 200
    assert verified["voice"] is False
    code, refused = node.handle("POST", "/local/rewrite", b'{"tip":"a","new_tip":"b"}')
    assert code == 403
    assert refused["code"] == "QNM-NO-REWRITE"
    snap = node.snapshot()
    assert snap["no_lie"] is True
    assert snap["no_rewrite"] is True
    assert snap["rewrite_key"] is False
    assert snap["verify_without_voice"] is True
    assert snap["copies_one_tunnel"] is False
    cfg = Path(__file__).resolve().parents[1] / "cfg" / "node.json"
    text = cfg.read_text(encoding="utf-8")
    assert '"no_lie": true' in text
    assert '"no_rewrite": true' in text
    assert '"rewrite_key": false' in text
    assert '"verify_without_voice": true' in text
    assert '"copies_one_tunnel": false' in text
