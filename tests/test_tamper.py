"""§14.3 Tamper isolates. No auto-heal."""

from __future__ import annotations

from pathlib import Path

import pytest

from qnm.boot import QNMRefuse
from qnm.node import Node


def test_tamper_isolates(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    node.set_bearer("operator", True)
    assert node.state == "LIVE"
    snap = node.isolate("disk_moved")
    assert snap["state"] == "ISOLATED"
    assert node.bearers.is_on("operator") is False
    assert node.bearers.is_on("local") is True


def test_ingress_tamper_isolates(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    out = node.ingress(b'{"op":"tamper","reason":"hash"}')
    assert out["state"] == "ISOLATED"


def test_chain_mismatch_isolates(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    chain = tmp_path / "data" / "chain" / "node.jsonl"
    text = chain.read_text(encoding="utf-8")
    chain.write_text(text.replace('"boot"', '"BOOT"'), encoding="utf-8")
    node.chain._load()
    out = node.check_tamper()
    assert out["state"] == "ISOLATED"


def test_no_heal_from_isolated(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    node.isolate("probe")
    with pytest.raises(QNMRefuse) as exc:
        node.heal()
    assert exc.value.code == "QNM-NO-AUTO-HEAL"
    with pytest.raises(QNMRefuse):
        node.set_bearer("operator", True)
    assert node.state == "ISOLATED"


def test_tamper_receipt_on_disk(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    node.isolate("witness")
    kinds = [r["kind"] for r in node.receipts()]
    assert "tamper_isolate" in kinds
