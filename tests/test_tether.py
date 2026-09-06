"""§14.5 Tethers drop clean."""

from __future__ import annotations

from pathlib import Path

import pytest

from qnm.boot import QNMRefuse
from qnm.node import Node


def test_declare_and_cut_clean(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    node.declare_tether("azhub", "azinterface")
    assert len(node.tethers.list()) == 1
    cut = node.cut_tether("azhub", "azinterface")
    assert cut["residue"] is False
    assert cut["auto_rewire"] is False
    assert node.tethers.list() == []
    disk = (tmp_path / "data" / "witness" / "declared.jsonl").read_text(encoding="utf-8")
    assert "azhub" not in disk


def test_cut_unknown_refuses(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    with pytest.raises(QNMRefuse) as exc:
        node.cut_tether("a", "b")
    assert exc.value.code == "QNM-TETHER-CLEAN"


def test_api_tether_declare_and_cut(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    code, declared = node.handle(
        "POST",
        "/local/tether",
        b'{"op":"declare","src":"mod-a","dst":"mod-b"}',
    )
    assert code == 200
    assert declared["src"] == "mod-a"
    code, cut = node.handle(
        "POST",
        "/local/tether",
        b'{"op":"cut","src":"mod-a","dst":"mod-b"}',
    )
    assert code == 200
    assert cut["residue"] is False
    assert node.tethers.list() == []


def test_no_auto_rewire_after_cut(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    node.declare_tether("left", "right")
    node.cut_tether("left", "right")
    assert node.tethers.list() == []
    node.queue_outbox("note", {"text": "unrelated"})
    assert node.tethers.list() == []
