"""§14.6 No account resurrection. Identity. Score. AnonBroadcast."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from qnm.boot import AUTHOR, IDENTITY, QNMRefuse
from qnm.node import Node
from qnm.score import score_local


def _load_anon_broadcast():
    path = Path(__file__).resolve().parents[1] / "modules" / "anon-broadcast" / "loopback.py"
    spec = importlib.util.spec_from_file_location("anon_broadcast_loopback", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_identity_aziel_eliab_only(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    assert node.identity == "Aziel Eliab"
    assert node.author == AUTHOR == IDENTITY
    lock = (tmp_path / "data" / "locks" / "install.lock").read_text(encoding="utf-8")
    assert "Aziel Eliab" in lock
    assert "Lumen" not in lock
    assert "Mandible" not in lock


def test_no_account_apis(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    for fn in (node.account_create, node.account_restore, node.account_resurrect):
        with pytest.raises(QNMRefuse) as exc:
            fn("ghost")
        assert exc.value.code == "QNM-NO-ACCOUNT"


def test_scorched_cannot_resurrect(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    node.arm_phoenix()
    out = node.scorch("operator")
    assert out["state"] == "SCORCHED"
    assert out["resurrectable"] is False
    memorial = tmp_path / "data" / "witness" / "memorial.json"
    assert memorial.is_file()
    with pytest.raises(QNMRefuse) as exc:
        node.account_resurrect()
    assert exc.value.code == "QNM-NO-ACCOUNT"
    again = Node(tmp_path)
    with pytest.raises(QNMRefuse) as exc2:
        again.boot()
    assert exc2.value.code == "QNM-NO-ACCOUNT"
    assert again.state == "SCORCHED"


def test_score_never_reads_views(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    base = node.score()
    assert base["views_read"] is False
    with pytest.raises(QNMRefuse) as exc:
        node.score({"views": 10**9})
    assert exc.value.code == "QNM-SCORE-NO-VIEWS"
    with pytest.raises(QNMRefuse):
        score_local(
            chain_ok=True,
            chain_length=3,
            isolated=False,
            phoenix=False,
            scorched=False,
            extra={"views": 99},
        )
    same = node.score()
    assert same["score"] == base["score"]


def test_anon_broadcast_never_publish(tmp_path: Path) -> None:
    mod = _load_anon_broadcast()
    rec = mod.render("desk closed", tmp_path / "data" / "outbox")
    assert rec["published"] is False
    assert rec["loopback"] is True
    assert rec["radios"] == "off"
    with pytest.raises(mod.AnonBroadcastRefuse) as exc:
        mod.publish("anywhere")
    assert exc.value.code == "QNM-ANON-NO-PUBLISH"
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    with pytest.raises(QNMRefuse) as qexc:
        node.queue_outbox("note", {"publish": True})
    assert qexc.value.code == "QNM-ANON-NO-PUBLISH"


def test_cfg_forbids_completeness_symbols() -> None:
    cfg = Path(__file__).resolve().parents[1] / "cfg" / "node.json"
    data = cfg.read_text(encoding="utf-8")
    assert "Aziel Eliab" in data
    assert "lattice_online" in data  # refuse list only
    assert '"live_from_site_ping": false' in data
    assert '"score_reads_views": false' in data
    assert "AIH-WP-1.3" in data
    assert "QNM-BUILD-1.0" in data
    assert '"bell_pair": false' in data
    assert '"qubit": false' in data
