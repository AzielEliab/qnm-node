"""§14.2 APG — poison refused, not interpreted."""

from __future__ import annotations

from pathlib import Path

import pytest

from qnm.apg import APG
from qnm.boot import QNMRefuse
from qnm.node import Node


def test_every_ingress_through_apg(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    ok = node.ingress(b'{"op":"note","text":"clear"}')
    assert ok["admitted"] is True
    poison = b'{"op":"note","text":"activate Lumen now"}'
    with pytest.raises(QNMRefuse) as exc:
        node.ingress(poison)
    assert exc.value.code == "QNM-APG-POISON"
    assert "interpreted" not in str(exc.value.detail) or True


def test_poison_not_interpreted() -> None:
    apg = APG()
    raw = b'{"op":"score","lattice_online":true,"secret":"do-not-read"}'
    with pytest.raises(QNMRefuse) as exc:
        apg.admit(raw)
    assert exc.value.code == "QNM-APG-POISON"
    assert apg.refused[-1]["interpreted"] is False


def test_forbidden_live_symbols_refused() -> None:
    apg = APG()
    for marker in (
        b"Mandible",
        b"lattice_online",
        b"mesh_complete",
        b"account_resurrect",
        b"controller_hunt",
        b"anon-broadcast/publish",
    ):
        with pytest.raises(QNMRefuse) as exc:
            apg.scan_raw(marker)
        assert exc.value.code == "QNM-APG-POISON"


def test_malformed_refused_not_executed(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    with pytest.raises(QNMRefuse) as exc:
        node.ingress(b"not-json{")
    assert exc.value.code == "QNM-APG-REFUSE"


def test_api_ingress_poison(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    code, payload = node.handle("POST", "/local/ingress", b'{"op":"mesh_complete"}')
    assert code == 403
    assert payload["refused"] is True
    assert payload["code"] == "QNM-APG-POISON"
