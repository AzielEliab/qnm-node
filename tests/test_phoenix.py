"""§14.4 PHOENIX-LOCK waits locally. No controller hunt."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from qnm.boot import QNMRefuse
from qnm.node import Node
from qnm.phoenix import Phoenix


def test_arm_waits_locally(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    snap = node.arm_phoenix()
    assert snap["state"] == "PHOENIX_LOCK"
    assert snap["phoenix"]["waiting"] == "local"
    assert snap["phoenix"]["controller_hunt"] is False
    assert node.phoenix.controller_hunt is False


def test_api_phoenix_arm(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    code, payload = node.handle("POST", "/local/phoenix/arm", b"{}")
    assert code == 200
    assert payload["state"] == "PHOENIX_LOCK"
    assert payload["phoenix"]["waiting"] == "local"


def test_no_controller_hunt() -> None:
    phoenix = Phoenix()
    phoenix.arm()
    with pytest.raises(QNMRefuse) as exc:
        phoenix.hunt_controller()
    assert exc.value.code == "QNM-PHOENIX-LOCAL-WAIT"


def test_arm_does_not_open_network(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*_a: object, **_k: object) -> None:
        raise AssertionError("PHOENIX-LOCK must not hunt a controller")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.create_connection, "__call__", blocked)
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    node.arm_phoenix()
    with pytest.raises(QNMRefuse) as exc:
        node.phoenix.hunt_controller()
    assert exc.value.code == "QNM-PHOENIX-LOCAL-WAIT"
    assert node.state == "PHOENIX_LOCK"


def test_phoenix_forward_only(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    node.arm_phoenix()
    with pytest.raises(QNMRefuse) as exc:
        node._advance("LIVE")
    assert exc.value.code == "QNM-NO-AUTO-HEAL"
    assert node.state == "PHOENIX_LOCK"
