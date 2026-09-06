"""§14.1 Offline — radios off, two roots, lock resume, no LIVE from ping."""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from qnm.boot import QNMRefuse, compute_install_root, install, lock_path
from qnm.node import DEFAULT_BIND, Node, serve


def test_two_installs_two_roots(tmp_path: Path) -> None:
    a = tmp_path / "a"
    b = tmp_path / "b"
    ra = install(a, entropy=b"entropy-one", nonce=b"nonce-one")
    rb = install(b, entropy=b"entropy-two", nonce=b"nonce-one")
    assert ra["install_root"] != rb["install_root"]
    assert ra["install_root"] == compute_install_root(b"entropy-one", b"nonce-one")
    assert rb["install_root"] == compute_install_root(b"entropy-two", b"nonce-one")


def test_resume_only_from_locks(tmp_path: Path) -> None:
    node = Node(tmp_path)
    first = node.boot(entropy=b"e", nonce=b"n")
    assert node.state == "LOCAL"
    again = Node(tmp_path)
    again.boot()
    assert again.install_root == first["install_root"]
    with pytest.raises(QNMRefuse) as exc:
        Node(tmp_path).boot(resume_from=tmp_path / "data" / "chain" / "node.jsonl")
    assert exc.value.code == "QNM-RESUME-LOCK-ONLY"
    assert lock_path(tmp_path).is_file()


def test_second_install_same_root_refused(tmp_path: Path) -> None:
    install(tmp_path, entropy=b"e", nonce=b"n")
    with pytest.raises(QNMRefuse) as exc:
        install(tmp_path, entropy=b"other", nonce=b"n2")
    assert exc.value.code == "QNM-RESUME-LOCK-ONLY"


def test_radios_off_and_local_bearer(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    snap = node.snapshot()
    assert snap["radios"] == "off"
    assert snap["bearers"]["local"] is True
    assert snap["bearers"]["operator"] is False
    assert snap["bearers"]["radio"] is False
    with pytest.raises(QNMRefuse) as exc:
        node.set_bearer("radio", True)
    assert exc.value.code == "QNM-RADIO-OFF"


def test_no_live_from_site_ping(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    ping = node.site_ping("https://example.invalid/lattice_ping")
    assert node.state == "LOCAL"
    assert ping["from_ping"] is False
    assert ping["code"] == "QNM-NO-LIVE-FROM-PING"


def test_live_only_from_operator_bearer(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    node.set_bearer("operator", True)
    assert node.state == "LIVE"


def test_no_auto_heal(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    node.isolate("probe")
    assert node.state == "ISOLATED"
    with pytest.raises(QNMRefuse) as exc:
        node.heal()
    assert exc.value.code == "QNM-NO-AUTO-HEAL"
    assert node.state == "ISOLATED"


def test_receipts_to_disk(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    log = tmp_path / "data" / "receipts" / "receipts.jsonl"
    chain = tmp_path / "data" / "chain" / "node.jsonl"
    assert log.is_file() and log.read_text(encoding="utf-8").strip()
    assert chain.is_file() and chain.read_text(encoding="utf-8").strip()
    assert node.receipts()
    leaves = list((tmp_path / "data" / "receipts").glob("*.json"))
    assert leaves


def test_local_api_bind_loopback_only(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    with pytest.raises(QNMRefuse) as exc:
        serve(node, host="0.0.0.0", port=0)
    assert exc.value.code == "QNM-LOOPBACK-ONLY"
    server = serve(node, host=DEFAULT_BIND, port=0)
    host, port = server.server_address[:2]
    assert host == "127.0.0.1"
    try:
        raw = json.dumps({}).encode()
        sock = socket.create_connection(("127.0.0.1", port), timeout=2)
        sock.sendall(
            b"POST /local/state HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        sock.close()
        code, payload = node.handle("GET", "/local/state", raw)
        assert code == 200
        assert payload["state"] == "LOCAL"
        assert payload["bind"] == "127.0.0.1"
    finally:
        server.server_close()


def test_no_network_needed_for_local_modules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*_a: object, **_k: object) -> None:
        raise AssertionError("radios/network must stay off")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    node.queue_outbox("note", {"text": "desk"})
    assert node.outbox.list()
    assert node.snapshot()["radios"] == "off"
