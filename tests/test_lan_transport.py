"""CI tests for the opt-in lan-tls adapter.

Loopback is an explicit opt-in. It is not cross-host proof and it is
not LIVE. Two physical machines are tests/test_lan_two_host.py.
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import qnm  # noqa: F401  — before qnsd, avoids the boot/vias cycle
from qnm.boot import QNMRefuse
from qnm.fedmesh.wire import envelope_id
from qnm.surface import refuse_wan_bind
from qnsd.lan.bind import select_bind
from qnsd.lan.contract import (
    MAX_FRAGMENTS,
    MAX_MESSAGES,
    MAX_QUEUE_ITEMS,
    MIN_FRAGMENT,
    LanRefuse,
    SendResult,
)
from qnsd.lan.frame import read_frame
from qnsd.lan.node import LanNode, LanTLSAdapter
from qnsd.lan.queue import QueueStore, new_item
from qnsd.lan.router import RoutePlanner
from qnsd.lan.session import _Rate, _split
from qnsd.lan.sign import sign_document
from qnsd.node import DEFAULT_BIND
from qnsd.photon import loads, photon_id
from qnsd.vias.base import VIA_ORDER

ROOT = Path(__file__).resolve().parents[1]
MARKER = "PAYLOAD-MARKER-DO-NOT-LOG"


def _pair(tmp_path: Path, *, fragment: int = 4096):
    node_a = LanNode(tmp_path / "a", enabled=True, allow_loopback=True, max_fragment_bytes=fragment)
    node_b = LanNode(tmp_path / "b", enabled=True, allow_loopback=True, max_fragment_bytes=fragment)
    started = node_b.listen("127.0.0.1", 0, allow_loopback=True)
    node_a.add_peer(node_b.public_material(), f"127.0.0.1:{started['port']}")
    node_b.add_peer(node_a.public_material(), "127.0.0.1:9")
    return node_a, node_b, started


def _close(*nodes: LanNode) -> None:
    for node in nodes:
        node.close()


def test_via_order_and_http_door_stay_put() -> None:
    assert VIA_ORDER == (
        "lan",
        "wifi",
        "plc",
        "bt",
        "rf",
        "gps",
        "nfc",
        "light",
        "qns",
        "operator",
        "local",
    )
    assert "lan-tls" not in VIA_ORDER
    assert DEFAULT_BIND == "127.0.0.1"
    with pytest.raises(QNMRefuse) as exc:
        refuse_wan_bind("0.0.0.0")
    assert exc.value.code == "QNM-LOOPBACK-ONLY"


def test_bind_refuses_wan_public_cgnat_and_bare_loopback() -> None:
    cases = (
        ("0.0.0.0", "QNS-LAN-WAN"),
        ("::", "QNS-LAN-WAN"),
        ("*", "QNS-LAN-WAN"),
        ("8.8.8.8", "QNS-LAN-WAN"),
        ("100.64.0.1", "QNS-LAN-WAN"),
        ("127.0.0.1", "QNS-LAN-BIND"),
    )
    for host, code in cases:
        with pytest.raises(LanRefuse) as exc:
            select_bind(host, allow_loopback=False)
        assert exc.value.code == code
    assert select_bind("127.0.0.1", allow_loopback=True) == "127.0.0.1"


def test_frame_length_is_refused_before_the_body() -> None:
    left, right = socket.socketpair()
    left.settimeout(0.3)
    right.sendall((0xFFFFFFFF).to_bytes(4, "big") + b"NO")
    started = time.monotonic()
    try:
        with pytest.raises(LanRefuse) as exc:
            read_frame(left)
        assert exc.value.code == "QNS-LAN-MALFORMED"
        assert exc.value.security is True
        assert time.monotonic() - started < 0.2
    finally:
        left.close()
        right.close()


def test_queue_cap_and_message_rate() -> None:
    raw = b"x" * (MAX_FRAGMENTS * MIN_FRAGMENT + 1)
    with pytest.raises(LanRefuse) as exc:
        _split(raw, MIN_FRAGMENT)
    assert exc.value.code == "QNS-LAN-QUOTA"
    rate = _Rate()
    for _ in range(MAX_MESSAGES):
        rate.bump()
    with pytest.raises(LanRefuse) as exc:
        rate.bump()
    assert exc.value.code == "QNS-LAN-QUOTA"


def test_disabled_listener_is_absent_and_not_live(tmp_path: Path) -> None:
    node = LanNode(tmp_path / "off", enabled=False)
    with pytest.raises(LanRefuse) as exc:
        node.listen("127.0.0.1", 0, allow_loopback=True)
    assert exc.value.code == "QNS-LAN-ABSENT"
    result = node.send_payload("#NOBODY00000", {"text": "no"})
    assert result.outcome == "absent"
    assert result.live is False
    assert node.capabilities()["live"] is False
    assert node.capabilities()["cross_host_proven"] is False
    assert node.capabilities()["fielding"] == "ABSENT"
    assert node.relay_contacts == 0
    assert node.relay_urls == ()
    assert len(node.planner.adapters) == 1
    assert isinstance(node.planner.adapters[0], LanTLSAdapter)


def test_loopback_exchange_stores_without_going_live(tmp_path: Path) -> None:
    node_a, node_b, started = _pair(tmp_path)
    try:
        assert started["live"] is False
        result = node_a.send_payload(node_b.handle, {"text": MARKER})
        assert result.outcome == "ok"
        assert result.ack_level == "stored"
        assert result.levels == ["received", "verified", "stored"]
        assert result.live is False
        assert result.relay_contacted is False
        assert node_a.capabilities()["live"] is False
        assert node_b.capabilities()["live"] is False
        assert node_b.capabilities()["cross_host_proven"] is False
        assert node_b.capabilities()["presence"] == "PRESENT"
        assert node_b.capabilities()["fielding"] == "ABSENT"
        report = node_b.verify()
        assert report["ok"] is True
        assert report["live"] is False
        assert report["receipts"] == 1
        inbox = list((tmp_path / "b" / "data" / "lan" / "inbox").glob("*.json"))
        assert len(inbox) == 1
        stored = json.loads(inbox[0].read_text(encoding="utf-8"))
        assert stored["payload_hash"] == result.payload_hash
        assert stored["packet_id"] == result.packet_id
        photon = loads(stored["photon"])
        assert photon.photon_id == result.packet_id
        assert photon_id(photon) == result.packet_id
        leaked = node_a.log_text() + node_b.log_text()
        leaked += (tmp_path / "a" / "data" / "lan" / "receipts.jsonl").read_text(encoding="utf-8")
        leaked += (tmp_path / "b" / "data" / "lan" / "receipts.jsonl").read_text(encoding="utf-8")
        leaked += (tmp_path / "a" / "data" / "lan" / "queue.jsonl").read_text(encoding="utf-8")
        assert MARKER not in leaked
        assert MARKER in inbox[0].read_text(encoding="utf-8")
        for line in (node_a.log_text() + node_b.log_text()).splitlines():
            keys = set(json.loads(line))
            assert keys <= {
                "event",
                "adapter",
                "packet_id",
                "payload_hash",
                "outcome",
                "code",
                "level",
                "handle",
                "peer_handle",
                "live",
                "loopback",
                "fragment_index",
                "fragment_count",
                "nbytes",
                "hop",
                "security",
            }
            assert json.loads(line)["live"] is False
    finally:
        _close(node_a, node_b)


def test_fragment_reassembly(tmp_path: Path) -> None:
    node_a, node_b, _started = _pair(tmp_path, fragment=300)
    try:
        result = node_a.send_payload(node_b.handle, {"text": MARKER, "blob": "A" * 2000})
        assert result.ack_level == "stored"
        assert result.live is False
        send_lines = [json.loads(line) for line in node_a.log_text().splitlines()]
        counts = [row.get("fragment_count") for row in send_lines if row.get("event") == "send"]
        assert counts and counts[0] > 1
        assert MARKER not in node_a.log_text()
        assert MARKER not in node_b.log_text()
    finally:
        _close(node_a, node_b)


def test_duplicate_is_idempotent(tmp_path: Path) -> None:
    node_a, node_b, _started = _pair(tmp_path)
    try:
        first = node_a.send_payload(node_b.handle, {"text": MARKER})
        second = node_a.send_payload(node_b.handle, {"text": MARKER})
        assert first.ack_level == "stored"
        assert second.ack_level == "stored"
        assert second.transport_accepted is False
        assert second.packet_id == first.packet_id
        seq = (tmp_path / "a" / "data" / "lan" / "seq.jsonl").read_text(encoding="utf-8").strip().splitlines()
        assert len(seq) == 1
        assert len(list((tmp_path / "b" / "data" / "lan" / "inbox").glob("*.json"))) == 1
        assert node_b.verify()["receipts"] == 1
    finally:
        _close(node_a, node_b)


def test_peer_unavailable_then_restart_flushes(tmp_path: Path) -> None:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    node_a = LanNode(tmp_path / "a", enabled=True, allow_loopback=True)
    node_b = LanNode(tmp_path / "b", enabled=True, allow_loopback=True)
    node_a.add_peer(node_b.public_material(), f"127.0.0.1:{port}")
    node_b.add_peer(node_a.public_material(), "127.0.0.1:9")
    try:
        down = node_a.send_payload(node_b.handle, {"text": "queued-one"})
        assert down.outcome == "temporary"
        assert down.code == "QNS-LAN-UNAVAILABLE"
        assert down.security is False
        assert down.live is False
        second = node_a.send_payload(node_b.handle, {"text": "queued-two"})
        assert second.code == "QNS-LAN-UNAVAILABLE"
        node_a.close()
        started = node_b.listen("127.0.0.1", port, allow_loopback=True)
        assert started["live"] is False
        resumed = LanNode(tmp_path / "a", enabled=True, allow_loopback=True)
        later = datetime.now(timezone.utc) + timedelta(seconds=5)
        results = resumed.flush(now=later)
        assert [item.ack_level for item in results] == ["stored", "stored"]
        assert all(item.live is False for item in results)
        assert node_b.verify()["ok"] is True
        assert len(list((tmp_path / "b" / "data" / "lan" / "inbox").glob("*.json"))) == 2
    finally:
        node_b.close()


def test_bad_signature_is_a_security_refusal(tmp_path: Path) -> None:
    node_a, node_b, _started = _pair(tmp_path)
    try:
        second = _Catch()
        node_a.planner = RoutePlanner([node_a.adapter, second])
        envelope = node_a._seal(node_b.handle, {"text": "tamper"}, 3600)
        envelope["sig"] = "A" * 40
        result = node_a.planner.dispatch({"dst_handle": node_b.handle, "envelope": envelope})
        assert result.code == "QNS-LAN-REFUSED"
        assert result.outcome == "refused"
        assert result.security is True
        assert result.live is False
        assert second.calls == 0
        assert list((tmp_path / "b" / "data" / "lan" / "inbox").glob("*.json")) == []
        assert not (tmp_path / "b" / "data" / "lan" / "seq.jsonl").exists() or (
            (tmp_path / "b" / "data" / "lan" / "seq.jsonl").read_text(encoding="utf-8").strip() == ""
        )
    finally:
        _close(node_a, node_b)


def test_reorder_gap_then_fill(tmp_path: Path) -> None:
    node_a, node_b, _started = _pair(tmp_path)
    try:
        first = node_a._seal(node_b.handle, {"text": "one"}, 3600, seq=1, prev="0" * 64)
        second = node_a._seal(
            node_b.handle,
            {"text": "two"},
            3600,
            seq=2,
            prev=envelope_id(first["body"]),
        )
        gap = node_a.deliver({"dst_handle": node_b.handle, "envelope": second})
        assert gap.code == "FED-GAP"
        assert gap.outcome == "temporary"
        assert gap.security is False
        stored = node_a.deliver({"dst_handle": node_b.handle, "envelope": first})
        assert stored.ack_level == "stored"
        filled = node_a.deliver({"dst_handle": node_b.handle, "envelope": second})
        assert filled.ack_level == "stored"
        assert node_b.verify()["ok"] is True
        lines = (tmp_path / "b" / "data" / "lan" / "seq.jsonl").read_text(encoding="utf-8").strip().splitlines()
        assert [json.loads(line)["seq"] for line in lines] == [1, 2]
    finally:
        _close(node_a, node_b)


def test_expired_future_and_fork(tmp_path: Path) -> None:
    node_a, node_b, _started = _pair(tmp_path)
    try:
        expired = node_a._seal(node_b.handle, {"text": "old"}, 3600)
        expired["expiry_utc"] = "2020-01-01T00:00:00Z"
        expired = sign_document(node_a.sign_private, expired)
        refused = node_a.deliver({"dst_handle": node_b.handle, "envelope": expired})
        assert refused.code == "QNS-LAN-EXPIRED"
        assert refused.outcome == "permanent"
        assert refused.security is True

        future = node_a._seal(node_b.handle, {"text": "future"}, 3600)
        future["created_utc"] = "2099-01-01T00:00:00Z"
        future["expiry_utc"] = "2099-01-02T00:00:00Z"
        future = sign_document(node_a.sign_private, future)
        clock = node_a.deliver({"dst_handle": node_b.handle, "envelope": future})
        assert clock.code == "QNS-LAN-CLOCK"
        assert clock.security is True

        good = node_a.send_payload(node_b.handle, {"text": "fork-base"})
        assert good.ack_level == "stored"
        forked = node_a._seal(node_b.handle, {"text": "fork-base"}, 3600)
        forked["payload_hash"] = "ab" * 32
        forked = sign_document(node_a.sign_private, forked)
        fork = node_a.deliver({"dst_handle": node_b.handle, "envelope": forked})
        assert fork.code == "QNS-LAN-FORK"
        assert fork.security is True
        assert len(list((tmp_path / "b" / "data" / "lan" / "inbox").glob("*.json"))) == 1
    finally:
        _close(node_a, node_b)


def test_revoked_peer_and_unapproved_source(tmp_path: Path) -> None:
    node_a, node_b, started = _pair(tmp_path)
    try:
        node_a.revoke(node_b.handle, "operator")
        revoked = node_a.send_payload(node_b.handle, {"text": "nope"})
        assert revoked.code == "QNS-LAN-REVOKED"
        assert revoked.security is True
        assert list((tmp_path / "b" / "data" / "lan" / "inbox").glob("*.json")) == []
    finally:
        _close(node_a, node_b)

    node_a = LanNode(tmp_path / "a2", enabled=True, allow_loopback=True)
    node_b = LanNode(tmp_path / "b2", enabled=True, allow_loopback=True)
    started = node_b.listen("127.0.0.1", 0, allow_loopback=True)
    node_a.add_peer(node_b.public_material(), f"127.0.0.1:{started['port']}")
    node_b.add_peer(node_a.public_material(), "10.1.0.1:9")
    try:
        spoofed = node_a.send_payload(node_b.handle, {"text": MARKER})
        assert spoofed.security is True
        assert spoofed.code == "QNS-LAN-REFUSED"
        assert spoofed.live is False
        assert MARKER not in node_b.log_text()
        assert list((tmp_path / "b2" / "data" / "lan" / "inbox").glob("*.json")) == []
    finally:
        _close(node_a, node_b)


def test_disk_loss_is_reported_and_not_rewritten(tmp_path: Path) -> None:
    node_a, node_b, _started = _pair(tmp_path)
    try:
        result = node_a.send_payload(node_b.handle, {"text": MARKER})
        assert result.ack_level == "stored"
        receipt_before = (tmp_path / "b" / "data" / "lan" / "receipts.jsonl").read_text(encoding="utf-8")
        inbox = list((tmp_path / "b" / "data" / "lan" / "inbox").glob("*.json"))
        inbox[0].unlink()
        report = node_b.verify()
        assert report["ok"] is False
        assert result.packet_id in report["missing_inbox"]
        assert (tmp_path / "b" / "data" / "lan" / "receipts.jsonl").read_text(encoding="utf-8") == receipt_before
    finally:
        _close(node_a, node_b)


def test_nonce_replay_and_queue_quota(tmp_path: Path) -> None:
    node = LanNode(tmp_path / "n", enabled=False)
    nonce = "ab" * 32
    node.remember_nonce(nonce)
    with pytest.raises(LanRefuse) as exc:
        node.remember_nonce(nonce)
    assert exc.value.code == "QNS-LAN-REPLAY"
    store = QueueStore(tmp_path / "q")
    body = {"packet_id": "0" * 64, "dst_handle": "h", "payload_hash": "1" * 64}
    for index in range(MAX_QUEUE_ITEMS):
        item = new_item(body, packet_id=f"{index:064x}", payload_hash="1" * 64, expiry_utc="2099-01-01T00:00:00Z")
        store.append(item)
    with pytest.raises(LanRefuse) as exc:
        store.append(new_item(body, packet_id="f" * 64, payload_hash="1" * 64, expiry_utc="2099-01-01T00:00:00Z"))
    assert exc.value.code == "QNS-LAN-QUOTA"
    assert exc.value.security is True
    assert len([row for row in store.items if row["state"] == "queued"]) == MAX_QUEUE_ITEMS


def test_security_refusal_does_not_try_a_lower_route() -> None:
    class Second:
        def __init__(self) -> None:
            self.calls = 0

        def capabilities(self) -> dict:
            return {"enabled": True, "live": True}

        def send(self, packet: dict) -> SendResult:
            self.calls += 1
            return SendResult(outcome="ok", ack_level="stored", transport_accepted=True)

    class First:
        def capabilities(self) -> dict:
            return {"enabled": True}

        def send(self, packet: dict) -> SendResult:
            return SendResult(outcome="refused", code="QNS-LAN-IDENTITY", security=True)

    second = Second()
    planner = RoutePlanner([First(), second])
    result = planner.dispatch({"dst_handle": "x"})
    assert result.security is True
    assert result.live is False
    assert second.calls == 0

    class Temporary:
        def capabilities(self) -> dict:
            return {"enabled": True, "live": True}

        def send(self, packet: dict) -> SendResult:
            return SendResult(outcome="temporary", code="QNS-LAN-UNAVAILABLE", security=False)

    second = Second()
    result = RoutePlanner([Temporary(), second]).dispatch({"dst_handle": "x"})
    assert result.ack_level == "stored"
    assert result.live is False
    assert second.calls == 1

    class Off:
        def capabilities(self) -> dict:
            return {"enabled": False, "live": True, "revoked": False}

        def send(self, packet: dict) -> SendResult:
            raise AssertionError("disabled adapter was called")

    result = RoutePlanner([Off()]).dispatch({"dst_handle": "x"})
    assert result.outcome == "absent"
    assert result.code == "QNS-LAN-ABSENT"
    assert result.live is False


def test_relay_client_is_not_imported() -> None:
    text = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "qnsd" / "lan").glob("*.py"))
    assert "fedmesh.relay" not in text
    assert "live = True" not in text
    assert "live=True" not in text
    assert "entangle" not in text.lower()
    assert "qubit" not in text.lower()


def test_cli_init_show_and_wan_refuse(tmp_path: Path) -> None:
    launcher = ROOT / "scripts" / "qns_lan.py"
    data = tmp_path / "cli"
    init = subprocess.run(
        [sys.executable, str(launcher), "--data-dir", str(data), "init"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert init.returncode == 0, init.stderr
    assert '"live": false' in init.stdout
    show = subprocess.run(
        [sys.executable, str(launcher), "--data-dir", str(data), "show"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert show.returncode == 0, show.stderr
    assert "PRIVATE" not in show.stdout
    assert "cert_pem" in show.stdout
    refused = subprocess.run(
        [sys.executable, str(launcher), "--data-dir", str(data), "listen", "--bind", "0.0.0.0", "--port", "9"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert refused.returncode == 2
    assert "QNS-LAN-WAN" in refused.stdout


class _Catch:
    def __init__(self) -> None:
        self.calls = 0

    def capabilities(self) -> dict:
        return {"enabled": True, "live": True}

    def send(self, packet: dict) -> SendResult:
        self.calls += 1
        return SendResult(outcome="ok", ack_level="stored", transport_accepted=True)
