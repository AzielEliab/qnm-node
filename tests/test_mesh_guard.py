"""Mesh security layer and node isolation on the qnm daemon."""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import threading
from pathlib import Path
from urllib.parse import quote

import pytest

from qnm.boot import QNMRefuse
from qnm.fedmesh.access import Actor
from qnm.fedmesh.airlock import check_sha256sums
from qnm.fedmesh.identity import open_keystore
from qnm.fedmesh.objects import RefLog
from qnm.fedmesh.relay import http_json
from qnm.fedmesh.secwire import local_statement
from qnm.fedmesh.wire import GENESIS_PREV, sign_ref, utc_now
from qnm.node import Node, serve

SECRET = "mesh-guard-secret-payload-not-on-the-wire-44c1"


def admin(node: Node) -> Actor:
    return Actor("admin", node.fed.owner.handle, via="loopback")


class Running:
    def __init__(self) -> None:
        self.servers = []

    def up(self, root: Path) -> tuple[Node, str]:
        node = Node(root)
        server = serve(node, "127.0.0.1", 0)
        port = server.server_address[1]
        url = f"http://127.0.0.1:{port}"
        node.fed.note_base(url)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.servers.append(server)
        return node, url

    def close(self) -> None:
        for server in self.servers:
            server.shutdown()
            server.server_close()
        self.servers.clear()


def _readexact(sock: socket.socket, size: int) -> bytes:
    buf = b""
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise OSError("short read")
        buf += chunk
    return buf


def _socks_session(conn: socket.socket) -> None:
    remote = None
    try:
        _readexact(conn, 3)
        conn.sendall(b"\x05\x00")
        head = _readexact(conn, 4)
        if head[3] != 3:
            return
        length = _readexact(conn, 1)[0]
        host = _readexact(conn, length).decode("idna")
        port = int.from_bytes(_readexact(conn, 2), "big")
        remote = socket.create_connection((host, port), 2.0)
        conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        _splice(conn, remote)
    except OSError:
        pass
    finally:
        conn.close()
        if remote is not None:
            remote.close()


def _splice(left: socket.socket, right: socket.socket) -> None:
    def pump(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    threads = (
        threading.Thread(target=pump, args=(left, right), daemon=True),
        threading.Thread(target=pump, args=(right, left), daemon=True),
    )
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=3)


def _serve_socks_clean(ready: list[int], stop: threading.Event) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    server.settimeout(0.2)
    ready.append(server.getsockname()[1])
    while not stop.is_set():
        try:
            conn, _addr = server.accept()
        except socket.timeout:
            continue
        threading.Thread(target=_socks_session, args=(conn,), daemon=True).start()
    server.close()


def test_e2e_cannot_be_disabled_and_get_does_not_enable(tmp_path: Path) -> None:
    node = Node(tmp_path)
    with pytest.raises(QNMRefuse) as exc:
        node.fed.local_op(admin(node), {"op": "e2e_off"})
    assert exc.value.code == "FED-POLICY"
    node.handle("GET", "/local/fedmesh")
    node.handle("GET", "/v1/fedmesh/health")
    assert node.fed.public_status()["e2e_mandatory"] is True
    assert node.fed.two_hop["enabled"] is False
    assert node.fed.tor.enabled is False
    assert node.fed.island is False
    assert node.fed.public_status()["zero_knowledge"] is False
    with pytest.raises(QNMRefuse) as name:
        node.fed.local_op(admin(node), {"op": "name"})
    assert name.value.code == "FED-WITNESS"


def test_peer_budget_breaker_and_local_quarantine(tmp_path: Path) -> None:
    host = Node(tmp_path / "host")
    peer = Node(tmp_path / "peer")
    other = Node(tmp_path / "other")
    host.fed.directory.remember_card(peer.fed.owner.card)
    host.fed.directory.remember_card(other.fed.owner.card)
    host.fed.set_relays(["http://127.0.0.1:9"])
    posts: list[str] = []
    host.fed.transport = lambda method, url, payload: posts.append(url) or {"ok": True}
    host.fed.peers.per_minute = 1
    host.fed.peers.breaker_threshold = 1
    assert host.fed.send_message(admin(host), other.fed.owner.handle, "hello-budget-note", share=True)["ok"] is True
    with pytest.raises(QNMRefuse) as quota:
        host.fed.send_message(admin(host), other.fed.owner.handle, "hello-budget-note", share=True)
    assert quota.value.code == "FED-PEER-QUOTA"
    with pytest.raises(QNMRefuse) as opened:
        host.fed.send_message(admin(host), other.fed.owner.handle, "hello-budget-note", share=True)
    assert opened.value.code == "FED-BREAKER"
    assert len(posts) == 1
    host.fed.peers.per_minute = 30
    host.fed.peers.breaker_threshold = 3
    host.fed.peers._fails.clear()
    host.fed.peers._open_until.clear()
    host.fed.peers._hits.clear()
    host.fed.quarantine_peer(peer.fed.owner.handle, cut=True)
    before = len(posts)
    with pytest.raises(QNMRefuse) as blocked:
        host.fed.send_message(admin(host), peer.fed.owner.handle, SECRET, share=True)
    assert blocked.value.code == "FED-QUARANTINE"
    assert len(posts) == before
    assert SECRET not in json.dumps(posts)
    assert host.fed.send_message(admin(host), other.fed.owner.handle, "still-open-for-others", share=True)["ok"] is True
    assert host.fed.owner.handle not in peer.fed.peers.quarantine
    assert host.fed.quarantine_peer(peer.fed.owner.handle, cut=False)["network_wide"] is False
    kinds = [row["kind"] for row in host.receipts()]
    assert "fedmesh_quarantine" in kinds


def test_island_mode_resync_has_no_fork(tmp_path: Path) -> None:
    running = Running()
    try:
        node, _node_url = running.up(tmp_path / "node")
        relay, relay_url = running.up(tmp_path / "relay")
        relay.fed.relay_on = True
        node.fed.set_relays([relay_url])
        digest = node.fed.put_object(admin(node), b"island-local-bytes")
        node.fed.enter_island()
        assert node.fed.island is True
        assert node.fed.relay_urls == []
        assert node.fed.put_object(admin(node), b"still-local")
        assert node.fed.run_task(admin(node), {"op": "add", "a": 2, "b": 2})["result"] == 4
        with pytest.raises(QNMRefuse) as blocked:
            node.fed.send_message(admin(node), "#aaaaaaaaaaa", SECRET, share=True)
        assert blocked.value.code == "FED-ISLAND"
        update = node.fed.push_ref(admin(node), "main", digest)
        assert node.fed.pending_refs
        assert SECRET not in json.dumps(update)
        again = Node(tmp_path / "node")
        assert again.fed.island is True
        assert again.fed.relay_urls == []
        left = node.fed.leave_island()
        assert left["island"] is False
        assert left["resync"]["refs_pending"] == 0
        assert relay.fed.held_refs[0]["object"] == digest
        clash = sign_ref(
            node.fed.owner.sign_private,
            handle=node.fed.owner.handle,
            key_id=node.fed.owner.key_id,
            sign_pub=str(node.fed.owner.card["sign_pub"]),
            ref="main",
            object_hash="ab" * 32,
            prev=GENESIS_PREV,
            seq=1,
            utc=utc_now(),
        )
        with pytest.raises(QNMRefuse) as fork:
            node.fed._apply_ref(clash)
        assert fork.value.code == "FED-FORK"
        assert node.fed.trust_view(node.fed.owner.handle)["equivocation"] is True
    finally:
        running.close()


def test_rollback_ref_is_a_fork(tmp_path: Path) -> None:
    node = Node(tmp_path)
    owner = node.fed.owner
    log = RefLog(tmp_path / "refs.jsonl")

    def update(seq: int, prev: str, obj: str) -> dict:
        return sign_ref(
            owner.sign_private,
            handle=owner.handle,
            key_id=owner.key_id,
            sign_pub=str(owner.card["sign_pub"]),
            ref="main",
            object_hash=obj,
            prev=prev,
            seq=seq,
            utc=utc_now(),
        )

    first = update(1, GENESIS_PREV, "ab" * 32)
    log.apply(first)
    second = update(2, first["hash"], "cd" * 32)
    log.apply(second)
    with pytest.raises(QNMRefuse) as exc:
        log.apply(update(2, first["hash"], "ef" * 32))
    assert exc.value.code == "FED-FORK"


def test_bad_hash_and_scanner_absent_promotion(tmp_path: Path) -> None:
    node = Node(tmp_path)
    with pytest.raises(QNMRefuse) as bad:
        node.fed.airlock.land(b"not-the-claimed-bytes", claimed="ab" * 32)
    assert bad.value.code == "FG-GATE-REFUSE"
    assert list(node.fed.airlock.root.glob("*")) == []
    payload = b"module-looking-bytes-print-hello"
    landed = node.fed.airlock.land(payload)
    mode = (node.fed.airlock.root / landed["sha256"]).stat().st_mode
    assert mode & 0o111 == 0
    runs = node.fed.sandbox_runs
    if node.fed.airlock.scan(landed["sha256"])["scanner_absent"]:
        with pytest.raises(QNMRefuse) as blocked:
            node.fed.promote_airlock(admin(node), landed["sha256"], override=False)
        assert blocked.value.code == "FED-AIRLOCK"
        promoted = node.fed.promote_airlock(admin(node), landed["sha256"], override=True)
        assert promoted["override"] is True
        assert any(row["verdict"] in ("absent", "rules-absent", "error") for row in promoted["scanners"])
    else:
        promoted = node.fed.promote_airlock(admin(node), landed["sha256"], override=False)
        assert promoted["override"] is False
    assert promoted["executed"] is False
    assert node.fed.sandbox_runs == runs
    assert node.fed.store.get(landed["sha256"]) == payload
    receipt = next(row for row in node.receipts() if row["kind"] == "fedmesh_airlock")
    assert receipt["body"]["object"] == landed["sha256"]
    assert payload.decode("utf-8") not in json.dumps(receipt)


def test_peer_code_is_not_executed(tmp_path: Path) -> None:
    running = Running()
    try:
        left, left_url = running.up(tmp_path / "left")
        right, right_url = running.up(tmp_path / "right")
        left.fed.directory.remember_card(right.fed.owner.card)
        right.fed.directory.remember_card(left.fed.owner.card)
        left.fed.mark_cluster(right.fed.owner.handle, right_url)
        right.fed.direct_on = True
        left.fed.direct_on = True
        left.fed.upstream_enabled = False
        before = right.fed.sandbox_runs
        marker = tmp_path / "should-not-exist"
        text = f"import os; os.remove({str(marker)!r})"
        sent = left.fed.send_message(admin(left), right.fed.owner.handle, text, share=True)
        assert sent["path"] == "cluster"
        assert right.fed.sandbox_runs == before
        assert not marker.exists()
        assert right.fed.inbox[-1]["text"] == text
    finally:
        running.close()


def test_two_hop_hides_destination_and_origin(tmp_path: Path) -> None:
    running = Running()
    try:
        sender, _sender_url = running.up(tmp_path / "sender")
        entry, entry_url = running.up(tmp_path / "entry")
        exit_node, exit_url = running.up(tmp_path / "exit")
        recipient, _recipient_url = running.up(tmp_path / "recipient")
        entry.fed.relay_on = True
        exit_node.fed.relay_on = True
        sender.fed.directory.remember_card(exit_node.fed.owner.card)
        sender.fed.directory.remember_card(recipient.fed.owner.card)
        sender.fed.enable_two_hop(entry_url, exit_url, exit_node.fed.owner.handle)
        sent = sender.fed.send_message(admin(sender), recipient.fed.owner.handle, SECRET, share=True)
        assert sent["path"] == "two-hop"
        assert sent["e2e"] is True
        outer = (entry.root / "data" / "fedmesh" / "hops-outer.jsonl").read_text(encoding="utf-8")
        assert sender.fed.owner.handle in outer
        assert recipient.fed.owner.handle not in outer
        assert SECRET not in outer
        exit_node.fed.hop_sources = [entry_url]
        exit_node.fed.pull_hops()
        view = json.dumps(exit_node.fed.delivered_hop_views)
        assert sender.fed.owner.handle not in view
        assert SECRET not in view
        blind = (exit_node.root / "data" / "fedmesh" / "blinds.jsonl").read_text(encoding="utf-8")
        assert sender.fed.owner.handle not in blind
        assert recipient.fed.owner.handle in blind
        assert SECRET not in blind
        recipient.fed.hop_sources = [exit_url]
        got = recipient.fed.pull_blinds()
        assert got[0]["text"] == SECRET
    finally:
        running.close()


def test_tor_adapter_uses_proxy_and_does_not_fall_back(tmp_path: Path) -> None:
    running = Running()
    stop = threading.Event()
    ready: list[int] = []
    threading.Thread(target=_serve_socks_clean, args=(ready, stop), daemon=True).start()
    while not ready:
        stop.wait(0.01)
    try:
        sender, _sender_url = running.up(tmp_path / "sender")
        relay, relay_url = running.up(tmp_path / "relay")
        peer, _peer_url = running.up(tmp_path / "peer")
        relay.fed.relay_on = True
        sender.fed.directory.remember_card(peer.fed.owner.card)
        http_json("POST", relay_url + "/v1/fedmesh/register", peer.fed.owner.card)
        sender.fed.set_relays([relay_url])
        sender.fed.tor.configure(f"127.0.0.1:{ready[0]}", enabled=True)
        sent = sender.fed.send_message(admin(sender), peer.fed.owner.handle, SECRET, share=True)
        assert sent["path"] == "relay"
        spool = (relay.root / "data" / "fedmesh" / "spool").read_text(encoding="utf-8") if False else ""
        spool = "".join(path.read_text(encoding="utf-8") for path in (relay.root / "data" / "fedmesh" / "spool").glob("*.jsonl"))
        assert SECRET not in spool
        assert "ciphertext" in spool
        sender.fed.tor.configure("127.0.0.1:1", enabled=True)
        with pytest.raises(QNMRefuse) as missing:
            sender.fed.send_message(admin(sender), peer.fed.owner.handle, SECRET, share=True)
        assert missing.value.code == "FED-TOR-ABSENT"
        assert sender.fed.tor.status()["custom_onion"] is False
        assert sender.fed.tor.status()["zero_knowledge"] is False
        assert sender.fed.public_status()["state_level_adversary"] is False
    finally:
        stop.set()
        running.close()


def test_airgap_bundle_verifies_and_rejects_tamper(tmp_path: Path) -> None:
    node = Node(tmp_path / "node")
    other = Node(tmp_path / "other")
    digest = node.fed.put_object(admin(node), b"sneakernet-bytes")
    dest = tmp_path / "bundle"
    exported = node.fed.export_airgap(str(dest), [digest])
    assert exported["sha256sum"] is True
    assert exported["live"] is False
    assert not (dest / "private.seal").exists()
    if shutil.which("sha256sum"):
        checked = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=dest, capture_output=True, text=True, check=False)
        assert checked.returncode == 0, checked.stderr
    else:
        assert check_sha256sums((dest / "SHA256SUMS").read_text(encoding="utf-8"), dest)
    imported = other.fed.import_airgap(str(dest))
    assert imported["verified"] is True
    assert imported["promoted"] is False
    assert other.fed.airlock.has(digest)
    assert not other.fed.store.has(digest)
    (dest / digest).write_bytes(b"tampered-sneakernet-bytes")
    with pytest.raises(QNMRefuse) as exc:
        other.fed.import_airgap(str(dest))
    assert exc.value.code == "FG-GATE-REFUSE"


def test_advisory_is_local_and_trust_has_no_score(tmp_path: Path) -> None:
    publisher = Node(tmp_path / "publisher")
    subscriber = Node(tmp_path / "subscriber")
    bystander = Node(tmp_path / "bystander")
    peer = "#bbbbbbbbbbb"
    statement = local_statement(
        publisher.fed.owner.sign_private,
        handle=publisher.fed.owner.handle,
        kind="advisory",
        fields={"entries": [{"peer": peer, "note": "local flag only", "until": "2026-12-01"}]},
        seq=1,
        prev=GENESIS_PREV,
    )
    subscribed = subscriber.fed.subscribe_advisory(statement)
    assert subscribed["affects"] == "subscriber"
    assert subscriber.fed.trust_view(peer)["advisory"] is True
    assert bystander.fed.trust_view(peer)["advisory"] is False
    blob = json.dumps(subscriber.fed.trust_view(publisher.fed.owner.handle))
    assert "score" not in blob
    broken = dict(statement)
    broken["sig"] = ("A" if not str(broken["sig"]).startswith("A") else "B") + str(broken["sig"])[1:]
    with pytest.raises(QNMRefuse):
        bystander.fed.subscribe_advisory(broken)
    vouched = subscriber.fed.vouch_peer(peer)
    assert vouched["local_only"] is True
    assert subscriber.fed.trust_view(peer)["vouches"] == 1
    assert bystander.fed.trust_view(peer)["vouches"] == 0


def test_cross_node_keystore_stays_closed(tmp_path: Path) -> None:
    left = Node(tmp_path / "left")
    right = Node(tmp_path / "right")
    left_seal = tmp_path / "left" / "data" / "identity"
    right_pass = (tmp_path / "right" / "data" / "identity" / "unattended.seal").read_bytes()
    with pytest.raises(QNMRefuse) as exc:
        open_keystore(left_seal, right_pass)
    assert exc.value.code == "FED-PASSPHRASE"
    with pytest.raises(QNMRefuse) as api:
        right.fed.local_op(admin(right), {"op": "tenant_key", "handle": left.fed.owner.handle})
    assert api.value.code == "FED-TENANT"
    assert left.fed.owner.handle != right.fed.owner.handle

