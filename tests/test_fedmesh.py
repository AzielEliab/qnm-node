"""Local-first edge mesh on the qnm daemon.

Covers handles, isolated instances, relay exchange, receipt-chain
negatives, quotas, roles, end-to-end ciphertext, rollups, multisig,
failover, discovery, store-and-forward, edge opt-in, the outbound
filter, and offline cluster sync.
"""

from __future__ import annotations

import json
import re
import stat
import threading
from io import StringIO
from pathlib import Path

import pytest

from qnm.boot import AUTHOR, IDENTITY, QNMRefuse
from qnm.fedmesh.access import GUEST_GET, Actor
from qnm.fedmesh.chain import Ledger
from qnm.fedmesh.identity import open_keystore
from qnm.fedmesh.objects import ObjectStore, RefLog
from qnm.fedmesh.policy import Outbound
from qnm.fedmesh.relay import http_json
from qnm.fedmesh.wire import (
    GENESIS_PREV,
    make_anchor,
    sign_peer_list,
    sign_ref,
    utc_now,
    b64d,
    handle_from_pubkey,
    key_id_from_pubkey,
)
from qnm.node import LOCAL_PATHS, Node, main, serve

HANDLE_RE = re.compile(r"^#[0-9A-HJKMNP-TV-Z]{11}$")
SECRET = "fedmesh-raw-secret-not-for-the-wire-9f3c"
FILE_SECRET = "neighborhood-file-bytes-stay-local-until-shared-77ab"


def admin(node: Node) -> Actor:
    return Actor("admin", node.fed.owner.handle, via="loopback")


def tree_text(path: Path) -> str:
    parts: list[str] = []
    if not path.exists():
        return ""
    for item in path.rglob("*"):
        if item.is_file():
            parts.append(item.read_bytes().decode("utf-8", "replace"))
    return "\n".join(parts)


class Running:
    def __init__(self) -> None:
        self.servers = []

    def up(self, root: Path) -> tuple[Node, str]:
        node = Node(root)
        server = serve(node, "127.0.0.1", 0)
        port = server.server_address[1]
        url = f"http://127.0.0.1:{port}"
        node.fed.note_base(url)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.servers.append(server)
        return node, url

    def close(self) -> None:
        for server in self.servers:
            server.shutdown()
            server.server_close()
        self.servers.clear()


def cluster_pair(left: Node, right: Node, left_url: str, right_url: str) -> None:
    left.fed.directory.remember_card(right.fed.owner.card)
    right.fed.directory.remember_card(left.fed.owner.card)
    left.fed.mark_cluster(right.fed.owner.handle, right_url)
    right.fed.mark_cluster(left.fed.owner.handle, left_url)
    left.fed.direct_on = True
    right.fed.direct_on = True


def test_handle_matches_key_and_author_stays(tmp_path: Path) -> None:
    node = Node(tmp_path)
    raw = b64d(str(node.fed.owner.card["sign_pub"]))
    assert HANDLE_RE.fullmatch(node.fed.owner.handle)
    assert handle_from_pubkey(raw) == node.fed.owner.handle
    assert key_id_from_pubkey(raw) == node.fed.owner.key_id
    assert len(node.fed.owner.key_id) == 64
    assert node.identity == IDENTITY == "Aziel Eliab"
    assert node.author == AUTHOR
    seal = tmp_path / "data" / "identity" / "private.seal"
    unattended = tmp_path / "data" / "identity" / "unattended.seal"
    assert stat.S_IMODE(seal.stat().st_mode) == 0o600
    assert stat.S_IMODE(unattended.stat().st_mode) == 0o600
    status = node.fed.public_status()
    assert status["anonymity"] is False
    assert status["nat_traversal"] is False
    assert status["e2e_forward_secrecy"] is False
    assert status["raw_leaves_only_on_share"] is True
    assert status["bluetooth"]["mesh_transport"] is False
    assert status["bluetooth"]["default_on"] is False
    assert status["relay_listen"] is False
    blob = json.dumps(node.snapshot())
    assert "sign_seed" not in blob
    assert "box_seed" not in blob
    boot = node.receipts()[0]
    from qnm.fedmesh.secwire import verify_identity_anchor
    from qnm.nolie import receipt_digest

    assert boot["receipt_hash"] == receipt_digest(boot)
    verify_identity_anchor(boot["identity_anchor"])
    assert boot["identity_anchor"]["receipt_hash"] == boot["receipt_hash"]
    assert boot["identity_anchor"]["handle"] == node.fed.owner.handle
    assert "key_id" not in boot["identity_anchor"]
    assert node.fed.public_status()["chainlock_upstream"] is False


def test_three_instances_do_not_share_keys(tmp_path: Path) -> None:
    nodes = [Node(tmp_path / name) for name in ("a", "b", "c")]
    handles = {node.fed.owner.handle for node in nodes}
    seals = {(node.root / "data" / "identity" / "private.seal").read_bytes() for node in nodes}
    assert len(handles) == 3
    assert len(seals) == 3
    for node in nodes:
        assert node.identity == "Aziel Eliab"


def test_cli_profiles_and_doctor(tmp_path: Path) -> None:
    base = tmp_path / "instances"
    first = StringIO()
    second = StringIO()
    import contextlib

    with contextlib.redirect_stdout(first):
        assert main(["doctor", "--data-dir", str(base), "--profile", "alpha"]) == 0
    with contextlib.redirect_stdout(second):
        assert main(["doctor", "--data-dir", str(base), "--profile", "beta"]) == 0
    alpha = json.loads(first.getvalue())
    beta = json.loads(second.getvalue())
    assert alpha["identity"] == "Aziel Eliab"
    assert alpha["anonymity"] is False
    assert alpha["relay_listen"] is False
    assert alpha["nat_traversal"] is False
    assert alpha["raw_leaves_only_on_share"] is True
    assert HANDLE_RE.fullmatch(alpha["mesh_handle"])
    assert alpha["mesh_handle"] != beta["mesh_handle"]
    with pytest.raises(QNMRefuse) as exc:
        from qnm.node import instance_directory

        instance_directory("/tmp/one-root", str(tmp_path / "other"))
    assert exc.value.code == "FED-PROFILE"


def test_receipt_chain_negatives(tmp_path: Path) -> None:
    node = Node(tmp_path)
    owner = node.fed.owner
    ledger = Ledger(tmp_path / "ledger.jsonl")

    def anchor(seq: int, prev: str, payload: str) -> dict:
        return make_anchor(
            owner.sign_private,
            handle=owner.handle,
            key_id=owner.key_id,
            sign_pub=str(owner.card["sign_pub"]),
            seq=seq,
            prev=prev,
            payload_hash_hex=payload,
        )

    first = anchor(1, GENESIS_PREV, "ab" * 32)
    ledger.submit(first)
    with pytest.raises(QNMRefuse) as replay:
        ledger.submit(dict(first))
    assert replay.value.code == "FED-REPLAY"

    forked = Ledger(tmp_path / "fork.jsonl")
    forked.submit(first)
    with pytest.raises(QNMRefuse) as fork:
        forked.submit(anchor(1, GENESIS_PREV, "cd" * 32))
    assert fork.value.code == "FED-FORK"

    gapped = Ledger(tmp_path / "gap.jsonl")
    gapped.submit(first)
    with pytest.raises(QNMRefuse) as gap:
        gapped.submit(anchor(3, first["hash"], "ef" * 32))
    assert gap.value.code == "FED-GAP"

    wrong = dict(first)
    wrong["handle"] = "#bbbbbbbbbbb"
    with pytest.raises(QNMRefuse) as key:
        Ledger(tmp_path / "key.jsonl").submit(wrong)
    assert key.value.code == "FED-WRONG-KEY"

    tampered = dict(first)
    tampered["payload_hash"] = "ff" * 32
    with pytest.raises(QNMRefuse) as tamper:
        Ledger(tmp_path / "tamper.jsonl").submit(tampered)
    assert tamper.value.code == "FED-TAMPER"


def test_ref_fork_reuses_receipt_check(tmp_path: Path) -> None:
    node = Node(tmp_path)
    owner = node.fed.owner
    log = RefLog(tmp_path / "refs.jsonl")
    left = sign_ref(
        owner.sign_private,
        handle=owner.handle,
        key_id=owner.key_id,
        sign_pub=str(owner.card["sign_pub"]),
        ref="main",
        object_hash="ab" * 32,
        prev=GENESIS_PREV,
        seq=1,
        utc=utc_now(),
    )
    right = sign_ref(
        owner.sign_private,
        handle=owner.handle,
        key_id=owner.key_id,
        sign_pub=str(owner.card["sign_pub"]),
        ref="main",
        object_hash="cd" * 32,
        prev=GENESIS_PREV,
        seq=1,
        utc=utc_now(),
    )
    log.apply(left)
    with pytest.raises(QNMRefuse) as exc:
        log.apply(right)
    assert exc.value.code == "FED-FORK"


def test_object_bytes_are_verified(tmp_path: Path) -> None:
    store = ObjectStore(tmp_path / "objects")
    digest = store.put(b"local-object")
    assert stat.S_IMODE((tmp_path / "objects" / digest).stat().st_mode) == 0o600
    path = tmp_path / "objects" / digest
    path.write_bytes(b"tampered-bytes")
    with pytest.raises(QNMRefuse) as exc:
        store.get(digest)
    assert exc.value.code == "FED-TAMPER"


def test_outbound_filter_blocks_raw_without_share(tmp_path: Path) -> None:
    node = Node(tmp_path)
    posts: list[tuple] = []
    node.fed.transport = lambda method, url, payload: posts.append((method, url, payload)) or {"ok": True}
    with pytest.raises(QNMRefuse) as refused:
        node.fed.send_message(admin(node), "#ccccccccccc", SECRET, share=False)
    assert refused.value.code == "FED-POLICY"
    assert posts == []
    assert SECRET not in tree_text(tmp_path / "data")
    policy = Outbound()
    policy.hold(SECRET)
    with pytest.raises(QNMRefuse) as raw:
        policy.guard({"kind": "msg", "text": SECRET}, share=True)
    assert raw.value.code == "FED-POLICY"
    light = {"v": "FED-MESH-1.0-draft", "kind": "digest", "author": AUTHOR, "handle": node.fed.owner.handle}
    assert policy.guard(light, share=False)["kind"] == "digest"


def test_get_never_enables(tmp_path: Path) -> None:
    node = Node(tmp_path)
    before_bearers = dict(node.bearers.snapshot())
    radios = node.snapshot()["radios"]
    code, health = node.handle("GET", "/v1/fedmesh/health")
    assert code == 200
    assert health["enabled_by_get"] is False
    assert health["relay"] is False
    node.handle("GET", "/local/fedmesh")
    mesh_code, mesh = node.handle("GET", "/v1/mesh")
    assert mesh_code == 403
    assert mesh["code"] == "QNM-MESH-NEVER-ENABLES"
    assert node.fed.relay_on is False
    assert node.fed.direct_on is False
    assert node.fed.edge_on is False
    assert node.fed.lan_on is False
    assert node.bearers.snapshot() == before_bearers
    assert node.snapshot()["radios"] == radios
    assert node.fed.public_status()["use_default_relay"] is False


def test_roles_on_local_routes(tmp_path: Path) -> None:
    node = Node(tmp_path)
    guest = Actor("guest", node.fed.owner.handle, via="token")
    developer = Actor("developer", node.fed.owner.handle, via="token")
    for route in sorted(LOCAL_PATHS):
        code, payload = node.handle("GET", route, b"", actor=guest)
        if route in GUEST_GET:
            assert payload.get("code") != "FED-ROLE", route
        else:
            assert code == 403 and payload.get("code") == "FED-ROLE", (route, payload)
        if route == "/local/fedmesh":
            continue
        for actor in (guest, developer):
            post_code, post = node.handle("POST", route, b"{}", actor=actor)
            assert post_code == 403 and post.get("code") == "FED-ROLE", (route, actor.role, post)
    guest_task = json.dumps({"op": "task", "job": {"op": "add", "a": 1, "b": 1}}).encode()
    assert node.handle("POST", "/local/fedmesh", guest_task, actor=guest)[1]["code"] == "FED-ROLE"
    guest_msg = json.dumps(
        {"op": "message", "to": "#aaaaaaaaaaa", "text": "hello-guest-note", "share": False}
    ).encode()
    assert node.handle("POST", "/local/fedmesh", guest_msg, actor=guest)[1]["code"] == "FED-POLICY"
    dev_task = node.handle("POST", "/local/fedmesh", guest_task, actor=developer)[1]
    assert dev_task.get("code") != "FED-ROLE"
    assert dev_task.get("ok") is True
    assert dev_task.get("result") == 2


def test_http_role_token_is_enforced(tmp_path: Path) -> None:
    running = Running()
    try:
        node, url = running.up(tmp_path)
        token = node.fed.grant_role("guest", node.fed.owner.handle)
        body = json.dumps({"name": "lan", "on": True}).encode()
        import urllib.error
        import urllib.request

        req = urllib.request.Request(url + "/local/bearer", data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-QNM-Role-Token", token)
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(req, timeout=2)
        payload = json.loads(exc.value.read().decode("utf-8"))
        assert exc.value.code == 403
        assert payload["code"] == "FED-ROLE"
        assert node.bearers.snapshot()["lan"] is False
    finally:
        running.close()


def test_tenant_quota_isolation_and_locked_keys(tmp_path: Path) -> None:
    node = Node(tmp_path)
    host = admin(node)
    passphrase = "tenant-pass-phrase"
    other_pass = "other-tenant-pass"
    made = node.fed.create_tenant(passphrase, role="developer")
    other = node.fed.create_tenant(other_pass, role="developer")
    tenant = Actor("developer", made["handle"], via="token")
    other_actor = Actor("developer", other["handle"], via="token")
    with pytest.raises(QNMRefuse) as unlocked:
        node.fed.run_task(tenant, {"op": "add", "a": 1, "b": 1})
    assert unlocked.value.code == "FED-PASSPHRASE"
    with pytest.raises(QNMRefuse) as admin_open:
        node.fed.unlock(host, made["handle"], passphrase)
    assert admin_open.value.code == "FED-TENANT"
    node.fed.unlock(tenant, made["handle"], passphrase)
    node.fed.unlock(other_actor, other["handle"], other_pass)
    with pytest.raises(QNMRefuse) as key_api:
        node.fed.local_op(host, {"op": "keystore"})
    assert key_api.value.code == "FED-TENANT"
    seal_path = Path(node.fed.tenants[made["handle"]]["dir"]) / "private.seal"
    assert passphrase not in seal_path.read_text(encoding="utf-8")
    opened = open_keystore(Path(node.fed.tenants[made["handle"]]["dir"]), passphrase.encode())
    assert opened.handle == made["handle"]
    with pytest.raises(QNMRefuse):
        open_keystore(Path(node.fed.tenants[made["handle"]]["dir"]), b"wrong-pass-phrase")

    node.fed.set_quota(made["handle"], {"memory_bytes": 64, "cpu_seconds": 0.2, "wall_seconds": 1, "tasks_per_minute": 10})
    node.fed.set_quota(other["handle"], {"storage_bytes": 100000, "tasks_per_minute": 10})
    limited = node.fed.run_task(tenant, {"op": "alloc", "bytes": 4096})
    assert limited["code"] == "FED-QUOTA"
    burned = node.fed.run_task(tenant, {"op": "burn", "seconds": 5})
    assert burned["code"] == "FED-QUOTA"
    node.fed.set_quota(made["handle"], {"wall_seconds": 0.4, "cpu_seconds": 2, "tasks_per_minute": 10})
    hung = node.fed.run_task(tenant, {"op": "hang"})
    assert hung["code"] == "FED-QUOTA"
    crashed = node.fed.run_task(tenant, {"op": "crash"})
    assert crashed["code"] == "FED-SANDBOX"
    still = node.fed.run_task(other_actor, {"op": "add", "a": 2, "b": 3})
    assert still["ok"] is True and still["result"] == 5
    node.fed.set_quota(made["handle"], {"storage_bytes": 8})
    with pytest.raises(QNMRefuse) as storage:
        node.fed.put_object(tenant, b"0123456789abcdef")
    assert storage.value.code == "FED-QUOTA"
    assert node.fed.put_object(other_actor, b"ok")
    node.fed.rate[made["handle"]] = []
    node.fed.set_quota(made["handle"], {"tasks_per_minute": 1, "storage_bytes": 1000})
    assert node.fed.run_task(tenant, {"op": "add", "a": 1, "b": 0})["ok"] is True
    with pytest.raises(QNMRefuse) as rate:
        node.fed.run_task(tenant, {"op": "add", "a": 1, "b": 0})
    assert rate.value.code == "FED-RATE"
    digest = node.fed.put_object(tenant, FILE_SECRET.encode())
    with pytest.raises(QNMRefuse) as share:
        node.fed.fetch_object(other_actor, digest)
    assert share.value.code == "FED-SHARE"
    with pytest.raises(QNMRefuse) as host_read:
        node.fed.fetch_object(host, digest)
    assert host_read.value.code == "FED-SHARE"
    node.fed.share_object(tenant, digest, other["handle"])
    assert node.fed.fetch_object(other_actor, digest) == FILE_SECRET.encode()
    blob = tree_text(tmp_path / "data")
    assert passphrase not in blob
    assert other_pass not in blob
    assert "sign_seed" not in blob


def test_messages_are_ciphertext_and_tamper_fails(tmp_path: Path) -> None:
    running = Running()
    try:
        sender, _sender_url = running.up(tmp_path / "a")
        relay, relay_url = running.up(tmp_path / "r")
        peer, _peer_url = running.up(tmp_path / "b")
        relay.fed.relay_on = True
        sender.fed.set_relays([relay_url])
        peer.fed.set_relays([relay_url])
        http_json("POST", relay_url + "/v1/fedmesh/register", peer.fed.owner.card)
        sent = sender.fed.send_message(admin(sender), peer.fed.owner.handle, SECRET, share=True)
        assert sent["path"] == "relay"
        assert sent["e2e"] is True
        spool = tree_text(relay.root / "data" / "fedmesh" / "spool")
        assert SECRET not in spool
        assert "ciphertext" in spool
        stolen = json.loads(
            next(path for path in (relay.root / "data" / "fedmesh" / "spool").glob("*.jsonl")).read_text().splitlines()[0]
        )["envelope"]
        stolen["ciphertext"] = ("A" if stolen["ciphertext"][:1] != "A" else "B") + stolen["ciphertext"][1:]
        with pytest.raises(QNMRefuse) as tamper:
            peer.fed.ingest(stolen)
        assert tamper.value.code in ("FED-E2E", "FED-TAMPER")
        got = peer.fed.poll()
        assert got and got[0]["text"] == SECRET
        assert any(row["kind"] == "fedmesh_delivery" for row in peer.receipts())
        again = peer.fed.poll()
        assert again == []
        assert SECRET not in tree_text(relay.root / "data" / "fedmesh")
    finally:
        running.close()


def test_store_and_forward_then_delivery(tmp_path: Path) -> None:
    running = Running()
    try:
        sender, _ = running.up(tmp_path / "a")
        relay, relay_url = running.up(tmp_path / "r")
        peer, _peer_url = running.up(tmp_path / "b")
        relay.fed.relay_on = True
        sender.fed.set_relays([relay_url])
        peer.fed.set_relays([relay_url])
        http_json("POST", relay_url + "/v1/fedmesh/register", peer.fed.owner.card)
        sender.fed.send_file(admin(sender), peer.fed.owner.handle, "note.txt", FILE_SECRET, share=True)
        held = tree_text(relay.root / "data" / "fedmesh" / "spool")
        assert FILE_SECRET not in held
        assert peer.fed.inbox == []
        delivered = peer.fed.poll()
        assert delivered[0]["text"] == FILE_SECRET
        assert any(row["kind"] == "fedmesh_delivery" for row in peer.receipts())
    finally:
        running.close()


def test_failover_when_one_relay_and_one_peer_die(tmp_path: Path) -> None:
    running = Running()
    try:
        sender, _ = running.up(tmp_path / "a")
        peer_b, _ = running.up(tmp_path / "b")
        peer_c, _ = running.up(tmp_path / "c")
        relay_1, url_1 = running.up(tmp_path / "r1")
        relay_2, url_2 = running.up(tmp_path / "r2")
        relay_1.fed.relay_on = True
        relay_2.fed.relay_on = True
        sender.fed.direct_on = False
        sender.fed.set_relays([url_1, url_2])
        peer_c.fed.set_relays([url_1, url_2])
        for url in (url_1, url_2):
            http_json("POST", url + "/v1/fedmesh/register", peer_c.fed.owner.card)
            http_json("POST", url + "/v1/fedmesh/register", peer_b.fed.owner.card)
        first = sender.fed.send_message(admin(sender), peer_c.fed.owner.handle, SECRET, share=True)
        assert len(first["relays"]) == 2
        assert SECRET not in tree_text(relay_1.root / "data" / "fedmesh" / "spool")
        assert SECRET not in tree_text(relay_2.root / "data" / "fedmesh" / "spool")
        running.servers[3].shutdown()
        running.servers[1].shutdown()
        second = sender.fed.send_message(admin(sender), peer_c.fed.owner.handle, FILE_SECRET, share=True)
        assert second["relays"] == [url_2]
        got = peer_c.fed.poll()
        texts = {row["text"] for row in got}
        assert SECRET in texts
        assert FILE_SECRET in texts
    finally:
        running.close()


def test_poisoned_peer_list_and_lan_discovery(tmp_path: Path) -> None:
    node = Node(tmp_path / "a")
    owner = node.fed.owner
    before = set(node.fed.directory.cards)
    huge = sign_peer_list(
        owner.sign_private,
        sender_handle=owner.handle,
        sign_pub=str(owner.card["sign_pub"]),
        relays=["http://127.0.0.1:9"] * 9,
        peers=[],
    )
    with pytest.raises(QNMRefuse) as poison:
        node.fed.directory.merge_peer_list(huge)
    assert poison.value.code == "FED-POISON"
    assert set(node.fed.directory.cards) == before
    assert node.fed.directory.relays == []
    good = sign_peer_list(
        owner.sign_private,
        sender_handle=owner.handle,
        sign_pub=str(owner.card["sign_pub"]),
        relays=["http://127.0.0.1:9"],
        peers=[],
    )
    assert node.fed.directory.merge_peer_list(good, rate_limit=2)["ok"] is True
    with pytest.raises(QNMRefuse) as limited:
        node.fed.directory.merge_peer_list(good, rate_limit=2)
    assert limited.value.code == "FED-POISON"

    running_nodes = [Node(tmp_path / "lan-a"), Node(tmp_path / "lan-b")]
    left, right = running_nodes
    left.fed.lan_on = True
    right.fed.lan_on = True
    left.fed.note_base("http://127.0.0.1:1")
    sock = right.fed.listen_lan()
    try:
        left.fed.announce_peers([(sock.host, sock.port)])
        assert right.fed.lan.poll(right.fed.ingest_lan, rounds=6) >= 1
        assert left.fed.owner.handle in right.fed.cluster
        known = set(right.fed.directory.cards)
        assert left.fed.lan is not None
        left.fed.lan.sock.sendto(b"QNM1" + b"{not-json", (sock.host, sock.port))
        assert right.fed.lan.poll(right.fed.ingest_lan, rounds=4) == 0
        assert set(right.fed.directory.cards) == known
    finally:
        if left.fed.lan is not None:
            left.fed.lan.close()
        sock.close()


def test_multisig_threshold(tmp_path: Path) -> None:
    running = Running()
    try:
        host, host_url = running.up(tmp_path / "host")
        peer, peer_url = running.up(tmp_path / "peer")
        cluster_pair(host, peer, host_url, peer_url)
        made = host.fed.create_tenant("multisig-passphrase", role="developer")
        tenant = Actor("developer", made["handle"], via="token")
        host.fed.unlock(tenant, made["handle"], "multisig-passphrase")
        host.fed.configure_vault(2, 2, [host.fed.owner.handle, made["handle"]], enabled=True)
        pending = host.fed.send_message(admin(host), peer.fed.owner.handle, SECRET, share=True)
        assert pending["pending"] is True
        assert pending["have"] == 1
        assert peer.fed.inbox == []
        routed = host.fed.approve(tenant, pending["subject"])
        assert routed["pending"] is False
        assert routed["path"] == "cluster"
        assert peer.fed.inbox[-1]["text"] == SECRET
        lone = Node(tmp_path / "lone")
        assert lone.fed.vault["enabled"] is False
    finally:
        running.close()


def test_offline_cluster_then_upstream_sync(tmp_path: Path) -> None:
    running = Running()
    try:
        left, left_url = running.up(tmp_path / "left")
        right, right_url = running.up(tmp_path / "right")
        relay, relay_url = running.up(tmp_path / "relay")
        relay.fed.relay_on = True
        cluster_pair(left, right, left_url, right_url)
        left.fed.upstream_enabled = False
        right.fed.upstream_enabled = False
        left.fed.set_relays(["http://127.0.0.1:1"])
        right.fed.set_relays(["http://127.0.0.1:1"])
        sent = left.fed.send_message(admin(left), right.fed.owner.handle, SECRET, share=True)
        assert sent["path"] == "cluster"
        assert right.fed.inbox[-1]["text"] == SECRET
        digest = left.fed.put_object(admin(left), FILE_SECRET.encode())
        left.fed.share_object(admin(left), digest, right.fed.owner.handle)
        assert right.fed.fetch_object(admin(right), digest) == FILE_SECRET.encode()
        changes = [{"kind": "ref", "ref": "main", "object": digest}]
        left_sig = left.fed.sign_rollup(admin(left), changes)
        right_sig = right.fed.sign_rollup(admin(right), changes)
        built = left.fed.build_rollup(
            admin(left),
            changes,
            [
                {"anchor": left_sig["anchor"], "projection": left_sig["projection"]},
                {"anchor": right_sig["anchor"], "projection": right_sig["projection"]},
            ],
        )
        staged = left.fed.stage_rollup(built["rollup"])
        assert staged["pushed"] is False
        assert staged["chainlock_upstream"] is False
        assert staged["temporal_lock"] is False
        assert right.fed.held_rollups
        rollup_blob = json.dumps(built["rollup"])
        assert FILE_SECRET not in rollup_blob
        assert SECRET not in rollup_blob
        left.fed.set_relays([relay_url])
        left.fed.upstream_enabled = True
        synced = left.fed.sync()
        assert synced["rollups_pending"] == 0
        assert relay.fed.held_rollups
        assert FILE_SECRET not in json.dumps(relay.fed.held_rollups)
        assert FILE_SECRET not in tree_text(relay.root / "data" / "fedmesh" / "spool")
    finally:
        running.close()


def test_offline_refs_sync_after_reconnect(tmp_path: Path) -> None:
    running = Running()
    try:
        node, _ = running.up(tmp_path / "node")
        relay, relay_url = running.up(tmp_path / "relay")
        relay.fed.relay_on = True
        node.fed.upstream_enabled = False
        node.fed.direct_on = False
        digest = node.fed.put_object(admin(node), FILE_SECRET.encode())
        update = node.fed.push_ref(admin(node), "main", digest)
        assert update["kind"] == "ref"
        assert update["object"] == digest
        assert FILE_SECRET not in json.dumps(update)
        assert node.fed.pending_refs
        node.fed.set_relays([relay_url])
        node.fed.upstream_enabled = True
        synced = node.fed.sync()
        assert synced["refs_pending"] == 0
        assert relay.fed.held_refs
        assert relay.fed.held_refs[0]["object"] == digest
        assert FILE_SECRET not in json.dumps(relay.fed.held_refs)
    finally:
        running.close()


def test_edge_compute_is_opt_in(tmp_path: Path) -> None:
    running = Running()
    try:
        guest, guest_url = running.up(tmp_path / "guest")
        host, host_url = running.up(tmp_path / "host")
        cluster_pair(guest, host, guest_url, host_url)
        host.fed.upstream_enabled = False
        guest.fed.upstream_enabled = False
        before = host.fed.sandbox_runs
        with pytest.raises(QNMRefuse) as refused:
            guest.fed.send_edge(
                admin(guest),
                host.fed.owner.handle,
                {"op": "echo", "text": SECRET},
                share=True,
            )
        assert refused.value.code == "FED-EDGE-OFF"
        assert host.fed.sandbox_runs == before
        host.fed.edge_on = True
        accepted = guest.fed.send_edge(
            admin(guest),
            host.fed.owner.handle,
            {"op": "echo", "text": SECRET},
            share=True,
        )
        assert accepted["path"] == "cluster"
        assert host.fed.sandbox_runs == before + 1
        kinds = [row["kind"] for row in host.receipts()]
        assert "fedmesh_edge_host" in kinds
        assert SECRET not in tree_text(host.root / "data" / "receipts")
        assert any(row["kind"] == "fedmesh_msg" for row in guest.receipts())
    finally:
        running.close()


def test_runtime_fixture_handle_envelope_and_isolation() -> None:
    """Daemon opens the runtime schedule and the published isolation vector."""
    import base64

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    from qnm.fedmesh.secwire import verify_identity_anchor, verify_isolation_statement
    from qnm.fedmesh.wire import (
        MSG_VERSION,
        b64url,
        b64url_d,
        canonical,
        decode_pub,
        handle_from_pubkey,
        key_id_from_pubkey,
        message_info,
        open_envelope,
        open_message_body,
        seal_envelope,
        seal_runtime_body,
        sha256_hex,
        sign_box_binding,
    )

    vectors = json.loads((Path(__file__).parent / "fixtures" / "fed-mesh-vectors.json").read_text(encoding="utf-8"))
    sign_private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(vectors["seed_hex"]))
    sign_raw = sign_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert handle_from_pubkey(sign_raw) == "#CPV0CWYPXP4"
    assert b64url(sign_raw) == vectors["public_key"]
    enc_private = X25519PrivateKey.from_private_bytes(bytes.fromhex(vectors["enc_seed_hex"]))
    enc_raw = enc_private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert b64url(enc_raw) == vectors["enc_public_key"]
    verify_identity_anchor(vectors["identity_anchor"])
    verify_isolation_statement(vectors["isolation"]["record"])
    record = vectors["isolation"]["record"]
    statement = {key: value for key, value in record.items() if key != "sig"}
    assert sha256_hex(canonical(statement)) == vectors["isolation"]["statement_hash"]

    sender = {
        "v": "FED-MESH-1.0-draft",
        "author": AUTHOR,
        "handle": vectors["handle"],
        "key_id": key_id_from_pubkey(sign_raw),
        "sign_pub": base64.b64encode(sign_raw).decode("ascii"),
        "box_pub": base64.b64encode(enc_raw).decode("ascii"),
    }
    sender["box_sig"] = sign_box_binding(
        sign_private, sender["handle"], sender["key_id"], sender["sign_pub"], sender["box_pub"]
    )
    body = b"cross-vector"
    eph = X25519PrivateKey.generate()
    nonce = b"\x01" * 12
    sealed = seal_runtime_body(
        recipient_public=decode_pub(vectors["enc_public_key"]),
        from_handle=vectors["handle"],
        to_handle="#4S11EZW09MD",
        seq=2,
        plaintext=body,
        ephemeral_private=eph,
        nonce=nonce,
    )
    opened = open_message_body(
        enc_private,
        from_handle=vectors["handle"],
        to_handle="#4S11EZW09MD",
        seq=2,
        nonce=sealed["nonce"],
        eph_public_key=sealed["eph_public_key"],
        ciphertext=sealed["ciphertext"],
    )
    assert opened == body
    shared = eph.exchange(X25519PublicKey.from_public_bytes(enc_raw))
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=MSG_VERSION.encode("ascii"),
        info=message_info(vectors["handle"], "#4S11EZW09MD", 2),
    ).derive(shared)
    assert AESGCM(key).decrypt(nonce, b64url_d(sealed["ciphertext"]), None) == body

    inner = {"plaintext": {"kind": "note", "text": "cross-vector"}}
    env = seal_envelope(
        private_key=sign_private,
        box_private=enc_private,
        sender=sender,
        recipient_card=sender,
        seq=1,
        prev="0" * 64,
        purpose="msg",
        plaintext=inner,
        nonce=nonce,
        ephemeral_private=eph,
    )
    assert env["v"] == MSG_VERSION
    assert env["handle"] == "#CPV0CWYPXP4"
    assert "ciphertext" in env
    assert "ct" not in env
    assert open_envelope(enc_private, sender, env) == inner


def test_bootstrap_is_required(tmp_path: Path) -> None:
    node = Node(tmp_path / "a")
    other = Node(tmp_path / "b")
    assert node.fed.public_status()["needs_bootstrap"] is True
    node.fed.directory.remember_card(other.fed.owner.card)
    with pytest.raises(QNMRefuse) as exc:
        node.fed.send_message(admin(node), other.fed.owner.handle, SECRET, share=True)
    assert exc.value.code == "FED-BOOTSTRAP"
    assert SECRET not in tree_text(node.root / "data")
