"""Design mode, fail-closed ethics, isolation, and reserved hub mirrors."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from qnm.boot import AUTHOR, QNMRefuse
from qnm.fedmesh.access import Actor
from qnm.fedmesh.secwire import sign_statement, signing_public_b64url
from qnm.fedmesh.wire import sha256_hex
from qnm.node import Node


def admin(node: Node) -> Actor:
    return Actor("admin", node.fed.owner.handle, via="loopback")


def _clear(_payload: dict) -> dict:
    return {"verdict": "clear", "version": "test-clear-0"}


def _hate(payload: dict) -> dict:
    if b"REFUSE-HATE" in payload["body"]:
        return {"verdict": "refuse", "version": "test-hate-0"}
    return {"verdict": "clear", "version": "test-hate-0"}


def _child(payload: dict) -> dict:
    if b"REFUSE-CHILD" in payload["body"]:
        return {"verdict": "refuse", "version": "test-child-0"}
    return {"verdict": "clear", "version": "test-child-0"}


def _nudity(payload: dict) -> dict:
    if b"REFUSE-NUDITY" in payload["body"]:
        return {"verdict": "refuse", "version": "test-nudity-0"}
    return {"verdict": "clear", "version": "test-nudity-0"}


def arm_clear(node: Node) -> None:
    _clear.version = "test-clear-0"  # type: ignore[attr-defined]
    _hate.version = "test-hate-0"  # type: ignore[attr-defined]
    _child.version = "test-child-0"  # type: ignore[attr-defined]
    node.fed.ethics.runners = {"nudity": _nudity, "child-image": _child, "hate-text": _hate}


def unlock(node: Node, peer: str = "127.0.0.1") -> None:
    challenge = node.fed.design_challenge(admin(node), peer)
    statement = sign_statement(
        node.fed.owner.sign_private,
        {
            "v": "FED-MESH-1.0",
            "kind": "design-unlock",
            "author": AUTHOR,
            "handle": node.fed.owner.handle,
            "public_key": signing_public_b64url(node.fed.owner.sign_private),
            "nonce": challenge["nonce"],
        },
    )
    opened = node.fed.design_unlock(admin(node), statement["sig"], statement["public_key"], peer)
    assert opened["unlocked"] is True


def test_design_is_local_and_get_does_not_unlock(tmp_path: Path) -> None:
    node = Node(tmp_path)
    page = node.handle("GET", "/local/design")
    assert page[0] == 200
    assert page[1]["unlocked"] is False
    assert page[1]["enabled_by_get"] is False
    assert "AZ.AzielEliab.AZ" in page[1]["html"]
    assert "azgrid" not in page[1]["html"]
    node.handle("GET", "/local/fedmesh")
    assert node.fed.owner.handle not in node.fed._design_open
    assert node.fed.public_status()["ethics_models_absent"] is True
    assert node.fed.public_status()["cap7_factory_unchanged"] is True
    with pytest.raises(QNMRefuse) as remote:
        node.fed.design_challenge(admin(node), "192.0.2.8")
    assert remote.value.code == "FG-GATE-REFUSE"
    with pytest.raises(QNMRefuse) as locked:
        node.fed.design_put(
            admin(node),
            {"slot": 0, "label": "notes.aziel", "template": "note", "theme": "night"},
            "127.0.0.1",
        )
    assert locked.value.code == "FED-PASSPHRASE"
    unlock(node)
    with pytest.raises(QNMRefuse) as guest:
        node.fed.design_put(
            Actor("guest", node.fed.owner.handle, via="loopback"),
            {"slot": 0, "label": "notes.aziel", "template": "blank", "theme": "day"},
            "127.0.0.1",
        )
    assert guest.value.code == "FED-ROLE"


def test_preview_themes_and_three_slots(tmp_path: Path) -> None:
    node = Node(tmp_path)
    unlock(node)
    for theme, needle in (("night", "#000000"), ("day", "#ffffff"), ("aziel", "#4b0082")):
        node.fed.design_put(
            admin(node),
            {
                "slot": 0,
                "label": "notes.aziel",
                "template": "note",
                "theme": theme,
                "blocks": [
                    {"type": "text", "text": "alpha"},
                    {"type": "text", "text": "beta"},
                    {"type": "embed", "app": "receipts"},
                ],
            },
            "127.0.0.1",
        )
        preview = node.fed.design_preview(admin(node), 0, "127.0.0.1")
        assert needle in preview["html"]
        assert "alpha" in preview["html"]
        assert preview["published"] is False
    moved = node.fed.design_move(admin(node), {"slot": 0, "from": 0, "to": 1}, "127.0.0.1")
    assert moved["blocks"] == 3
    with pytest.raises(QNMRefuse) as reserved:
        node.fed.design_put(
            admin(node),
            {"slot": 1, "label": "AZ.AzielEliab.AZ", "template": "blank", "theme": "night"},
            "127.0.0.1",
        )
    assert reserved.value.code == "FED-SLOT"
    with pytest.raises(QNMRefuse) as fourth:
        node.fed.design_put(
            admin(node),
            {"slot": 3, "label": "extra.aziel", "template": "blank", "theme": "night"},
            "127.0.0.1",
        )
    assert fourth.value.code == "FED-SLOT"
    self_name = node.fed.owner.handle[1:] + ".aziel"
    with pytest.raises(QNMRefuse) as own:
        node.fed.design_put(
            admin(node),
            {"slot": 1, "label": self_name, "template": "blank", "theme": "day"},
            "127.0.0.1",
        )
    assert own.value.code == "FED-SLOT"


def test_publish_fails_closed_without_models(tmp_path: Path) -> None:
    node = Node(tmp_path)
    unlock(node)
    node.fed.design_put(
        admin(node),
        {"slot": 0, "label": "notes.aziel", "template": "note", "theme": "night", "blocks": [{"type": "text", "text": "hello"}]},
        "127.0.0.1",
    )
    with pytest.raises(QNMRefuse) as blocked:
        node.fed.design_publish(admin(node), 0, "127.0.0.1", override=True)
    assert blocked.value.code == "FED-ETHICS-ABSENT"
    assert node.fed.refs.tips == {}
    assert node.fed.isolated_local == {}
    assert node.fed.island is False


def test_clear_publish_signs_ref_after_ethics(tmp_path: Path) -> None:
    node = Node(tmp_path)
    arm_clear(node)
    unlock(node)
    secret = "site-copy-that-stays-out-of-the-receipt"
    node.fed.design_put(
        admin(node),
        {"slot": 0, "label": "notes.aziel", "template": "note", "theme": "aziel", "blocks": [{"type": "text", "text": secret}]},
        "127.0.0.1",
    )
    published = node.fed.design_publish(admin(node), 0, "127.0.0.1", override=True)
    assert published["published"] is True
    assert published["ref"] == "notes.aziel"
    assert node.fed.store.get(published["object"]).decode("utf-8").find(secret) >= 0
    receipts = json.dumps(node.receipts())
    assert secret not in receipts
    assert "test-hate-0" in receipts
    assert node.fed.sandbox_runs == 0
    preview = node.fed.design_preview(admin(node), 0, "127.0.0.1")
    assert "#d4af37" in preview["html"]


def test_hate_isolates_without_publishing_or_deleting_the_draft(tmp_path: Path) -> None:
    node = Node(tmp_path)
    arm_clear(node)
    unlock(node)
    node.fed.put_object(admin(node), b"local-bytes-remain")
    node.fed.design_put(
        admin(node),
        {
            "slot": 0,
            "label": "notes.aziel",
            "template": "note",
            "theme": "night",
            "blocks": [{"type": "text", "text": "REFUSE-HATE"}],
        },
        "127.0.0.1",
    )
    with pytest.raises(QNMRefuse) as refused:
        node.fed.design_publish(admin(node), 0, "127.0.0.1", override=True)
    assert refused.value.code == "FED-ETHICS"
    assert node.fed.refs.tips == {}
    assert node.fed.island is True
    assert node.fed.isolated_local[node.fed.owner.handle]["content_stored"] is False
    assert node.fed.isolated_local[node.fed.owner.handle]["chainlock"] is False
    blob = json.dumps(node.receipts()) + (tmp_path / "data" / "fedmesh" / "local-statements.jsonl").read_text(encoding="utf-8")
    assert "REFUSE-HATE" not in blob
    draft = next((tmp_path / "data" / "fedmesh" / "design").rglob("*.json")).read_text(encoding="utf-8")
    assert "REFUSE-HATE" in draft
    assert node.fed.put_object(admin(node), b"still-local")
    with pytest.raises(QNMRefuse) as leave:
        node.fed.leave_island()
    assert leave.value.code == "FED-ISOLATED"
    appeal = node.fed.appeal(admin(node), "127.0.0.1")
    assert appeal["lifted"] is False
    assert appeal["reports_filed"] is False
    assert appeal["recheck"]["ran"] is True
    again = Node(tmp_path)
    assert again.fed.island is True
    assert again.fed.owner.handle in again.fed.isolated_local
    with pytest.raises(QNMRefuse):
        again.fed.leave_island()


def test_child_image_is_not_kept(tmp_path: Path) -> None:
    node = Node(tmp_path)
    arm_clear(node)
    unlock(node)
    raw = b"REFUSE-CHILD-image-bytes"
    with pytest.raises(QNMRefuse) as refused:
        node.fed.design_put(
            admin(node),
            {
                "slot": 0,
                "label": "photos.aziel",
                "template": "blank",
                "theme": "night",
                "blocks": [{"type": "image", "image_b64": base64.b64encode(raw).decode("ascii"), "alt": "x"}],
            },
            "127.0.0.1",
        )
    assert refused.value.code == "FED-ETHICS"
    assert list(node.fed.airlock.root.glob("*")) == []
    tree = ""
    for path in (tmp_path / "data").rglob("*"):
        if path.is_file():
            tree += path.read_bytes().decode("utf-8", "replace")
    assert raw.decode("ascii") not in tree
    assert node.fed.isolated_local[node.fed.owner.handle]["reason"] == "CHILD"
    appeal = node.fed.appeal(admin(node), "127.0.0.1")
    assert appeal["recheck"]["reason"] == "hash-only"
    assert appeal["lifted"] is False


def test_relay_honors_a_signed_isolation_record(tmp_path: Path) -> None:
    home = Node(tmp_path / "home")
    arm_clear(home)
    unlock(home)
    home.fed.design_put(
        admin(home),
        {"slot": 0, "label": "notes.aziel", "template": "note", "theme": "night", "blocks": [{"type": "text", "text": "REFUSE-HATE"}]},
        "127.0.0.1",
    )
    with pytest.raises(QNMRefuse):
        home.fed.design_publish(admin(home), 0, "127.0.0.1", override=True)
    statement = None
    for line in (tmp_path / "home" / "data" / "fedmesh" / "local-statements.jsonl").read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if row.get("kind") == "isolation":
            statement = row
    assert statement is not None
    assert statement["reason"] == "HATE"
    assert statement["check"] == "hate-text"
    assert statement["model"] == "test-hate-0"
    assert "content_stored" not in statement
    assert "author" not in statement
    assert home.fed.isolated_local[home.fed.owner.handle]["content_stored"] is False
    assert home.fed.isolated_local[home.fed.owner.handle]["chainlock"] is False
    other = Node(tmp_path / "other")
    kept = other.fed.put_object(admin(other), b"other-node-bytes")
    other.fed.relay_on = True
    code, accepted = other.handle(
        "POST",
        "/v1/mesh/relay/isolation",
        json.dumps(statement).encode("utf-8"),
    )
    assert code == 200
    assert accepted["network_wide"] is False
    assert accepted["chainlock_upstream"] is False
    with pytest.raises(QNMRefuse) as blocked:
        other.fed.http_relay(
            "POST",
            "/v1/fedmesh/send",
            "",
            json.dumps({"from": home.fed.owner.handle, "v": "x"}).encode("utf-8"),
        )
    assert blocked.value.code == "FED-ISOLATED"
    assert other.fed.store.get(kept) == b"other-node-bytes"
    assert other.fed.island is False


def test_reserved_mirror_restore_checks_the_hash(tmp_path: Path) -> None:
    node = Node(tmp_path)
    body = b"hub-mirror-index"
    digest = sha256_hex(body)
    statement = sign_statement(
        node.fed.owner.sign_private,
        {
            "v": "FED-MESH-1.0",
            "kind": "mirror-restore",
            "author": AUTHOR,
            "handle": node.fed.owner.handle,
            "public_key": signing_public_b64url(node.fed.owner.sign_private),
            "slot": "ae",
            "index": "index.html",
            "files": [{"name": "index.html", "sha256": digest}],
            "seq": 1,
            "prev": "0" * 64,
        },
    )
    restored = node.fed.mirrors.restore(statement, {"index.html": body})
    assert restored["origin_restored"] is False
    assert restored["served_locally"] is True
    assert node.fed.mirrors.serve("ae")["text"] == "hub-mirror-index"
    bad = dict(statement)
    with pytest.raises(QNMRefuse) as mismatch:
        node.fed.mirrors.restore(bad, {"index.html": b"not-the-signed-bytes"})
    assert mismatch.value.code == "FG-GATE-REFUSE"
    assert node.fed.mirrors.serve("ae")["text"] == "hub-mirror-index"
    (tmp_path / "data" / "fedmesh" / "mirrors" / "ae" / "index.html").write_bytes(b"tampered")
    with pytest.raises(QNMRefuse) as served:
        node.fed.mirrors.serve("ae")
    assert served.value.code == "FG-GATE-REFUSE"
    other = Node(tmp_path / "other")
    foreign = sign_statement(
        other.fed.owner.sign_private,
        {
            "v": "FED-MESH-1.0",
            "kind": "mirror-restore",
            "author": AUTHOR,
            "handle": other.fed.owner.handle,
            "public_key": signing_public_b64url(other.fed.owner.sign_private),
            "slot": "ae",
            "index": "index.html",
            "files": [{"name": "index.html", "sha256": digest}],
            "seq": 2,
            "prev": restored["hash"],
        },
    )
    with pytest.raises(QNMRefuse) as wrong_key:
        node.fed.mirrors.restore(foreign, {"index.html": body})
    assert wrong_key.value.code == "FED-WRONG-KEY"


def test_isolation_is_posted_before_island_drops_relays(tmp_path: Path) -> None:
    home = Node(tmp_path / "home")
    relay = Node(tmp_path / "relay")
    arm_clear(home)
    unlock(home)
    relay.fed.relay_on = True
    seen: list[tuple[str, str, list[str]]] = []

    def transport(method: str, url: str, payload: dict) -> dict:
        seen.append((method, url, list(home.fed.relay_urls)))
        path = url.split("http://relay", 1)[1]
        return relay.fed.http_relay(method, path, "", json.dumps(payload).encode("utf-8"))

    home.fed.transport = transport
    home.fed.set_relays(["http://relay"])
    home.fed.design_put(
        admin(home),
        {"slot": 0, "label": "notes.aziel", "template": "note", "theme": "night", "blocks": [{"type": "text", "text": "REFUSE-HATE"}]},
        "127.0.0.1",
    )
    with pytest.raises(QNMRefuse) as refused:
        home.fed.design_publish(admin(home), 0, "127.0.0.1", override=True)
    assert refused.value.code == "FED-ETHICS"
    assert seen == [("POST", "http://relay/v1/mesh/relay/isolation", ["http://relay"])]
    assert home.fed.relay_urls == []
    assert home.fed.island is True
    assert home.fed.owner.handle in relay.fed.isolated_seen
    kinds = [row["kind"] for row in home.receipts()]
    assert kinds.index("fedmesh_isolation") < kinds.index("fedmesh_island")
    anchored = next(row for row in home.receipts() if row["kind"] == "fedmesh_isolation")
    assert anchored["identity_anchor"]["handle"] == home.fed.owner.handle
    assert anchored["identity_anchor"]["receipt_hash"] == anchored["receipt_hash"]
    assert home.fed.public_status()["chainlock_upstream"] is False
    assert relay.fed.public_status()["chainlock_upstream"] is False
    code, health = relay.handle("GET", "/v1/mesh/relay")
    assert code == 200
    assert health["enabled_by_get"] is False
    assert relay.fed.relay_on is True
    code, mesh = home.handle("GET", "/v1/mesh")
    assert code == 403
    assert mesh["code"] == "QNM-MESH-NEVER-ENABLES"
