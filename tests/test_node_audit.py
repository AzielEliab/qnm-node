"""2026-11-13 node audit: envelope v2, peer pins, photon frame, LAN path."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from qnm.boot import QNMRefuse
from qnm.chain import GENESIS_PREV
from qnm.fedmesh.discover import Directory
from qnm.fedmesh.identity import _identity_from_seeds
from qnm.fedmesh.wire import (
    ENVELOPE_V1,
    ENVELOPE_V2,
    MSG_VERSION,
    b64url,
    canonical,
    frame_header_aad,
    open_envelope,
    open_message_body,
    seal_envelope,
    sign_card_rotation,
)
from qnsd.boot import QNSRefuse
from qnsd.lan.node import LanNode, host_facts
from qnsd.light.carrier import SimulatedHardware, open_frame, seal_frame
from qnsd.photon import dumps, loads, make_photon

ROOT = Path(__file__).resolve().parents[1]
V1_ENVELOPE = {
    "v": "FED-MESH-1.0",
    "kind": "msg",
    "handle": "#CPV0CWYPXP4",
    "public_key": "ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ",
    "to": "#936AJZW9JFZ",
    "seq": 1,
    "prev": "0" * 64,
    "nonce": "gYGBgYGBgYGBgYGB",
    "eph_public_key": "q08ZeZj8xWzG7WjB2TGvm7Ui7AB0PhgfczCRXfSqMXY",
    "ciphertext": "oKX8t_YeJATC55lVAziGbh02J8-Rb_GsVLAOafoo-dw772se97pUXKovZC5EQSU",
    "sig": "f7YLOvTM9NxBcorhGnwQIXiDocHdTUCJBaWe_qgttQYRvbtGyJryJWh-SHTMUnCwWhvxdwsvJOnPytqxGGvWCw",
}
SIGN_SEED = bytes.fromhex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
BOX_SEED = bytes.fromhex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")


def _pair():
    sender = _identity_from_seeds(SIGN_SEED, BOX_SEED, seal_kind="audit")
    recip = _identity_from_seeds(bytes.fromhex("21" * 32), bytes.fromhex("61" * 32), seal_kind="audit")
    return sender, recip


def _seal(sender, recip, text="freeze"):
    return seal_envelope(
        private_key=sender.sign_private,
        box_private=sender.box_private,
        sender=sender.card,
        recipient_card=recip.card,
        seq=1,
        prev=GENESIS_PREV,
        purpose="msg",
        plaintext={"kind": "note", "text": text},
        nonce=bytes.fromhex("81" * 12),
        ephemeral_private=X25519PrivateKey.from_private_bytes(bytes.fromhex("71" * 32)),
    )


def _resign(sender, envelope: dict) -> dict:
    body = {key: value for key, value in envelope.items() if key != "sig"}
    signed = dict(body)
    signed["sig"] = b64url(sender.sign_private.sign(canonical(body)))
    return signed


def test_v1_envelope_opens_only_with_explicit_opt_in() -> None:
    sender, recip = _pair()
    with pytest.raises(QNMRefuse) as refused:
        open_envelope(recip.box_private, recip.card, V1_ENVELOPE)
    assert refused.value.code == "FED-DOWNGRADE"
    with pytest.raises(QNMRefuse) as explicit:
        open_envelope(recip.box_private, recip.card, V1_ENVELOPE, allow_v1=False)
    assert explicit.value.code == "FED-DOWNGRADE"
    opened = open_envelope(recip.box_private, recip.card, V1_ENVELOPE, allow_v1=True)
    assert opened["text"] == "freeze"
    assert V1_ENVELOPE["v"] == MSG_VERSION
    assert sender.handle == V1_ENVELOPE["handle"]


def test_envelope_v1_frame_is_refused_by_default() -> None:
    """FED-MESH-ENVELOPE-1 must not decrypt unless allow_v1=True."""
    sender, recip = _pair()
    legacy = _resign(sender, {**V1_ENVELOPE, "v": ENVELOPE_V1})
    assert legacy["v"] == "FED-MESH-ENVELOPE-1"
    with pytest.raises(QNMRefuse) as refused:
        open_envelope(recip.box_private, recip.card, legacy)
    assert refused.value.code == "FED-DOWNGRADE"
    assert "allow_v1=True" in refused.value.detail
    assert ENVELOPE_V2 in refused.value.detail
    with pytest.raises(QNMRefuse) as body:
        open_message_body(
            recip.box_private,
            from_handle=legacy["handle"],
            to_handle=legacy["to"],
            seq=int(legacy["seq"]),
            nonce=legacy["nonce"],
            eph_public_key=legacy["eph_public_key"],
            ciphertext=legacy["ciphertext"],
            version=ENVELOPE_V1,
            msg_type="msg",
        )
    assert body.value.code == "FED-DOWNGRADE"
    opened = open_envelope(recip.box_private, recip.card, legacy, allow_v1=True)
    assert opened["text"] == "freeze"
    plain = open_message_body(
        recip.box_private,
        from_handle=legacy["handle"],
        to_handle=legacy["to"],
        seq=int(legacy["seq"]),
        nonce=legacy["nonce"],
        eph_public_key=legacy["eph_public_key"],
        ciphertext=legacy["ciphertext"],
        version=ENVELOPE_V1,
        msg_type="msg",
        allow_v1=True,
    )
    assert b"freeze" in plain
    session = (ROOT / "qnsd" / "lan" / "session.py").read_text(encoding="utf-8")
    assert "allow_v1=False" in session
    assert "allow_v1=True" not in session


def test_third_node_cannot_open_a_to_b_frame() -> None:
    sender, recip = _pair()
    other = _identity_from_seeds(bytes.fromhex("31" * 32), bytes.fromhex("81" * 32), seal_kind="audit")
    env = _seal(sender, recip)
    assert env["v"] == ENVELOPE_V2
    assert open_envelope(recip.box_private, recip.card, env)["text"] == "freeze"
    with pytest.raises(QNMRefuse) as wrong:
        open_envelope(other.box_private, other.card, env)
    assert wrong.value.code in {"FED-TAMPER", "FED-E2E", "FED-WRONG-KEY"}
    with pytest.raises(QNMRefuse):
        open_message_body(
            other.box_private,
            from_handle=str(env["handle"]),
            to_handle=str(env["to"]),
            seq=int(env["seq"]),
            nonce=str(env["nonce"]),
            eph_public_key=str(env["eph_public_key"]),
            ciphertext=str(env["ciphertext"]),
            version=ENVELOPE_V2,
            msg_type="msg",
        )
    with pytest.raises(QNMRefuse):
        open_message_body(
            recip.box_private,
            from_handle=str(env["handle"]),
            to_handle=other.handle,
            seq=int(env["seq"]),
            nonce=str(env["nonce"]),
            eph_public_key=str(env["eph_public_key"]),
            ciphertext=str(env["ciphertext"]),
            version=ENVELOPE_V2,
            msg_type="msg",
        )


def test_header_is_bound_as_associated_data() -> None:
    sender, recip = _pair()
    aad = frame_header_aad(
        sender=sender.handle,
        recipient=recip.handle,
        seq=1,
        header_type="msg",
        version=ENVELOPE_V2,
    )
    assert b'"type":"msg"' in aad
    assert b'"version":"FED-MESH-ENVELOPE-2"' in aad
    env = _seal(sender, recip)
    swapped = dict(env)
    swapped["seq"] = 2
    with pytest.raises(QNMRefuse):
        open_envelope(recip.box_private, recip.card, swapped)


def test_python_js_envelope_vectors() -> None:
    fixture_path = ROOT / "tests" / "fixtures" / "envelope-v2-vectors.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    _sender, recip = _pair()
    section = fixture["python"]
    opened = open_message_body(
        recip.box_private,
        from_handle=section["sender"],
        to_handle=section["recipient"],
        seq=int(section["seq"]),
        nonce=b64url(bytes.fromhex(section["nonce_hex"])),
        eph_public_key=section["eph_public_key"],
        ciphertext=section["ciphertext"],
        version=section["version"],
        msg_type=section["type"],
    )
    assert opened.decode("utf-8") == section["plaintext"]
    js = fixture["js"]
    js_plain = open_message_body(
        recip.box_private,
        from_handle=js["sender"],
        to_handle=js["recipient"],
        seq=int(js["seq"]),
        nonce=b64url(bytes.fromhex(js["nonce_hex"])),
        eph_public_key=js["eph_public_key"],
        ciphertext=js["ciphertext"],
        version=js["version"],
        msg_type=js["type"],
    )
    assert js_plain == b"from-js"
    proc = subprocess.run(
        ["node", str(ROOT / "tests" / "js" / "envelope_v2_interop.mjs"), str(fixture_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    assert report["python_ok"] is True
    assert report["python_plaintext"] == section["plaintext"]
    assert report["js_matches_fixture"] is True


def test_peer_pin_is_full_key_and_rotation_is_signed(tmp_path: Path) -> None:
    current = _identity_from_seeds(bytes.fromhex("11" * 32), bytes.fromhex("22" * 32), seal_kind="audit")
    nxt = _identity_from_seeds(bytes.fromhex("33" * 32), bytes.fromhex("44" * 32), seal_kind="audit")
    stranger = _identity_from_seeds(bytes.fromhex("55" * 32), bytes.fromhex("66" * 32), seal_kind="audit")
    assert len(current.key_id) == 64
    assert current.handle != current.key_id
    directory = Directory()
    directory.remember_card(current.card)
    assert directory.key_active(current.key_id) is True
    planted_id = "ab" * 32
    directory.cards[nxt.handle] = {
        "handle": nxt.handle,
        "key_id": planted_id,
        "sign_pub": current.card["sign_pub"],
        "key_status": "active",
    }
    directory.allow[planted_id] = directory.cards[nxt.handle]
    with pytest.raises(QNMRefuse) as collided:
        directory.remember_card(nxt.card)
    assert collided.value.code == "FED-WRONG-KEY"
    directory.cards.pop(nxt.handle)
    directory.allow.pop(planted_id)
    forged = sign_card_rotation(stranger.sign_private, current.key_id, nxt.card)
    with pytest.raises(QNMRefuse):
        directory.rotate_card(nxt.card, forged)
    rotation = sign_card_rotation(current.sign_private, current.key_id, nxt.card)
    moved = directory.rotate_card(nxt.card, rotation)
    assert moved["key_id"] == nxt.key_id
    assert directory.key_active(current.key_id) is False
    assert directory.key_active(nxt.key_id) is True
    assert current.handle not in directory.cards
    assert directory.cards[nxt.handle]["key_id"] == nxt.key_id

    node = LanNode(tmp_path / "lan", enabled=False)
    material = node.public_material()
    other = LanNode(tmp_path / "peer", enabled=False)
    added = node.add_peer(other.public_material(), "10.1.0.20:8894")
    assert added["key_id"] == other.card["key_id"]
    assert len(added["key_id"]) == 64
    pinned = node.peers.get(other.handle)
    assert pinned["card"]["key_id"] == other.card["key_id"]
    raw = json.loads((node.root / "data" / "lan" / "peers.json").read_text(encoding="utf-8"))
    assert other.handle not in raw
    assert other.card["key_id"] in raw
    third = LanNode(tmp_path / "third", enabled=False)
    stolen = third.public_material()
    stolen["card"] = dict(stolen["card"])
    stolen["card"]["handle"] = other.handle
    with pytest.raises(QNMRefuse):
        node.add_peer(stolen, "10.1.0.21:8894")
    rotated_node = LanNode(tmp_path / "rotated", enabled=False)
    fresh = LanNode(tmp_path / "fresh", enabled=False)
    fresh.add_peer(material, "10.1.0.10:9")
    good = sign_card_rotation(node.sign_private, node.card["key_id"], rotated_node.card)
    turned = fresh.rotate_peer(rotated_node.public_material(), "10.1.0.30:8894", good)
    assert turned["key_id"] == rotated_node.card["key_id"]
    assert fresh.peers.get_key(rotated_node.card["key_id"])["key_status"] == "active"
    retired = fresh.peers.get(node.handle)
    assert retired["key_status"] == "rotated"
    with pytest.raises(Exception):
        fresh.peers.get_key(node.card["key_id"])
    bad = sign_card_rotation(other.sign_private, node.card["key_id"], stranger.card)
    again = LanNode(tmp_path / "again", enabled=False)
    again.add_peer(material, "10.1.0.10:9")
    with pytest.raises(Exception):
        again.rotate_peer(stranger.public_material(), "10.1.0.40:8894", bad)


def test_simulated_photon_frame_is_not_hardware() -> None:
    photon = make_photon(src="node-a", dst="node-b", payload={"text": "sim"})
    link = SimulatedHardware()
    sent = link.transmit(dumps(photon))
    assert sent["live"] is False
    assert sent["real_hardware"] is False
    assert sent["hardware"] == "simulated"
    assert sent["mock"] is False
    got = link.receive()
    assert got["ok"] is True
    assert got["live"] is False
    assert got["real_hardware"] is False
    assert loads(got["payload"]).photon_id == photon.photon_id
    frame = seal_frame(dumps(photon))
    assert frame.startswith(b"\xaa\xaa\xaa\xaa\x7e")
    assert open_frame(frame) == dumps(photon)
    import zlib

    assert zlib.crc32(b"123456789") & 0xFFFFFFFF == 0xCBF43926
    with pytest.raises(QNSRefuse):
        open_frame(frame[:-1] + bytes([frame[-1] ^ 0x01]))


def test_lan_script_inserts_repo_root_for_a_fresh_clone() -> None:
    script = ROOT / "scripts" / "qns_lan.py"
    source = script.read_text(encoding="utf-8")
    preamble = source.split("import qnm", 1)[0]
    saved = list(sys.path)
    try:
        sys.path = [entry for entry in sys.path if Path(entry or ".").resolve() != ROOT]
        assert str(ROOT) not in sys.path
        namespace = {"__file__": str(script)}
        exec(preamble, namespace)  # noqa: S102 — the script preamble is the path fix under test
        assert str(ROOT) in sys.path
        assert namespace["_REPO_ROOT"] == ROOT
    finally:
        sys.path = saved
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        check=False,
        capture_output=True,
        text=True,
        cwd=ROOT / "scripts",
        env={"PYTHONPATH": "", "PATH": "/usr/bin:/bin", "HOME": "/tmp"},
    )
    assert proc.returncode == 0, proc.stderr
    assert "peer-rotate" in proc.stdout


def test_host_facts_do_not_invent_a_second_device() -> None:
    same = host_facts("127.0.0.1:8894", local_id="abc", peer_id="def", stored=True)
    assert same["same_machine"] is True
    assert same["second_device"] is False
    assert same["live"] is False
    matched = host_facts("192.0.2.10:8894", local_id="abc", peer_id="abc", stored=True)
    assert matched["same_machine"] is True
    assert matched["second_device"] is False
    other = host_facts("192.0.2.20:8894", local_id="abc", peer_id="def", stored=True)
    assert other["same_machine"] is False
    assert other["second_device"] is True
    assert other["live"] is False
    unknown = host_facts("192.0.2.20:8894", local_id="abc", peer_id="", stored=True)
    assert unknown["second_device"] is False
    assert unknown["host_proven"] is False
    assert unknown["live"] is False
    unstored = host_facts("192.0.2.20:8894", local_id="abc", peer_id="def", stored=False)
    assert unstored["second_device"] is False
