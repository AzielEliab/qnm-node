"""Freeze packet identity, VIA_ORDER, sequence, receipt hashes, identity.

Phase 0. These tests call the code that already ships. They do not open
a socket and they do not change formulas. Goldens are the contract.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from qnm.boot import AUTHOR, QNMRefuse, SPEC, compute_install_root, sha256_hex
from qnm.chain import GENESIS_PREV, Chain
from qnm.fedmesh.chain import classify_link
from qnm.fedmesh.identity import _identity_from_seeds
from qnm.fedmesh.secwire import verify_identity_anchor
from qnm.fedmesh.wire import (
    MSG_VERSION,
    envelope_id,
    message_info,
    open_envelope,
    seal_envelope,
    verify_envelope,
)
from qnm.nolie import receipt_digest
from qnm.pairs import compute_pair_id
from qnsd.node import DEFAULT_BIND
from qnsd.outbox import Outbox
from qnsd.photon import (
    MAGIC,
    PHOTON_FIELDS,
    PHOTON_ID_FIELDS,
    VER,
    canonical_bytes,
    loads,
    make_photon,
    photon_id,
    photon_id_hash,
)
from qnsd.policy import Policy
from qnsd.vias.base import VIA_ORDER
from qnsd.walker import ViaStack
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

PHOTON_GOLDEN = "5e3369621394ca3b7c64f3f4034f9d53841a32aee6e99e18836e88b34838ca5e"
PAIR_GOLDEN = "fd922705c1b4dd3b3fd8bb0f900b1309ec87308a726cb5bb328525dc4a387341"
INSTALL_GOLDEN = "6bb1c527448d72ce2eeb1b3e220fcb1c0fedd1c6d77288dac3eac7f0c8d7ffcd"
INSTALL_EMPTY_GENESIS = "6c9587e3281d323ce0deadabb0b83e0134c21905f1e8f789da2fc63e857a08dc"
RECEIPT_GOLDEN = "773b07502d132fd595e1150fe29e31d6dd1b988a0e09dadc90afb2ccd08ba562"
LINK_GOLDEN = "d63e1cadeff11c7cae823dd5f9dba988b99b3674d8ead7bf6b862f60ddf1cc72"
HANDLE_GOLDEN = "#CPV0CWYPXP4"
KEY_ID_GOLDEN = "65b60673d6ed884bf01c2c222d82ada0740f29ac3355d6a925c81f17f47a27b8"
VECTOR_RECEIPT = "49ef88c622177cd9662ea63d147589c9cea6c32adede83b7e7d127f853022dba"
ENVELOPE_ID_GOLDEN = "afa667dde9be1843de142f04150481065af073ccbae5d425839d81ab7297e279"
SIGN_SEED = bytes.fromhex(
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
)
BOX_SEED = bytes.fromhex(
    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
)


def test_via_order_and_walker_classes_frozen() -> None:
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
    assert ViaStack().classes("LIVE", Policy()) == VIA_ORDER
    assert ViaStack().classes("COLD", Policy()) == ("local",)
    assert DEFAULT_BIND == "127.0.0.1"


def test_photon_id_golden_ignores_hop_fields() -> None:
    assert PHOTON_ID_FIELDS == ("magic", "ver", "src", "dst", "pair_id", "payload")
    assert MAGIC == "QNS1" and VER == "1.3"
    assert PHOTON_FIELDS[0] == "magic"
    payload = {"label": "freeze", "n": 1}
    photon = make_photon(
        src="src-freeze",
        dst="dst-freeze",
        pair_id="pair-freeze",
        payload=payload,
        via="lan",
    )
    assert photon.photon_id == PHOTON_GOLDEN
    assert photon_id(photon) == PHOTON_GOLDEN
    photon.via = "bt"
    photon.hop = 7
    photon.seen = ["x"]
    photon.translate = True
    photon.utc = "1999-01-01T00:00:00Z"
    assert photon_id(photon) == PHOTON_GOLDEN
    assert photon_id_hash({"magic": MAGIC, "ver": VER, "src": "src-freeze", "dst": "dst-freeze", "pair_id": "pair-freeze", "payload": payload}) == PHOTON_GOLDEN
    wire = canonical_bytes(photon.to_dict())
    assert loads(wire).photon_id == PHOTON_GOLDEN
    with pytest.raises(Exception):
        loads(b'{"magic":"QNS1","ver":"9.9"}')


def test_pair_id_and_install_root_golden() -> None:
    left = "aa" * 32
    right = "bb" * 32
    nonce_a = "11" * 16
    nonce_b = "22" * 16
    assert compute_pair_id(left, right, nonce_a, nonce_b) == PAIR_GOLDEN
    assert compute_pair_id(right, left, nonce_b, nonce_a) == PAIR_GOLDEN
    assert compute_install_root(b"entropy-freeze", b"nonce-freeze", b"genesis-freeze") == INSTALL_GOLDEN
    assert compute_install_root(b"entropy-freeze", b"nonce-freeze", None) == INSTALL_EMPTY_GENESIS
    assert compute_install_root(b"entropy-freeze", b"nonce-freeze", b"") == INSTALL_EMPTY_GENESIS


def test_handle_and_key_id_from_vector_seed() -> None:
    ident = _identity_from_seeds(SIGN_SEED, BOX_SEED, seal_kind="freeze")
    assert ident.handle == HANDLE_GOLDEN
    assert ident.key_id == KEY_ID_GOLDEN
    assert AUTHOR == "Aziel Eliab"


def test_receipt_digest_skips_hash_and_anchor() -> None:
    receipt = {
        "author": "Aziel Eliab",
        "body": {"n": 1},
        "kind": "freeze",
        "prev": "0" * 64,
        "seq": 1,
    }
    assert receipt_digest(receipt) == RECEIPT_GOLDEN
    stamped = dict(receipt)
    stamped["receipt_hash"] = "ab" * 32
    stamped["identity_anchor"] = {"sig": "not-part-of-the-digest"}
    assert receipt_digest(stamped) == RECEIPT_GOLDEN
    moved = dict(receipt)
    moved["body"] = {"n": 2}
    assert receipt_digest(moved) != RECEIPT_GOLDEN


def test_chain_link_hash_golden(tmp_path: Path) -> None:
    core = {
        "author": AUTHOR,
        "body": {"freeze": 1},
        "kind": "freeze",
        "prev": GENESIS_PREV,
        "seq": 1,
        "spec": SPEC,
        "utc": "2026-01-01T00:00:00Z",
    }
    digest = sha256_hex(
        json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )
    assert digest == LINK_GOLDEN
    row = {
        "seq": 1,
        "kind": "freeze",
        "body": {"freeze": 1},
        "prev": GENESIS_PREV,
        "hash": digest,
        "utc": "2026-01-01T00:00:00Z",
        "spec": SPEC,
        "author": AUTHOR,
    }
    path = tmp_path / "data" / "chain"
    path.mkdir(parents=True)
    (path / "node.jsonl").write_text(
        json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    chain = Chain(tmp_path)
    assert chain.verify()["ok"] is True
    assert chain.tip == LINK_GOLDEN
    row["body"] = {"freeze": 2}
    (path / "node.jsonl").write_text(
        json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    broken = Chain(tmp_path)
    assert broken.verify()["ok"] is False


def test_sequence_rules_frozen() -> None:
    genesis = GENESIS_PREV
    first = "a" * 64
    second = "b" * 64
    classify_link(seen=None, tip_seq=None, tip_hash=None, seq=1, prev=genesis, digest=first)
    with pytest.raises(QNMRefuse) as gap:
        classify_link(seen=None, tip_seq=None, tip_hash=None, seq=0, prev=genesis, digest=first)
    assert gap.value.code == "FED-GAP"
    with pytest.raises(QNMRefuse) as missing:
        classify_link(seen=None, tip_seq=None, tip_hash=None, seq=2, prev=genesis, digest=first)
    assert missing.value.code == "FED-GAP"
    with pytest.raises(QNMRefuse) as bad_prev:
        classify_link(seen=None, tip_seq=None, tip_hash=None, seq=1, prev="1" * 64, digest=first)
    assert bad_prev.value.code == "FED-FORK"
    with pytest.raises(QNMRefuse) as replay:
        classify_link(seen=first, tip_seq=1, tip_hash=first, seq=1, prev=genesis, digest=first)
    assert replay.value.code == "FED-REPLAY"
    with pytest.raises(QNMRefuse) as fork:
        classify_link(seen=first, tip_seq=1, tip_hash=first, seq=1, prev=genesis, digest=second)
    assert fork.value.code == "FED-FORK"
    classify_link(seen=None, tip_seq=1, tip_hash=first, seq=2, prev=first, digest=second)
    with pytest.raises(QNMRefuse) as prev_fork:
        classify_link(seen=None, tip_seq=1, tip_hash=first, seq=2, prev=second, digest=second)
    assert prev_fork.value.code == "FED-FORK"
    with pytest.raises(QNMRefuse) as hole:
        classify_link(seen=None, tip_seq=1, tip_hash=first, seq=3, prev=first, digest=second)
    assert hole.value.code == "FED-GAP"
    with pytest.raises(QNMRefuse) as back:
        classify_link(seen=None, tip_seq=2, tip_hash=second, seq=2, prev=first, digest=first)
    assert back.value.code == "FED-FORK"


def test_envelope_signature_and_cipher_golden() -> None:
    sender = _identity_from_seeds(SIGN_SEED, BOX_SEED, seal_kind="freeze")
    recip = _identity_from_seeds(bytes.fromhex("21" * 32), bytes.fromhex("61" * 32), seal_kind="freeze")
    env = seal_envelope(
        private_key=sender.sign_private,
        box_private=sender.box_private,
        sender=sender.card,
        recipient_card=recip.card,
        seq=1,
        prev=GENESIS_PREV,
        purpose="msg",
        plaintext={"kind": "note", "text": "freeze"},
        nonce=bytes.fromhex("81" * 12),
        ephemeral_private=X25519PrivateKey.from_private_bytes(bytes.fromhex("71" * 32)),
    )
    assert env["v"] == MSG_VERSION == "FED-MESH-1.0"
    assert message_info(sender.handle, recip.handle, 1) == b"FED-MESH-1.0|#CPV0CWYPXP4|#936AJZW9JFZ|1"
    assert envelope_id(env) == ENVELOPE_ID_GOLDEN
    assert env["sig"] == (
        "f7YLOvTM9NxBcorhGnwQIXiDocHdTUCJBaWe_qgttQYRvbtGyJryJWh-SHTMUnCwWhvxdwsvJOnPytqxGGvWCw"
    )
    assert env["ciphertext"] == "oKX8t_YeJATC55lVAziGbh02J8-Rb_GsVLAOafoo-dw772se97pUXKovZC5EQSU"
    verify_envelope(env)
    opened = open_envelope(recip.box_private, recip.card, env)
    assert opened["text"] == "freeze"
    tampered = dict(env)
    tampered["sig"] = env["sig"][:-1] + ("A" if env["sig"][-1] != "A" else "B")
    with pytest.raises(QNMRefuse) as bad:
        verify_envelope(tampered)
    assert bad.value.code == "FED-TAMPER"


def test_identity_anchor_vector_still_verifies() -> None:
    vectors = json.loads(
        (Path(__file__).parent / "fixtures" / "fed-mesh-vectors.json").read_text(encoding="utf-8")
    )
    assert vectors["handle"] == HANDLE_GOLDEN
    assert vectors["receipt_hash"] == VECTOR_RECEIPT
    verify_identity_anchor(vectors["identity_anchor"])
    assert vectors["identity_anchor"]["receipt_hash"] == VECTOR_RECEIPT
    assert "key_id" not in vectors["identity_anchor"]


def test_outbox_keeps_photon_id_and_refuses_publish(tmp_path: Path) -> None:
    photon = make_photon(src="src-freeze", dst="dst-freeze", pair_id="pair-freeze", payload={"n": 1})
    box = Outbox(tmp_path)
    waited = box.wait_photon(photon.to_dict(), "lan", "freeze")
    assert waited["payload"]["photon_id"] == photon.photon_id
    assert waited["payload"]["photon"]["photon_id"] == photon.photon_id
    again = Outbox(tmp_path)
    assert again.waits()[0]["payload"]["photon_id"] == photon.photon_id
    with pytest.raises(Exception) as refused:
        box.queue("publish", {"publish": True})
    assert "QNM-ANON-NO-PUBLISH" in str(refused.value)
