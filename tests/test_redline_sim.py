"""REDLINE-1.0 attack simulations — every attempt REFUSES.

CI without hardware must pass the ABSENT / refuse paths.
architecture_score vs fielded_score stay honest (never fielded 100).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from qnm.archive import ChainArchive
from qnm.boot import QNMRefuse, sha256_hex
from qnm.fold import FOLDLOCK_DIGEST, fold_sensitive, foldlock_cite
from qnm.node import Node, serve
from qnm.shelf import encrypt_pack, export_tip, load_operator_key, restore_signed
from qnm.surface import (
    attack_surface_map,
    redline_checklist,
    refuse_wan_bind,
)
from qnm.unkillability import FIELDED_BAND
from qnsd.api import main as qnsd_main
from qnsd.api import serve as qnsd_serve
from qnsd.boot import QNSRefuse
from qnsd.node import Node as QnsdNode
from qnsd.phy import claim_live, refuse_fake_live


def _boot(root: Path) -> Node:
    node = Node(root)
    node.boot(entropy=b"e", nonce=b"n")
    return node


def test_mesh_enable_via_get_refuses(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    before = dict(node.bearers.snapshot())
    for path in (
        "/v1/mesh",
        "/mesh",
        "/v1/mesh/enable",
        "/v1/mesh/radios",
        "/v1/mesh?enable=1",
    ):
        code, payload = node.handle("GET", path, b"")
        assert code == 403
        assert payload["code"] == "QNM-MESH-NEVER-ENABLES"
        assert node.snapshot()["mesh_enable"] is False
        assert node.bearers.snapshot() == before
    code, post = node.handle("POST", "/v1/mesh", b'{"enable":true}')
    assert code == 403
    assert post["code"] == "QNM-MESH-NEVER-ENABLES"
    qnsd = QnsdNode(tmp_path / "q")
    qnsd.boot(entropy=b"q", nonce=b"n")
    code, payload = qnsd.handle("GET", "/v1/mesh", b"")
    assert code == 403
    assert payload["code"] == "QNM-MESH-NEVER-ENABLES"


def test_fake_live_radio_without_adapter_refuses(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    with pytest.raises(QNMRefuse) as fake:
        refuse_fake_live("rf", claimed_live=True, adapter_present=False)
    assert fake.value.code == "QNS-RADIO-NOT-LIVE"
    with pytest.raises(QNMRefuse) as live:
        claim_live("cellular")
    assert live.value.code in {"RADIO-NO-MODEM", "QNS-RADIO-NOT-LIVE"}
    with pytest.raises(QNMRefuse) as claimed:
        node.claim_live_radio("wifi")
    assert claimed.value.code in {"RADIO-NO-WIFI", "QNS-RADIO-NOT-LIVE"}
    snap = node.snapshot()
    assert snap["fabric"]["live_rf_mesh"] is False
    assert snap.get("radios_fielded") is False or snap["fabric"]["radios_fielded"] is False


def test_invented_plane_b_doi_and_url_refuse(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    with pytest.raises(QNMRefuse) as doi:
        node.planes_act({"op": "invent_doi"})
    assert doi.value.code == "QNM-NO-FAN-DOI"
    with pytest.raises(QNMRefuse) as fake_doi:
        node.planes_act({"op": "doi", "doi": "10.5281/zenodo.0"})
    assert fake_doi.value.code == "QNM-NO-FAN-DOI"
    with pytest.raises(QNMRefuse) as url:
        node.planes_act(
            {
                "op": "shelf",
                "url": "https://example.com/invented-pack",
                "digest": "a" * 64,
                "body": "nope",
            }
        )
    assert url.value.code == "QNM-NO-FAN-SHELF"
    with pytest.raises(QNMRefuse) as zenodo:
        node.planes_act(
            {
                "op": "shelf",
                "url": "https://zenodo.org/records/1",
                "digest": "b" * 64,
                "body": "nope",
            }
        )
    assert zenodo.value.code == "QNM-NO-FAN-SHELF"
    with pytest.raises(QNMRefuse) as invent:
        node.planes_act({"op": "invent_shelf"})
    assert invent.value.code == "QNM-NO-FAN-SHELF"
    assert node.unkillability()["planes"]["plane_b"]["doi"] is None


def test_unsigned_tip_restore_refuses(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    packed = node.pack_archive()
    with pytest.raises(QNMRefuse) as unsigned:
        node.archive.restore(Path(packed["path"]))
    assert unsigned.value.code == "QNM-TIP-UNSIGNED"
    with pytest.raises(QNMRefuse) as api:
        node.archive_act({"op": "restore", "path": packed["path"]})
    assert api.value.code == "QNM-TIP-UNSIGNED"
    with pytest.raises(QNMRefuse) as shelf:
        restore_signed(b"tip-bytes", digest=None)
    assert shelf.value.code == "QNM-TIP-UNSIGNED"
    with pytest.raises(QNMRefuse) as mismatch:
        ChainArchive(tmp_path).restore(Path(packed["path"]), digest="0" * 64)
    assert mismatch.value.code == "QNM-TIP-UNSIGNED"
    ok = node.archive.restore(Path(packed["path"]), digest=packed["digest"])
    assert ok["signed"] is True
    assert ok["digest"] == packed["digest"]


def test_neighbor_vote_to_fix_refuses(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    with pytest.raises(QNMRefuse) as vote:
        node.reheal({"vote": 3, "majority": True, "vote_to_fix": True})
    assert vote.value.code == "QNM-REHEAL-NO-MAJORITY"
    with pytest.raises(QNMRefuse) as neighbor:
        node.reheal({"neighbor": "peer", "listen": True})
    assert neighbor.value.code == "QNM-REHEAL-NO-NEIGHBOR"
    with pytest.raises(QNMRefuse) as phoenix:
        node.phoenix.vote_to_fix()
    assert phoenix.value.code == "QNM-REHEAL-NO-MAJORITY"


def test_wan_bind_and_second_door_refuse(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    with pytest.raises(QNMRefuse) as wan:
        serve(node, host="0.0.0.0", port=0)
    assert wan.value.code == "QNM-LOOPBACK-ONLY"
    with pytest.raises((QNSRefuse, QNMRefuse)) as qwan:
        qnsd_serve(QnsdNode(tmp_path / "q"), host="0.0.0.0", port=0)
    assert qwan.value.code == "QNM-LOOPBACK-ONLY"
    with pytest.raises(QNMRefuse) as tls:
        refuse_wan_bind("0.0.0.0", tls=False, operator_wan=True)
    assert tls.value.code == "QNM-NO-PLAINTEXT-REMOTE"
    assert refuse_wan_bind("localhost") == "127.0.0.1"
    rc = qnsd_main(["serve", "--root", str(tmp_path / "extra")])
    assert rc == 2


def test_plaintext_remote_export_and_shelf_key(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    pack = b"cold-shelf-tip-pack"
    with pytest.raises(QNMRefuse) as no_key:
        load_operator_key()
    assert no_key.value.code == "QNM-SHELF-NO-KEY"
    with pytest.raises(QNMRefuse) as placeholder:
        load_operator_key("changeme")
    assert placeholder.value.code == "QNM-SHELF-NO-KEY"
    with pytest.raises(QNMRefuse) as remote:
        export_tip(pack, dest="https://example.com/tip", encrypt=False)
    assert remote.value.code == "QNM-NO-PLAINTEXT-REMOTE"
    with pytest.raises(QNMRefuse) as http:
        export_tip(pack, dest="http://127.0.0.1/tip", encrypt=False, operator_plaintext_export=True)
    assert http.value.code == "QNM-NO-PLAINTEXT-REMOTE"
    key = "operator-shelf-key-32bytes-long!!"
    envelope = encrypt_pack(pack, key=key)
    assert envelope["magic"] == "QNMS1"
    assert envelope["alg"] in {"hmac-sha256-ctr", "aes-256-gcm"}
    assert "changeme" not in str(envelope)
    opened = restore_signed(b"", digest=sha256_hex(pack), envelope=envelope, key=key)
    assert opened["restored"] is True
    folded = fold_sensitive({"password": "no", "op": "export", "text": "https://evil.example/x"})
    assert folded["inner"]["password"] == "[FLD3:block]"
    assert "[FLD3:url]" in folded["inner"]["text"]
    cite = foldlock_cite()
    assert cite["digest"] == FOLDLOCK_DIGEST
    assert cite["invented"] is False
    assert cite["status"] in {"SLOT", "foldlock.py"}
    code, surface = node.handle("GET", "/local/surface", b"")
    assert code == 200
    assert surface["decision"] == "monolith-local-control-plane"
    assert surface["public_api"] == []
    assert surface["wan_default"] is False
    assert surface["token_in_git"] is False
    code, redline = node.handle("GET", "/local/redline", b"")
    assert code == 200
    ids = {row["id"] for row in redline["items"]}
    assert {
        "auth",
        "token_never_in_git",
        "mesh_get_never_enables",
        "az_generator_not_callable",
        "radio_live_only_on_presence",
        "poison_refuse",
        "no_rewrite",
    } <= ids
    assert all(row["pass"] is True for row in redline["items"])


def test_scores_stay_honest_never_fielded_100(tmp_path: Path) -> None:
    node = _boot(tmp_path)
    node.enable_fabric()
    kill = node.unkillability()
    assert kill["score"] == kill["fielded_score"]
    assert kill["fielded_score"] == 70
    assert kill["fielded_band"] == list(FIELDED_BAND)
    assert kill["architecture_score"] >= 80
    assert kill["architecture_score"] <= 100
    assert kill["fielded_score"] != 100
    assert kill["publish_to_hubs"] is False
    assert kill["hubs_must_not_publish_100"] is True
    assert kill["meets_target"] is False
    mapped = attack_surface_map()
    assert mapped["publish_fielded_100"] is False
    assert mapped["architecture_score_published"] is False
    assert redline_checklist()["items"][-1]["id"] == "fielded_not_100"


def test_source_has_no_invented_key_or_foldlock_engine() -> None:
    root = Path(__file__).resolve().parents[1]
    banned = (
        "QNM_LOCAL_TOKEN=",
        "QNM_SHELF_KEY=",
        "rewrite_key = True",
        "DEFAULT_SHELF_KEY",
        "invented_foldlock",
    )
    files = (
        list((root / "qnm").rglob("*.py"))
        + list((root / "qnsd").rglob("*.py"))
        + list((root / "cfg").glob("*"))
    )
    for path in files:
        text = path.read_text(encoding="utf-8")
        for token in banned:
            assert token not in text, f"{path} contains {token}"
    assert not (root / "qnsd" / "foldlock.py").is_file()
    assert not (root / "qnm" / "foldlock.py").is_file()
    assert foldlock_cite()["engine_in_repo"] is False
