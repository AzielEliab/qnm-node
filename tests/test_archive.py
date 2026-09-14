"""RE-EXPAND-1.0 — bytes of chain survive; verify + new local node on tip."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from qnm.archive import CHAIN_MEMBER, MANIFEST_MEMBER, ChainArchive
from qnm.boot import QNMRefuse, sha256_hex
from qnm.node import Node


def _tar(members: dict[str, bytes], dest: Path) -> Path:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, blob in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(blob)
            tar.addfile(info, io.BytesIO(blob))
    dest.write_bytes(buf.getvalue())
    return dest


def test_pack_keeps_chain_bytes_not_summary(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    raw = (tmp_path / "data" / "chain" / "node.jsonl").read_bytes()
    packed = node.pack_archive()
    assert packed["summary"] is False
    assert packed["weights"] is False
    members = ChainArchive(tmp_path).read_members(Path(packed["path"]))
    assert members[CHAIN_MEMBER] == raw
    assert b'"summary"' not in members[CHAIN_MEMBER] or b'"seq"' in members[CHAIN_MEMBER]
    verified = node.verify_archive(packed["path"])
    assert verified["ok"] is True
    assert verified["tip"] == packed["tip"]


def test_reexpand_is_new_node_on_tip_not_index(tmp_path: Path) -> None:
    src = Node(tmp_path / "src")
    src.boot(entropy=b"src-e", nonce=b"src-n")
    packed = src.pack_archive()
    tip = packed["tip"]
    archive_bytes = ChainArchive(tmp_path / "src").read_members(Path(packed["path"]))[CHAIN_MEMBER]
    dest = tmp_path / "dest"
    out = src.reexpand_from({"path": packed["path"], "dest": str(dest)})
    assert out["new_local_node"] is True
    assert out["mesh_from_index"] is False
    assert out["crawler"] is False
    seated = Node(dest)
    seated.boot()
    assert seated.chain.tip == tip
    assert seated.chain.path.read_bytes() == archive_bytes
    assert seated.install_root != src.install_root
    assert seated.state == "LOCAL"
    assert seated.pairs.list() == []
    with pytest.raises(QNMRefuse) as exc:
        src.archive.reexpand(Path(packed["path"]), tmp_path / "idx", from_index=True)
    assert exc.value.code == "QNM-ARCHIVE-NO-INDEX"


def test_crawlers_do_not_reexpand(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    packed = node.pack_archive()
    with pytest.raises(QNMRefuse) as exc:
        node.archive.reexpand(Path(packed["path"]), tmp_path / "crawl", actor="crawler")
    assert exc.value.code == "QNM-ARCHIVE-NO-CRAWLER"


def test_weights_are_not_the_tarball(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    with pytest.raises(QNMRefuse) as exc:
        node.archive.refuse_weights()
    assert exc.value.code == "QNM-ARCHIVE-NOT-WEIGHTS"
    fake = tmp_path / "model.pt"
    fake.write_bytes(b"not-a-chain")
    with pytest.raises(QNMRefuse) as wxc:
        node.verify_archive(fake)
    assert wxc.value.code == "QNM-ARCHIVE-NOT-WEIGHTS"


def test_summary_archive_refused(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    summary = json.dumps({"summary": True, "tip": node.chain.tip, "kinds": ["boot"]}).encode()
    dest = tmp_path / "data" / "archive" / "summary.tar"
    dest.parent.mkdir(parents=True, exist_ok=True)
    _tar(
        {
            CHAIN_MEMBER: summary,
            MANIFEST_MEMBER: json.dumps({"kind": "summary", "files": {CHAIN_MEMBER: sha256_hex(summary)}}).encode(),
        },
        dest,
    )
    with pytest.raises(QNMRefuse) as exc:
        node.verify_archive(dest)
    assert exc.value.code == "QNM-ARCHIVE-BYTES"


def test_api_archive_pack(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    code, packed = node.handle("POST", "/local/archive", b'{"op":"pack"}')
    assert code == 200
    assert Path(packed["path"]).is_file()
    assert packed["summary"] is False
