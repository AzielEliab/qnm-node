"""RE-EXPAND-FROM-ARCHIVE — mesh law (Aziel Eliab only).

Bytes of the chain survive, not summaries.
Re-expand = archive verify + a new local node seated on that tip.
Not mesh growing from an index. Crawlers do not re-expand.
Weights are not the tarball.

Keeps split-the-wires, cold-copy, and die-with-the-pull.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from typing import Any

from qnm.boot import AUTHOR, IDENTITY, SPEC, QNMRefuse, _utc_now, install, sha256_hex
from qnm.chain import CHAIN_NAME, Chain
ARCHIVE_SPEC = "RE-EXPAND-1.0"
CHAIN_MEMBER = f"chain/{CHAIN_NAME}"
MANIFEST_MEMBER = "MANIFEST.json"
WEIGHT_SUFFIXES = (".pt", ".pth", ".bin", ".onnx", ".safetensors", ".gguf", ".ckpt")
SUMMARY_KINDS = frozenset({"summary", "index", "crawl", "crawler", "weights"})


def _tarinfo(name: str, blob: bytes) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=name)
    info.size = len(blob)
    return info


class ChainArchive:
    """Pack and verify raw chain bytes. Re-expand onto a new local node."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.dir = self.root / "data" / "archive"
        self.dir.mkdir(parents=True, exist_ok=True)

    def pack(self, *, kind: str = "qnm-chain-archive") -> dict[str, Any]:
        if kind in SUMMARY_KINDS:
            raise QNMRefuse("QNM-ARCHIVE-BYTES", "bytes of chain survive, not summaries")
        chain_path = self.root / "data" / "chain" / CHAIN_NAME
        if not chain_path.is_file() or not chain_path.stat().st_size:
            raise QNMRefuse("QNM-ARCHIVE-BYTES", "no chain bytes to pack")
        chain_bytes = chain_path.read_bytes()
        if _looks_like_summary(chain_bytes):
            raise QNMRefuse("QNM-ARCHIVE-BYTES", "bytes of chain survive, not summaries")
        probe = Chain(self.root).verify()
        if not probe["ok"]:
            raise QNMRefuse("QNM-WIRES-FAIL-CLOSED", "refuse to pack a broken chain")
        manifest = {
            "kind": "qnm-chain-archive",
            "spec": ARCHIVE_SPEC,
            "build": SPEC,
            "author": AUTHOR,
            "identity": IDENTITY,
            "utc": _utc_now(),
            "tip": probe["tip"],
            "length": probe["length"],
            "files": {CHAIN_MEMBER: sha256_hex(chain_bytes)},
            "summary": False,
            "index": False,
            "weights": False,
            "mesh_from_index": False,
        }
        man_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            tar.addfile(_tarinfo(CHAIN_MEMBER, chain_bytes), io.BytesIO(chain_bytes))
            tar.addfile(_tarinfo(MANIFEST_MEMBER, man_bytes), io.BytesIO(man_bytes))
        blob = buf.getvalue()
        digest = sha256_hex(blob)
        dest = self.dir / f"{digest}.tar"
        dest.write_bytes(blob)
        return {
            "ok": True,
            "path": str(dest),
            "digest": digest,
            "tip": probe["tip"],
            "length": probe["length"],
            "bytes": len(chain_bytes),
            "tarball_bytes": len(blob),
            "summary": False,
            "weights": False,
            "spec": ARCHIVE_SPEC,
            "author": AUTHOR,
        }

    def read_members(self, archive_path: Path) -> dict[str, bytes]:
        path = Path(archive_path)
        self._refuse_weights_name(path)
        if not path.is_file():
            raise QNMRefuse("QNM-ARCHIVE-MISSING", "archive file missing")
        try:
            with tarfile.open(path, mode="r") as tar:
                names = tar.getnames()
                if any(_is_weight_name(n) for n in names):
                    raise QNMRefuse("QNM-ARCHIVE-NOT-WEIGHTS", "weights are not the tarball")
                out: dict[str, bytes] = {}
                for name in names:
                    handle = tar.extractfile(name)
                    if handle is not None:
                        out[name] = handle.read()
        except tarfile.TarError as exc:
            raise QNMRefuse("QNM-ARCHIVE-BYTES", "not a chain tarball") from exc
        return out

    def verify(self, archive_path: Path) -> dict[str, Any]:
        members = self.read_members(archive_path)
        if CHAIN_MEMBER not in members:
            raise QNMRefuse("QNM-ARCHIVE-BYTES", "bytes of chain survive, not summaries")
        chain_bytes = members[CHAIN_MEMBER]
        if _looks_like_summary(chain_bytes):
            raise QNMRefuse("QNM-ARCHIVE-BYTES", "bytes of chain survive, not summaries")
        manifest = _manifest(members)
        if manifest.get("kind") in SUMMARY_KINDS or manifest.get("summary") or manifest.get("index"):
            raise QNMRefuse("QNM-ARCHIVE-BYTES", "bytes of chain survive, not summaries")
        if manifest.get("weights") or manifest.get("kind") == "weights":
            raise QNMRefuse("QNM-ARCHIVE-NOT-WEIGHTS", "weights are not the tarball")
        expected = str((manifest.get("files") or {}).get(CHAIN_MEMBER) or "")
        if expected and expected != sha256_hex(chain_bytes):
            raise QNMRefuse("QNM-WIRES-FAIL-CLOSED", "archive chain hash mismatch")
        tip, length = _verify_chain_bytes(chain_bytes)
        if manifest.get("tip") and manifest["tip"] != tip:
            raise QNMRefuse("QNM-WIRES-FAIL-CLOSED", "archive tip does not match chain bytes")
        return {
            "ok": True,
            "tip": tip,
            "length": length,
            "bytes": len(chain_bytes),
            "summary": False,
            "index": False,
            "weights": False,
            "crawler": False,
            "spec": ARCHIVE_SPEC,
            "author": AUTHOR,
        }

    def reexpand(
        self,
        archive_path: Path,
        dest_root: Path,
        *,
        actor: str = "operator",
        from_index: bool = False,
        entropy: bytes | None = None,
        nonce: bytes | None = None,
    ) -> dict[str, Any]:
        if from_index:
            raise QNMRefuse(
                "QNM-ARCHIVE-NO-INDEX",
                "re-expand is not mesh growing from an index",
            )
        if str(actor or "").strip().lower() in {"crawler", "bot", "spider", "scraper"}:
            raise QNMRefuse("QNM-ARCHIVE-NO-CRAWLER", "crawlers do not re-expand")
        checked = self.verify(archive_path)
        members = self.read_members(archive_path)
        dest = Path(dest_root)
        dest.mkdir(parents=True, exist_ok=True)
        chain_dir = dest / "data" / "chain"
        chain_dir.mkdir(parents=True, exist_ok=True)
        (dest / "data" / "witness").mkdir(parents=True, exist_ok=True)
        (dest / "data" / "archive").mkdir(parents=True, exist_ok=True)
        chain_bytes = members[CHAIN_MEMBER]
        (chain_dir / CHAIN_NAME).write_bytes(chain_bytes)
        record = install(dest, entropy=entropy, nonce=nonce)
        seated = Chain(dest)
        verified = seated.verify()
        if not verified["ok"] or verified["tip"] != checked["tip"]:
            raise QNMRefuse("QNM-WIRES-FAIL-CLOSED", "re-expand verify failed")
        if seated.path.read_bytes() != chain_bytes:
            raise QNMRefuse("QNM-ARCHIVE-BYTES", "re-expand must keep chain bytes")
        sidecar = {
            "kind": "reexpand",
            "tip": verified["tip"],
            "length": verified["length"],
            "install_root": record["install_root"],
            "mesh_from_index": False,
            "crawler": False,
            "weights": False,
            "summary": False,
            "new_local_node": True,
            "utc": _utc_now(),
            "spec": ARCHIVE_SPEC,
            "author": AUTHOR,
        }
        (dest / "data" / "witness" / "reexpand.json").write_text(
            json.dumps(sidecar, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        return {
            "ok": True,
            "tip": verified["tip"],
            "length": verified["length"],
            "bytes": len(chain_bytes),
            "install_root": record["install_root"],
            "new_local_node": True,
            "mesh_from_index": False,
            "crawler": False,
            "weights": False,
            "summary": False,
            "pairs": 0,
            "spec": ARCHIVE_SPEC,
            "author": AUTHOR,
        }

    def refuse_weights(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse("QNM-ARCHIVE-NOT-WEIGHTS", "weights are not the tarball")

    def refuse_crawler(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse("QNM-ARCHIVE-NO-CRAWLER", "crawlers do not re-expand")

    def refuse_index(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse("QNM-ARCHIVE-NO-INDEX", "re-expand is not mesh growing from an index")

    def restore(
        self,
        archive_path: Path,
        *,
        digest: str | None = None,
    ) -> dict[str, Any]:
        """Restore a packed tip only with a matching tarball digest. Unsigned refuses."""
        expect = str(digest or "").strip().lower()
        if not expect:
            raise QNMRefuse("QNM-TIP-UNSIGNED", "unsigned tip restore refused")
        path = Path(archive_path)
        if not path.is_file():
            raise QNMRefuse("QNM-ARCHIVE-MISSING", "archive file missing")
        got = sha256_hex(path.read_bytes())
        if got != expect:
            raise QNMRefuse("QNM-TIP-UNSIGNED", "tip restore digest mismatch")
        verified = self.verify(path)
        verified["digest"] = got
        verified["signed"] = True
        verified["restored"] = True
        return verified

    def _refuse_weights_name(self, path: Path) -> None:
        if _is_weight_name(path.name):
            raise QNMRefuse("QNM-ARCHIVE-NOT-WEIGHTS", "weights are not the tarball")


def _is_weight_name(name: str) -> bool:
    lowered = name.lower()
    if "weight" in lowered or "safetensor" in lowered:
        return True
    return lowered.endswith(WEIGHT_SUFFIXES)


def _looks_like_summary(blob: bytes) -> bool:
    text = blob.decode("utf-8", errors="replace").strip()
    if not text:
        return True
    try:
        row = json.loads(text)
    except json.JSONDecodeError:
        return False
    if isinstance(row, dict) and (
        row.get("summary")
        or row.get("index")
        or "seq" not in row
        or "hash" not in row
        or "prev" not in row
    ):
        return True
    return False


def _manifest(members: dict[str, bytes]) -> dict[str, Any]:
    raw = members.get(MANIFEST_MEMBER)
    if raw is None:
        return {"kind": "qnm-chain-archive", "files": {}}
    try:
        row = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QNMRefuse("QNM-ARCHIVE-BYTES", "manifest is not JSON") from exc
    if not isinstance(row, dict):
        raise QNMRefuse("QNM-ARCHIVE-BYTES", "manifest must be an object")
    return row


def _verify_chain_bytes(chain_bytes: bytes) -> tuple[str, int]:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        dest = root / "data" / "chain"
        dest.mkdir(parents=True)
        (dest / CHAIN_NAME).write_bytes(chain_bytes)
        verified = Chain(root).verify()
    if not verified["ok"]:
        raise QNMRefuse("QNM-WIRES-FAIL-CLOSED", "; ".join(verified["errors"]))
    return str(verified["tip"]), int(verified["length"])
