"""Content-addressed objects and git-like refs.

Objects are keyed by SHA-256 and checked on read. A push publishes a
signed ref update (handle, ref, object hash, prev, seq, signature).
That update is what sync broadcasts. Conflicting updates for the same
handle and ref use the same fork check as receipt chains.

Author: Aziel Eliab only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from qnm.boot import QNMRefuse
from qnm.fedmesh.chain import classify_link
from qnm.fedmesh.wire import GENESIS_PREV, sha256_hex, utc_now, verify_ref


class ObjectStore:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, data: bytes) -> str:
        digest = sha256_hex(data)
        path = self.root / digest
        if not path.is_file():
            path.write_bytes(data)
            path.chmod(0o600)
        else:
            self.get(digest)
        return digest

    def get(self, digest: str) -> bytes:
        path = self.root / digest
        if not path.is_file():
            raise QNMRefuse("FED-FETCH", "object not in the local store")
        data = path.read_bytes()
        if sha256_hex(data) != digest:
            raise QNMRefuse("FED-TAMPER", "object bytes do not match the hash")
        return data

    def has(self, digest: str) -> bool:
        return (self.root / digest).is_file()


class RefLog:
    """One branch per (handle, ref name). Forks reuse classify_link."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.tips: dict[tuple[str, str], dict[str, Any]] = {}
        self.seen: dict[tuple[str, str, int], str] = {}
        if self.path.is_file():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    self._accept(json.loads(line), persist=False)

    def tip(self, handle: str, ref: str) -> tuple[int, str]:
        row = self.tips.get((handle, ref))
        if row is None:
            return 0, GENESIS_PREV
        return int(row["seq"]), str(row["hash"])

    def apply(self, update: dict[str, Any]) -> dict[str, Any]:
        return self._accept(update, persist=True)

    def _accept(self, update: dict[str, Any], *, persist: bool) -> dict[str, Any]:
        verify_ref(update)
        handle = str(update["handle"])
        ref = str(update["ref"])
        seq = int(update["seq"])
        prev = str(update["prev"])
        digest = str(update["hash"])
        key = (handle, ref)
        seen_key = (handle, ref, seq)
        tip = self.tips.get(key)
        classify_link(
            seen=self.seen.get(seen_key),
            tip_seq=None if tip is None else int(tip["seq"]),
            tip_hash=None if tip is None else str(tip["hash"]),
            seq=seq,
            prev=prev,
            digest=digest,
        )
        if persist:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(update, sort_keys=True, separators=(",", ":")) + "\n")
                fh.flush()
        self.seen[seen_key] = digest
        self.tips[key] = {"seq": seq, "hash": digest, "object": update["object"]}
        return update


def digest_status(*, handle: str, receipt_tip: str, refs: list[dict[str, Any]]) -> dict[str, Any]:
    """Lightweight state digest. Hashes only."""
    body = {
        "v": "FED-MESH-1.0-draft",
        "kind": "digest",
        "handle": handle,
        "receipt_tip": receipt_tip,
        "refs": refs,
        "utc": utc_now(),
    }
    body["engine_digest"] = sha256_hex(
        json.dumps(
            {"handle": handle, "receipt_tip": receipt_tip, "refs": refs},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    return body
