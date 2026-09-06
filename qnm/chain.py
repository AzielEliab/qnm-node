"""Append-only local chain — QNM-BUILD-1.0 §8.

Receipts live on disk under data/chain/. No rewrite. No remote tip.
This is not lattice_online and not mesh_complete.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from qnm.boot import AUTHOR, SPEC, QNMRefuse, _utc_now, sha256_hex

GENESIS_PREV = "0" * 64
CHAIN_NAME = "node.jsonl"


def _canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


@dataclass(frozen=True)
class Link:
    seq: int
    kind: str
    body: dict[str, Any]
    prev: str
    hash: str
    utc: str
    spec: str = SPEC
    author: str = AUTHOR


class Chain:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.path = self.root / "data" / "chain" / CHAIN_NAME
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._links: list[Link] = []
        if self.path.is_file():
            self._load()

    def __len__(self) -> int:
        return len(self._links)

    def __iter__(self) -> Iterator[Link]:
        return iter(self._links)

    @property
    def tip(self) -> str:
        return self._links[-1].hash if self._links else GENESIS_PREV

    def _load(self) -> None:
        links: list[Link] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            links.append(
                Link(
                    seq=int(row["seq"]),
                    kind=str(row["kind"]),
                    body=dict(row["body"]),
                    prev=str(row["prev"]),
                    hash=str(row["hash"]),
                    utc=str(row["utc"]),
                    spec=str(row.get("spec", SPEC)),
                    author=str(row.get("author", AUTHOR)),
                )
            )
        self._links = links

    def append(self, kind: str, body: dict[str, Any] | None = None) -> Link:
        if kind in ("lattice_online", "mesh_complete", "Lumen", "Mandible"):
            raise QNMRefuse("QNM-APG-POISON", "forbidden live symbol")
        payload = dict(body or {})
        prev = self.tip
        utc = _utc_now()
        seq = len(self._links) + 1
        core = {
            "author": AUTHOR,
            "body": payload,
            "kind": kind,
            "prev": prev,
            "seq": seq,
            "spec": SPEC,
            "utc": utc,
        }
        digest = sha256_hex(_canonical(core))
        link = Link(
            seq=seq,
            kind=kind,
            body=payload,
            prev=prev,
            hash=digest,
            utc=utc,
        )
        line = json.dumps(
            {
                "seq": link.seq,
                "kind": link.kind,
                "body": link.body,
                "prev": link.prev,
                "hash": link.hash,
                "utc": link.utc,
                "spec": link.spec,
                "author": link.author,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
        self._links.append(link)
        return link

    def verify(self) -> dict[str, Any]:
        errors: list[str] = []
        prev = GENESIS_PREV
        for i, link in enumerate(self._links):
            core = {
                "author": link.author,
                "body": link.body,
                "kind": link.kind,
                "prev": link.prev,
                "seq": link.seq,
                "spec": link.spec,
                "utc": link.utc,
            }
            expected = sha256_hex(_canonical(core))
            if link.hash != expected:
                errors.append(f"index {i}: hash mismatch")
            if link.prev != prev:
                errors.append(f"index {i}: broken prev")
            prev = link.hash
        return {
            "ok": not errors,
            "length": len(self._links),
            "tip": self.tip,
            "errors": errors,
        }
