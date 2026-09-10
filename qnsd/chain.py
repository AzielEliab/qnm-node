"""Append-only local chain — QNS-CD-1.0.

JSONL under data/chain/. Reuses QNM-BUILD-1.0 Chain. No rewrite.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from qnm.chain import Chain as QnmChain, Link
from qnsd.boot import AUTHOR, SPEC


class Chain:
    def __init__(self, root: Path) -> None:
        self._inner = QnmChain(root)
        self.root = Path(root)
        self.path = self._inner.path

    def __len__(self) -> int:
        return len(self._inner)

    @property
    def tip(self) -> str:
        return self._inner.tip

    def append(self, kind: str, body: dict[str, Any] | None = None) -> Link:
        payload = dict(body or {})
        payload.setdefault("qnsd_spec", SPEC)
        payload.setdefault("author", AUTHOR)
        return self._inner.append(kind, payload)

    def verify(self) -> dict[str, Any]:
        return self._inner.verify()
