"""Memorial — QNS-CD-1.0.

Reuses QNM-BUILD-1.0 + AIH-WP-1.3 pair ledger. Not an account.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from qnm.memorial import Memorial as QnmMemorial


class Memorial:
    def __init__(self, root: Path) -> None:
        self._inner = QnmMemorial(root)
        self.root = Path(root)
        self.path = self._inner.path
        self.pair_path = self._inner.pair_path

    def living_pairs(self) -> list[dict[str, Any]]:
        return self._inner.living_pairs()

    def remember_pair(self, record: dict[str, Any]) -> dict[str, Any]:
        return self._inner.remember_pair(record)

    def forget_pair(self, pair_id: str) -> dict[str, Any] | None:
        return self._inner.forget_pair(pair_id)

    def forget_all_pairs(self) -> int:
        return self._inner.forget_all_pairs()

    def write(
        self,
        install_root: str,
        reason: str,
        pairs_cut: list[str] | None = None,
    ) -> dict[str, Any]:
        return self._inner.write(install_root, reason, pairs_cut=pairs_cut)

    def load(self) -> dict[str, Any] | None:
        return self._inner.load()
