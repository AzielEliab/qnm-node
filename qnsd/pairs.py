"""AIH OFFER / ACCEPT / SEAL — QNS-CD-1.0.

SEAL is medium-independent (AIH-WP-1.3). It does not require OS
Bluetooth or Wi-Fi. bearer_id on SEAL is the path that day, not a
marriage license. Pair cut stops further emit.
"""

from __future__ import annotations

from typing import Any

from qnm.pairs import HOP_MAX_DEFAULT, Pairs as QnmPairs, compute_pair_id, handshake_seal
from qnsd.boot import AUTHOR, PAIR_SPEC, SPEC


class Pairs:
    def __init__(self, memorial: Any) -> None:
        self._inner = QnmPairs(memorial)

    def list(self) -> list[dict[str, Any]]:
        return self._inner.list()

    def ids(self) -> list[str]:
        return self._inner.ids()

    def peers(self) -> set[str]:
        return self._inner.peers()

    def has_edge(self, peer_root: str) -> bool:
        return self._inner.has_edge(peer_root)

    def get(self, pair_id: str) -> dict[str, Any] | None:
        return self._inner.get(pair_id)

    def living(self, pair_id: str) -> bool:
        if not pair_id:
            return True
        return self.get(pair_id) is not None

    def offer(self, **kwargs: Any) -> dict[str, Any]:
        rec = self._inner.offer(**kwargs)
        rec["os_bt"] = False
        rec["os_wifi"] = False
        rec["seal_needs_radio"] = False
        return rec

    def accept(self, offer: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        rec = self._inner.accept(offer, **kwargs)
        rec["seal_needs_radio"] = False
        return rec

    def seal(self, handshake: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        # SEAL independent of OS BT / Wi-Fi — via is path that day only.
        rec = self._inner.seal(handshake, **kwargs)
        rec["marriage_license"] = False
        rec["medium_independent"] = True
        rec["os_bt"] = False
        rec["os_wifi"] = False
        rec["seal_needs_radio"] = False
        rec["qnsd_spec"] = SPEC
        rec["pair_spec"] = PAIR_SPEC
        rec["author"] = AUTHOR
        return rec

    def cut(self, pair_id: str) -> dict[str, Any]:
        result = self._inner.cut(pair_id)
        result["no_further_emit"] = True
        return result

    def cut_all(self) -> dict[str, Any]:
        return self._inner.cut_all()


__all__ = [
    "HOP_MAX_DEFAULT",
    "Pairs",
    "compute_pair_id",
    "handshake_seal",
]
