"""Per-peer budgets, circuit breaker, and local trust notes.

Every peer starts untrusted. Limits are local. Opening a circuit or
quarantining a handle does not tell any other node to do the same.
Trust fields are signals. There is no score and no public ranking.

Author: Aziel Eliab only.
"""

from __future__ import annotations

import time
from typing import Any

from qnm.boot import QNMRefuse


class PeerGuard:
    def __init__(self) -> None:
        self.per_minute = 30
        self.byte_budget = 256_000
        self.breaker_threshold = 3
        self.breaker_seconds = 60.0
        self.quarantine: set[str] = set()
        self._hits: dict[str, list[tuple[float, int]]] = {}
        self._fails: dict[str, int] = {}
        self._open_until: dict[str, float] = {}
        self.heartbeats: dict[str, int] = {}
        self.hash_matches: dict[str, int] = {}
        self.vouches: dict[str, dict[str, Any]] = {}
        self.equivocation: set[str] = set()
        self.advisories: list[dict[str, Any]] = []
        self.advisory_flags: set[str] = set()

    def check(self, peer: str, nbytes: int, *, now: float | None = None) -> None:
        if peer in self.quarantine:
            raise QNMRefuse("FED-QUARANTINE", "this node has quarantined that handle")
        moment = time.monotonic() if now is None else now
        if self._open_until.get(peer, 0.0) > moment:
            raise QNMRefuse("FED-BREAKER", "peer circuit is open")
        window = [(stamp, size) for stamp, size in self._hits.get(peer, []) if moment - stamp < 60.0]
        messages = len(window)
        used = sum(size for _, size in window)
        if messages >= self.per_minute or used + max(nbytes, 0) > self.byte_budget:
            self.note_failure(peer, now=moment)
            raise QNMRefuse("FED-PEER-QUOTA", "per-peer budget")
        window.append((moment, max(nbytes, 0)))
        self._hits[peer] = window

    def note_failure(self, peer: str, *, now: float | None = None) -> None:
        moment = time.monotonic() if now is None else now
        count = self._fails.get(peer, 0) + 1
        self._fails[peer] = count
        if count >= self.breaker_threshold:
            self._open_until[peer] = moment + self.breaker_seconds

    def circuit(self, peer: str) -> dict[str, Any]:
        moment = time.monotonic()
        until = self._open_until.get(peer, 0.0)
        return {"peer": peer, "open": until > moment, "failures": self._fails.get(peer, 0)}
