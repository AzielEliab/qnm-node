"""Route planner. A security refusal does not try a lower route.

``live: true`` on a capability report does not make a route eligible.
"""

from __future__ import annotations

from typing import Any, Protocol

from qnsd.lan.contract import SendResult


class Adapter(Protocol):
    def capabilities(self) -> dict[str, Any]:
        ...

    def send(self, packet: dict[str, Any]) -> SendResult:
        ...


def _eligible(cap: dict[str, Any]) -> bool:
    if cap.get("enabled") is not True:
        return False
    if cap.get("revoked") is True:
        return False
    return True


class RoutePlanner:
    def __init__(self, adapters: list[Any]) -> None:
        self.adapters = list(adapters)

    def dispatch(self, packet: dict[str, Any]) -> SendResult:
        last = SendResult(
            outcome="absent",
            code="QNS-LAN-ABSENT",
            security=False,
            detail="no eligible route",
        )
        saw = False
        for adapter in self.adapters:
            cap = adapter.capabilities()
            if not _eligible(cap):
                continue
            saw = True
            result = adapter.send(packet)
            result.live = False
            if result.security or result.outcome in ("refused", "permanent"):
                return result
            if result.outcome == "ok" and result.ack_level == "stored":
                return result
            last = result
        if not saw:
            return last
        return last
