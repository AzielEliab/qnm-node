"""Flash emitter hook — QNS-CD-1.0.

Mock-friendly. Records OOK frames. No live LED / camera flash.
"""

from __future__ import annotations

from typing import Any


class Emitter:
    def __init__(self) -> None:
        self.flashes: list[bytes] = []
        self.mock = True

    def flash(self, bits: bytes) -> dict[str, Any]:
        self.flashes.append(bits)
        return {"ok": True, "mock": True, "count": len(self.flashes)}
