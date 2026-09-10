"""Camera hook — QNS-CD-1.0.

Mock-friendly. deny=True is a permanent restriction (walker goes next).
No live device is opened.
"""

from __future__ import annotations

from typing import Any


class Camera:
    def __init__(self, deny: bool = False) -> None:
        self.deny = bool(deny)
        self.frames: list[bytes] = []
        self.mock = True

    def capture(self, frame: bytes | None = None) -> dict[str, Any]:
        if self.deny:
            return {
                "ok": False,
                "perm": True,
                "code": "QNS-CAMERA-DENY",
                "detail": "camera deny",
                "mock": True,
            }
        if frame is not None:
            self.frames.append(frame)
        return {"ok": True, "mock": True, "frames": len(self.frames)}
