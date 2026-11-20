"""Camera hook — QNS-CD-1.0.

deny=True is a permanent restriction (walker goes next).
No live device is opened. A captured buffer is not a camera.
"""

from __future__ import annotations

from typing import Any


class Camera:
    def __init__(self, deny: bool = False) -> None:
        self.deny = bool(deny)
        self.frames: list[bytes] = []
        self.mock = False
        self.real_hardware = False
        self.live = False

    def capture(self, frame: bytes | None = None) -> dict[str, Any]:
        if self.deny:
            return {
                "ok": False,
                "perm": True,
                "code": "QNS-CAMERA-DENY",
                "detail": "camera deny",
                "mock": False,
                "live": False,
                "real_hardware": False,
                "hardware": "simulated",
            }
        if frame is not None:
            self.frames.append(frame)
        return {
            "ok": True,
            "mock": False,
            "live": False,
            "real_hardware": False,
            "hardware": "simulated",
            "frames": len(self.frames),
        }
