"""Light via — camera-flash OCC. Needs declare. Camera deny is PERM."""

from __future__ import annotations

from typing import Any

from qnsd.light.camera import Camera
from qnsd.light.codec import decode, encode
from qnsd.light.emitter import Emitter
from qnsd.vias.base import (
    ABSENT,
    OK,
    PERM,
    PRESENT,
    PROBE,
    BaseAdapter,
    ViaContext,
    ViaResult,
)


class LightAdapter(BaseAdapter):
    name = "light"

    def __init__(self) -> None:
        self.camera = Camera()
        self.emitter = Emitter()

    def presence(self, ctx: ViaContext) -> str:
        rec = ctx.declared_via("light")
        if rec or ctx.hooks.get("light_declared"):
            return PRESENT
        return ABSENT

    def admit(self, raw: bytes, ctx: ViaContext) -> ViaResult:
        if self.presence(ctx) == ABSENT:
            return ViaResult(
                ok=False,
                kind=ABSENT,
                via=self.name,
                absent=True,
                code="QNS-VIA-ABSENT",
                detail="light undeclared",
            )
        cam = ctx.hooks.get("camera") or self.camera
        if ctx.camera_deny or getattr(cam, "deny", False):
            return ViaResult(
                ok=False,
                kind=PERM,
                via=self.name,
                perm=True,
                code="QNS-CAMERA-DENY",
                detail="camera deny",
            )
        result = decode(raw)
        if result.get("kind") == "probe":
            return ViaResult(
                ok=False,
                kind=PROBE,
                via=self.name,
                probe=True,
                code="QNS-PROBE-NOT-PHOTON",
                detail="light without preamble",
            )
        return ViaResult(
            ok=True,
            kind=OK,
            via=self.name,
            photon=result.get("photon"),
            detail="light admit",
        )

    def emit(self, photon: dict[str, Any], ctx: ViaContext) -> ViaResult:
        if self.presence(ctx) == ABSENT:
            return ViaResult(
                ok=False,
                kind=ABSENT,
                via=self.name,
                absent=True,
                code="QNS-VIA-ABSENT",
                detail="light undeclared",
            )
        cam = ctx.hooks.get("camera") or self.camera
        if ctx.camera_deny or getattr(cam, "deny", False):
            return ViaResult(
                ok=False,
                kind=PERM,
                via=self.name,
                perm=True,
                code="QNS-CAMERA-DENY",
                detail="camera deny",
            )
        bits = encode(photon)
        self.emitter.flash(bits)
        return ViaResult(
            ok=True,
            kind=OK,
            via=self.name,
            photon=photon,
            detail="light emit",
        )


ADAPTER = LightAdapter()
