"""Light via — camera-flash OCC. Needs declare. Camera deny is PERM."""

from __future__ import annotations

from typing import Any

from qnsd.boot import QNSRefuse
from qnsd.light.camera import Camera
from qnsd.light.carrier import open_frame
from qnsd.light.codec import decode, encode
from qnsd.light.emitter import Emitter
from qnsd.photon import dumps, loads
from qnsd.vias.base import (
    ABSENT,
    HOOK_PENDING,
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
    mock = False
    device_hook = HOOK_PENDING
    protocol = "REAL"

    def __init__(self) -> None:
        self.camera = Camera()
        self.emitter = Emitter()

    def presence(self, ctx: ViaContext) -> str:
        if ctx.fabric_armed:
            return PRESENT
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
        sealed = _sealed_photon(raw)
        if sealed is not None:
            return ViaResult(
                ok=True,
                kind=OK,
                via=self.name,
                photon=sealed,
                detail="sealed photon frame",
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
        payload = dumps(photon)
        try:
            carried = self.emitter.carry(payload)
        except QNSRefuse:
            carried = {
                "ok": False,
                "mock": True,
                "simulated": True,
                "real_hardware": False,
                "live": False,
                "hardware": "simulated",
            }
        # A named driver is not a lamp. Only real_hardware may set live_link.
        live = bool(carried.get("real_hardware"))
        return ViaResult(
            ok=True,
            kind=OK,
            via=self.name,
            photon=photon,
            detail="light protocol emit; camera/emitter HOOK-PENDING"
            if not live
            else "light emit",
            hook_pending=not live,
            live_link=live,
            fielded=False,
            status=HOOK_PENDING if not live else "REAL",
            code="" if live else "QNS-HOOK-PENDING",
        )


def _sealed_photon(raw: bytes) -> dict[str, Any] | None:
    if not isinstance(raw, (bytes, bytearray)) or not bytes(raw).startswith(b"\xaa\xaa\xaa\xaa"):
        return None
    try:
        payload = open_frame(bytes(raw))
        return loads(payload).to_dict()
    except Exception:
        return None


ADAPTER = LightAdapter()
