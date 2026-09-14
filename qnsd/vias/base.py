"""ViaAdapter Protocol — QNS-CD-1.0.

Every send class implements this Protocol. Sticky-via is banned: the
walker never remembers a last-success class as the next default.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

VIA_ORDER = ("lan", "wifi", "plc", "bt", "rf", "light", "qns", "operator", "local")
ALWAYS_PRESENT = ("local", "qns", "operator")
DECLARE_REQUIRED = ("rf", "plc", "light", "wifi")
PHYSICAL_HOOK = ("bt", "rf", "wifi", "light")
CHANNELS_ON = ("rf", "bt", "wifi", "light", "lan", "plc", "qns", "operator", "local")

PRESENT = "PRESENT"
ABSENT = "ABSENT"
PERM = "PERM"
FAIL = "FAIL"
WAIT = "WAIT"
OK = "OK"
PROBE = "PROBE"
HOOK_PENDING = "HOOK-PENDING"


@dataclass
class ViaContext:
    state: str = "COLD"
    declared: dict[str, dict[str, Any]] = field(default_factory=dict)
    camera_deny: bool = False
    lan_link: bool = False
    fabric_armed: bool = False
    phy_drivers: dict[str, Any] = field(default_factory=dict)
    hooks: dict[str, Any] = field(default_factory=dict)

    def declared_via(self, name: str) -> dict[str, Any]:
        return dict(self.declared.get(name) or {})

    def has_phy_driver(self, name: str) -> bool:
        driver = self.phy_drivers.get(name) or self.hooks.get(f"{name}_driver")
        return bool(driver)


@dataclass
class ViaResult:
    ok: bool
    kind: str
    via: str
    detail: str = ""
    code: str = ""
    photon: dict[str, Any] | None = None
    probe: bool = False
    perm: bool = False
    absent: bool = False
    hook_pending: bool = False
    live_link: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "kind": self.kind,
            "via": self.via,
            "detail": self.detail,
            "code": self.code,
            "photon": self.photon,
            "probe": self.probe,
            "perm": self.perm,
            "absent": self.absent,
            "hook_pending": self.hook_pending,
            "live_link": self.live_link,
        }


@runtime_checkable
class ViaAdapter(Protocol):
    name: str

    def presence(self, ctx: ViaContext) -> str:
        """PRESENT or ABSENT."""

    def admit(self, raw: bytes, ctx: ViaContext) -> ViaResult:
        """Ingress on this class."""

    def emit(self, photon: dict[str, Any], ctx: ViaContext) -> ViaResult:
        """Egress on this class. Fail/perm/absent — never raise NotImplemented."""


class BaseAdapter:
    """Shared helpers. Concrete vias override presence/emit as needed."""

    name = "base"
    mock = False
    device_hook = "none"

    def presence(self, ctx: ViaContext) -> str:
        if self.name in ALWAYS_PRESENT:
            return PRESENT
        if ctx.fabric_armed and self.name in CHANNELS_ON:
            return PRESENT
        if self.name in DECLARE_REQUIRED:
            rec = ctx.declared_via(self.name)
            if not rec:
                return ABSENT
        return PRESENT

    def hook_pending_result(
        self,
        photon: dict[str, Any] | None = None,
        *,
        detail: str = "",
    ) -> ViaResult:
        return ViaResult(
            ok=False,
            kind=HOOK_PENDING,
            via=self.name,
            hook_pending=True,
            live_link=False,
            code="QNS-HOOK-PENDING",
            detail=detail
            or (
                f"{self.name} armed; device hook pending; "
                "no invented live link"
            ),
            photon=photon,
        )

    def admit(self, raw: bytes, ctx: ViaContext) -> ViaResult:
        if self.presence(ctx) == ABSENT:
            return ViaResult(
                ok=False,
                kind=ABSENT,
                via=self.name,
                absent=True,
                code="QNS-VIA-ABSENT",
                detail=f"{self.name} absent",
            )
        return ViaResult(
            ok=True,
            kind=OK,
            via=self.name,
            detail="admitted",
            live_link=False,
            photon={"raw_len": len(raw), "via": self.name},
        )

    def emit(self, photon: dict[str, Any], ctx: ViaContext) -> ViaResult:
        if self.presence(ctx) == ABSENT:
            return ViaResult(
                ok=False,
                kind=ABSENT,
                via=self.name,
                absent=True,
                code="QNS-VIA-ABSENT",
                detail=f"{self.name} absent",
            )
        if self.name in PHYSICAL_HOOK and not ctx.has_phy_driver(self.name):
            return self.hook_pending_result(photon)
        return ViaResult(
            ok=True,
            kind=OK,
            via=self.name,
            photon=photon,
            detail="emitted",
            live_link=bool(ctx.has_phy_driver(self.name)),
        )
