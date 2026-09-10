"""ViaAdapter Protocol — QNS-CD-1.0.

Every send class implements this Protocol. Sticky-via is banned: the
walker never remembers a last-success class as the next default.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

VIA_ORDER = ("lan", "plc", "bt", "rf", "light", "qns", "operator", "local")
ALWAYS_PRESENT = ("local", "qns", "operator")
DECLARE_REQUIRED = ("rf", "plc", "light")

PRESENT = "PRESENT"
ABSENT = "ABSENT"
PERM = "PERM"
FAIL = "FAIL"
WAIT = "WAIT"
OK = "OK"
PROBE = "PROBE"


@dataclass
class ViaContext:
    state: str = "COLD"
    declared: dict[str, dict[str, Any]] = field(default_factory=dict)
    camera_deny: bool = False
    lan_link: bool = False
    hooks: dict[str, Any] = field(default_factory=dict)

    def declared_via(self, name: str) -> dict[str, Any]:
        return dict(self.declared.get(name) or {})


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

    def presence(self, ctx: ViaContext) -> str:
        if self.name in ALWAYS_PRESENT:
            return PRESENT
        if self.name in DECLARE_REQUIRED:
            rec = ctx.declared_via(self.name)
            if not rec:
                return ABSENT
        return PRESENT

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
        return ViaResult(
            ok=True,
            kind=OK,
            via=self.name,
            photon=photon,
            detail="emitted",
        )
