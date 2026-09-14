"""ViaAdapter Protocol — QNS-CD-1.0.

Every send class implements this Protocol. Sticky-via is banned: the
walker never remembers a last-success class as the next default.

OS radios (cellular, Wi-Fi, Bluetooth, GNSS, NFC) stamp
LIVE | ABSENT | REFUSED from real host probes. No mock chatter.
Light camera/emitter stays HOOK-PENDING. Photon codec is REAL.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

VIA_ORDER = (
    "lan",
    "wifi",
    "plc",
    "bt",
    "rf",
    "gps",
    "nfc",
    "light",
    "qns",
    "operator",
    "local",
)
ALWAYS_PRESENT = ("local", "qns", "operator")
DECLARE_REQUIRED = ("plc", "light")
PHYSICAL_HOOK = ("light",)
OS_PHY = ("rf", "wifi", "bt", "gps", "nfc")
SOFTWARE_DECLARE = ("lan", "plc")
CHANNELS_ON = (
    "rf",
    "bt",
    "wifi",
    "gps",
    "nfc",
    "light",
    "lan",
    "plc",
    "qns",
    "operator",
    "local",
)
SOFT_RADIO_CHANNELS = OS_PHY + ("bitmesh",)
CHANNELS_ON_MEANS = "software path allowed; OS PHYs LIVE|ABSENT|REFUSED"
MOCK = "MOCK"

PRESENT = "PRESENT"
ABSENT = "ABSENT"
PERM = "PERM"
FAIL = "FAIL"
WAIT = "WAIT"
OK = "OK"
PROBE = "PROBE"
HOOK_PENDING = "HOOK-PENDING"
REFUSED = "REFUSED"
FIELDING_REAL = "REAL"
FIELDING_HOOK = "HOOK-PENDING"
FIELDING_OFF = "OFF"
FIELDING_LIVE = "LIVE"
FIELDING_ABSENT = "ABSENT"
FIELDING_REFUSED = "REFUSED"


def physical_via_stamps(ctx: ViaContext | None = None) -> dict[str, str]:
    """OS PHYs are LIVE or ABSENT. Light camera stays HOOK-PENDING."""
    seated = ctx if ctx is not None else ViaContext()
    stamps = {name: channel_fielding(name, seated) for name in OS_PHY}
    stamps["light"] = channel_fielding("light", seated)
    return stamps


def radios_stamp(enabled: bool) -> str:
    """Channels-ON software path. Never an invented live mesh."""
    return "software-on" if enabled else "off"


def channel_honesty(*, enabled: bool, ctx: ViaContext | None = None) -> dict[str, Any]:
    """Public honesty block. Architecture path ≠ fielded radios."""
    seated = ctx if ctx is not None else ViaContext(fabric_armed=enabled)
    audit = audit_channels(seated)
    phy = dict(audit["physical_vias"])
    live_any = any(label == FIELDING_LIVE for name, label in phy.items() if name in OS_PHY)
    return {
        "channels_on": list(CHANNELS_ON) if enabled else [],
        "all_channels_on": bool(enabled),
        "channels_on_means": CHANNELS_ON_MEANS,
        "radios": radios_stamp(enabled),
        "radios_fielded": False,
        "radios_status": FIELDING_LIVE if live_any else FIELDING_ABSENT,
        "physical_vias": phy,
        "os_phy": dict(audit.get("os_phy") or {}),
        "photon": "REAL",
        "photon_channel": FIELDING_ABSENT,
        "bitmesh_channel": phy.get("gps", FIELDING_ABSENT),
        "fielded_phy": False,
        "plane_c_attest_before_live": True,
        "live_rf_mesh": False,
        "live_bt_link": bool(phy.get("bt") == FIELDING_LIVE),
        "live_wifi_link": bool(phy.get("wifi") == FIELDING_LIVE),
        "live_cellular": bool(phy.get("rf") == FIELDING_LIVE),
        "live_gnss": bool(phy.get("gps") == FIELDING_LIVE),
        "live_nfc": bool(phy.get("nfc") == FIELDING_LIVE),
        "live_flash": False,
        "mock": False,
        "invented": False,
    }


@dataclass
class ViaContext:
    state: str = "COLD"
    declared: dict[str, dict[str, Any]] = field(default_factory=dict)
    camera_deny: bool = False
    lan_link: bool = False
    fabric_armed: bool = False
    phy_drivers: dict[str, Any] = field(default_factory=dict)
    phy_runner: Any = None
    phy_cache: dict[str, Any] = field(default_factory=dict)
    hooks: dict[str, Any] = field(default_factory=dict)

    def declared_via(self, name: str) -> dict[str, Any]:
        return dict(self.declared.get(name) or {})

    def has_phy_driver(self, name: str) -> bool:
        driver = self.phy_drivers.get(name) or self.hooks.get(f"{name}_driver")
        return bool(driver)

    def phy(self, name: str) -> dict[str, Any]:
        """LIVE OS probe. Cached per context. Never invents a radio."""
        if name in self.phy_cache:
            return dict(self.phy_cache[name])
        from qnsd.phy import env_runner, probe

        runner = self.phy_runner if self.phy_runner is not None else env_runner()
        card = probe(name, runner=runner)
        self.phy_cache[name] = card
        return dict(card)


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
    fielded: bool = False
    status: str = ""

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
            "fielded": self.fielded,
            "status": self.status,
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
        if self.name in OS_PHY:
            return PRESENT if ctx.phy(self.name).get("live") else ABSENT
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
            fielded=False,
            status=HOOK_PENDING,
            code="QNS-HOOK-PENDING",
            detail=detail
            or (
                f"{self.name} camera/emitter hook pending; "
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
                status=FIELDING_ABSENT,
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
        if self.presence(ctx) == ABSENT and self.name in OS_PHY:
            return os_phy_emit(self.name, photon, ctx)
        if self.presence(ctx) == ABSENT:
            return ViaResult(
                ok=False,
                kind=ABSENT,
                via=self.name,
                absent=True,
                status=FIELDING_ABSENT,
                code="QNS-VIA-ABSENT",
                detail=f"{self.name} absent",
            )
        if self.name in OS_PHY:
            return os_phy_emit(self.name, photon, ctx)
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


def os_phy_emit(name: str, photon: dict[str, Any], ctx: ViaContext) -> ViaResult:
    """LIVE OS emit: confirm adapter. Never invent over-the-air success."""
    from qnsd.phy import REFUSE_CODES, VIA_TO_PHY

    card = ctx.phy(name)
    phy = VIA_TO_PHY.get(name, name)
    if not card.get("live"):
        code = str(card.get("refuse_code") or REFUSE_CODES.get(phy) or "RADIO-ABSENT")
        return ViaResult(
            ok=False,
            kind=REFUSED,
            via=name,
            absent=True,
            live_link=False,
            fielded=False,
            status=FIELDING_REFUSED,
            code=code,
            detail=str(card.get("detail") or f"{phy} absent"),
            photon=photon,
        )
    if phy == "gps":
        return ViaResult(
            ok=False,
            kind=REFUSED,
            via=name,
            live_link=True,
            fielded=False,
            status=FIELDING_REFUSED,
            code="RADIO-GNSS-RX-ONLY",
            detail="GNSS is receive-only; not a transmit via",
            photon=photon,
        )
    return ViaResult(
        ok=True,
        kind=OK,
        via=name,
        photon=photon,
        live_link=True,
        fielded=False,
        status=FIELDING_LIVE,
        detail=f"{phy} adapter LIVE; transmitted=false (no invented chatter)",
        code="",
    )


def channel_fielding(name: str, ctx: ViaContext) -> str:
    """LIVE | ABSENT | REFUSED for OS PHYs. Software stays REAL."""
    if name in ALWAYS_PRESENT:
        return FIELDING_REAL
    if name in OS_PHY:
        card = ctx.phy(name)
        return FIELDING_LIVE if card.get("live") else FIELDING_ABSENT
    if ctx.has_phy_driver(name):
        return FIELDING_LIVE
    if name in PHYSICAL_HOOK:
        return FIELDING_HOOK if ctx.fabric_armed else FIELDING_OFF
    if name in SOFTWARE_DECLARE:
        return FIELDING_REAL if (ctx.fabric_armed or ctx.declared_via(name)) else FIELDING_OFF
    return FIELDING_ABSENT


def audit_channels(ctx: ViaContext | None = None) -> dict[str, Any]:
    """ALL-CHANNELS audit. OS radios are LIVE or ABSENT — never mock success."""
    seated = ctx if ctx is not None else ViaContext()
    rows: list[dict[str, Any]] = []
    for name in VIA_ORDER:
        fielding = channel_fielding(name, seated)
        phy = seated.phy(name) if name in OS_PHY else {}
        rows.append(
            {
                "name": name,
                "fielding": fielding,
                "armed": bool(seated.fabric_armed and name in CHANNELS_ON),
                "phy_driver": bool(phy.get("live") or seated.has_phy_driver(name)),
                "live_link": bool(phy.get("live")),
                "live_radio": bool(phy.get("live")),
                "adapter": phy.get("adapter") or "",
                "tool": phy.get("tool") or "",
            }
        )
    labels = {row["name"]: row["fielding"] for row in rows}
    labels["photon"] = FIELDING_REAL
    labels["cellular"] = labels.get("rf", FIELDING_ABSENT)
    os_labels = {name: labels[name] for name in OS_PHY}
    return {
        "ok": True,
        "channels": rows,
        "labels": labels,
        "os_phy": os_labels,
        "photon": {
            "name": "photon",
            "fielding": FIELDING_REAL,
            "protocol": "QNS1",
            "phy_driver": False,
            "live_link": False,
            "note": "codec REAL; not a radio PHY",
        },
        "physical_vias": {**os_labels, "light": labels.get("light", FIELDING_OFF)},
        "all_channels_on": bool(seated.fabric_armed),
        "invented_phy": False,
        "mock": False,
        "plane_c_attest_before_live": True,
        "live_rf_mesh": False,
        "live_bt_link": bool(os_labels.get("bt") == FIELDING_LIVE),
        "live_wifi_link": bool(os_labels.get("wifi") == FIELDING_LIVE),
        "live_cellular": bool(os_labels.get("rf") == FIELDING_LIVE),
        "live_gnss": bool(os_labels.get("gps") == FIELDING_LIVE),
        "live_nfc": bool(os_labels.get("nfc") == FIELDING_LIVE),
        "live_flash": False,
    }
