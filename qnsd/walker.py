"""ViaStack + restriction walker — QNS-CD-1.0.

Every send class lives in one program. Restriction walks the next
class automatically. force_via restricted ⇒ wait, no silent remap.
Sticky-via banned. Packet id does not change across hops.
"""

from __future__ import annotations

from typing import Any

from qnsd.boot import AUTHOR, SPEC, QNSRefuse
from qnsd.photon import HOP_MAX_DEFAULT, Photon
from qnsd.policy import Policy
from qnsd.translate import apply as translate_apply
from qnsd.vias import ADAPTERS, VIA_ORDER
from qnsd.vias.base import ABSENT, FAIL, PERM, PROBE, ViaAdapter, ViaContext, ViaResult

NO_EMIT = ("ISOLATED", "PHOENIX_LOCK", "SCORCHED")


class ViaStack:
    def __init__(
        self,
        adapters: dict[str, ViaAdapter] | None = None,
        policy: Policy | None = None,
    ) -> None:
        self.adapters = dict(adapters or ADAPTERS)
        self.policy = policy or Policy()

    def classes(self, state: str, policy: Policy | None = None) -> tuple[str, ...]:
        pol = policy or self.policy
        if state == "COLD":
            return ("local",)
        if state in NO_EMIT:
            return ()
        if pol.force_via:
            return (pol.force_via,)
        if pol.always_try:
            return tuple(VIA_ORDER)
        return tuple(VIA_ORDER)

    def walk(
        self,
        photon: Photon | dict[str, Any],
        *,
        ctx: ViaContext,
        policy: Policy | None = None,
        via_in: str = "",
        pairs_living: bool = True,
        start_at: str | None = None,
    ) -> dict[str, Any]:
        pol = policy or self.policy
        body = photon.to_dict() if isinstance(photon, Photon) else dict(photon)
        photon_id = str(body.get("photon_id") or "")
        hop = int(body.get("hop") or 0)
        if "hop_max" in body and body["hop_max"] is not None:
            hop_max = int(body["hop_max"])
        elif pol.hop_max is not None:
            hop_max = int(pol.hop_max)
        else:
            hop_max = HOP_MAX_DEFAULT
        seen = list(body.get("seen") or [])

        if not pairs_living:
            raise QNSRefuse("QNS-PAIR-CUT", "no further emit")

        if hop >= hop_max:
            return self._drop("QNS-HOP-MAX", f"hops {hop} >= hop_max {hop_max}", body)

        me = str(body.get("src") or "") + ":" + str(hop)
        token = photon_id or me
        if token in seen or (body.get("dst") and body["dst"] in seen and hop > 0):
            return self._drop("QNS-LOOP-DROP", "loop in seen", body)
        # also drop if a hop mark already recorded
        mark = f"{body.get('via')}:{hop}"
        if mark in seen and body.get("via"):
            return self._drop("QNS-LOOP-DROP", "loop in seen", body)

        order = self.classes(ctx.state, pol)
        if start_at and start_at in order:
            order = order[order.index(start_at) :]
        tried: list[str] = []
        results: list[dict[str, Any]] = []
        restricted = bool(pol.force_via)

        if not order:
            raise QNSRefuse("QNS-NO-EMIT", f"no emit in {ctx.state}")

        for name in order:
            adapter = self.adapters[name]
            presence = adapter.presence(ctx)
            tried.append(name)
            if presence == ABSENT:
                results.append(
                    {"via": name, "kind": ABSENT, "code": "QNS-VIA-ABSENT"}
                )
                if restricted:
                    return self._wait(body, name, "force_via restricted; absent")
                continue
            emitted = adapter.emit(body, ctx)
            results.append(emitted.as_dict())
            if emitted.ok:
                via_from = via_in or str(body.get("via_in") or body.get("via") or "")
                translated = translate_apply(body, via_in=via_from or name, via_out=name)
                out = translated.to_dict()
                out["hop"] = hop + 1
                out["seen"] = seen + [token]
                out["via"] = name
                return {
                    "ok": True,
                    "emitted": True,
                    "waiting": False,
                    "dropped": False,
                    "via": name,
                    "via_in": via_from or name,
                    "via_out": name,
                    "translate": bool(out["translate"]),
                    "photon_id": out["photon_id"],
                    "photon": out,
                    "tried": tried,
                    "walked": tried,
                    "results": results,
                    "remapped": False,
                    "api_calls": 1,
                    "spec": SPEC,
                    "author": AUTHOR,
                }
            if emitted.kind == PROBE:
                return {
                    "ok": False,
                    "emitted": False,
                    "probe": True,
                    "is_photon": False,
                    "code": "QNS-PROBE-NOT-PHOTON",
                    "via": name,
                    "tried": tried,
                    "spec": SPEC,
                    "author": AUTHOR,
                }
            if emitted.kind == PERM:
                if restricted:
                    return self._wait(body, name, "force_via restricted; perm")
                continue
            if emitted.kind in (FAIL, ABSENT):
                if restricted:
                    return self._wait(body, name, "force_via restricted; no silent remap")
                continue
            if restricted:
                return self._wait(body, name, "force_via restricted")

        if restricted:
            return self._wait(body, pol.force_via or tried[-1], "force_via restricted")

        # Always-try exhausted — wait on last class, no remap beyond stack
        last = tried[-1] if tried else "local"
        return self._wait(body, last, "via stack exhausted")

    def admit(
        self,
        raw: bytes,
        *,
        via: str,
        ctx: ViaContext,
    ) -> ViaResult:
        if via not in self.adapters:
            raise QNSRefuse("QNS-VIA-UNKNOWN", f"unknown via:{via}")
        return self.adapters[via].admit(raw, ctx)

    def _wait(self, photon: dict[str, Any], via: str, reason: str) -> dict[str, Any]:
        return {
            "ok": True,
            "emitted": False,
            "waiting": True,
            "dropped": False,
            "death": False,
            "remapped": False,
            "via": via,
            "reason": reason,
            "photon_id": photon.get("photon_id"),
            "photon": photon,
            "code": "QNS-FORCE-WAIT" if "force_via" in reason else "QNS-PATH-WAIT",
            "api_calls": 1,
            "spec": SPEC,
            "author": AUTHOR,
        }

    def _drop(self, code: str, detail: str, photon: dict[str, Any]) -> dict[str, Any]:
        return {
            "ok": False,
            "emitted": False,
            "waiting": False,
            "dropped": True,
            "death": False,
            "code": code,
            "detail": detail,
            "photon_id": photon.get("photon_id"),
            "spec": SPEC,
            "author": AUTHOR,
        }


def seen_loop(photon: Photon | dict[str, Any], token: str) -> bool:
    body = photon.to_dict() if isinstance(photon, Photon) else photon
    return token in list(body.get("seen") or [])
