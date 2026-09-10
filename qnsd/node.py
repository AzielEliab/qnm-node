"""Local qnsd process — QNS-CD-1.0.

COLD → LOCAL → LIVE → DEGRADED → ISOLATED → PHOENIX_LOCK → SCORCHED.

Photon is the packet. Restriction walks the next class. Packet id does
not change across hops. API binds 127.0.0.1 only (see api.py).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from qnm.phoenix import Phoenix
from qnsd.apg import APG
from qnsd.azpipe import AZPIPE
from qnsd.boot import (
    AUTHOR,
    COMPANION,
    HUB_LAW,
    IDENTITY,
    PAIR_SPEC,
    PARENTS,
    SPEC,
    QNSRefuse,
    ensure_data_dirs,
    install,
    load_lock,
    lock_path,
    mark_scorched,
    resume,
)
from qnsd.chain import Chain
from qnsd.light.codec import decode as light_decode
from qnsd.memorial import Memorial
from qnsd.outbox import Outbox
from qnsd.pairs import HOP_MAX_DEFAULT, Pairs
from qnsd.photon import Photon, loads as photon_loads, make_photon
from qnsd.policy import Policy
from qnsd.receipts import Receipts
from qnsd.translate import apply as translate_apply
from qnsd.vias import ADAPTERS, VIA_ORDER
from qnsd.vias.base import ViaContext
from qnsd.walker import ViaStack

STATES = (
    "COLD",
    "LOCAL",
    "LIVE",
    "DEGRADED",
    "ISOLATED",
    "PHOENIX_LOCK",
    "SCORCHED",
)

_FORWARD = {
    "COLD": ("LOCAL",),
    "LOCAL": ("LIVE", "DEGRADED", "ISOLATED", "PHOENIX_LOCK", "SCORCHED"),
    "LIVE": ("DEGRADED", "ISOLATED", "PHOENIX_LOCK", "SCORCHED"),
    "DEGRADED": ("ISOLATED", "PHOENIX_LOCK", "SCORCHED"),
    "ISOLATED": ("PHOENIX_LOCK", "SCORCHED"),
    "PHOENIX_LOCK": ("SCORCHED",),
    "SCORCHED": (),
}

DEFAULT_PORT = 8891
DEFAULT_BIND = "127.0.0.1"


def load_cfg(root: Path) -> dict[str, Any]:
    path = Path(root) / "cfg" / "node.json"
    if not path.is_file():
        return {
            "spec": SPEC,
            "companion": COMPANION,
            "hub_law": HUB_LAW,
            "author": AUTHOR,
            "bind": DEFAULT_BIND,
            "port": DEFAULT_PORT,
            "radios": "off",
            "sticky_via": False,
        }
    return json.loads(path.read_text(encoding="utf-8"))


class Node:
    def __init__(self, root: Path | None = None, cfg: dict[str, Any] | None = None) -> None:
        self.root = Path(root) if root is not None else Path.cwd()
        ensure_data_dirs(self.root)
        self.cfg = cfg if cfg is not None else load_cfg(self.root)
        self.state = "COLD"
        self.identity = IDENTITY
        self.author = AUTHOR
        self.spec = SPEC
        self.install_root: str | None = None
        self.apg = APG()
        self.pipe = AZPIPE(self.apg)
        self.chain = Chain(self.root)
        self.receipts_log = Receipts(self.root, self.chain)
        self.outbox = Outbox(self.root)
        self.phoenix = Phoenix()
        self.memorial = Memorial(self.root)
        self.pairs = Pairs(self.memorial)
        self.policy = Policy(self.root)
        self.declared: dict[str, dict[str, Any]] = {}
        self._load_declared()
        self.stack = ViaStack(ADAPTERS, self.policy)
        self.camera_deny = False
        self.lan_link = False
        self._load_state_lock()

    def ctx(self) -> ViaContext:
        return ViaContext(
            state=self.state,
            declared=dict(self.declared),
            camera_deny=self.camera_deny,
            lan_link=self.lan_link,
        )

    def _advance(self, dest: str) -> None:
        if dest == self.state:
            return
        allowed = _FORWARD.get(self.state, ())
        if dest not in allowed:
            raise QNSRefuse("QNM-NO-AUTO-HEAL", f"{self.state} cannot become {dest}")
        self.state = dest
        self._persist_state()

    def _write_receipt(self, kind: str, body: dict[str, Any]) -> dict[str, Any] | None:
        return self.receipts_log.write(kind, body)

    def receipts(self) -> list[dict[str, Any]]:
        return self.receipts_log.list()

    def snapshot(self) -> dict[str, Any]:
        chain = self.chain.verify()
        presences = {name: self.stack.adapters[name].presence(self.ctx()) for name in VIA_ORDER}
        return {
            "ok": True,
            "state": self.state,
            "install_root": self.install_root,
            "identity": self.identity,
            "author": self.author,
            "spec": self.spec,
            "companion": COMPANION,
            "hub_law": HUB_LAW,
            "pair_bind": PAIR_SPEC,
            "parents": list(PARENTS),
            "via_order": list(VIA_ORDER),
            "presence": presences,
            "declared": dict(self.declared),
            "policy": self.policy.snapshot(),
            "radios": "off",
            "sticky_via": False,
            "auto_heal": False,
            "live_from_site_ping": False,
            "phoenix": self.phoenix.status(),
            "pairs": self.pairs.list(),
            "hop_max": self.policy.hop_max,
            "bell_pair": False,
            "qubit": False,
            "outbox": self.outbox.list(),
            "chain": {"ok": chain["ok"], "length": chain["length"], "tip": chain["tip"]},
            "bind": DEFAULT_BIND,
            "softwares_tab": False,
            "node_gate": False,
            "mesh_enable": False,
        }

    def boot(
        self,
        *,
        entropy: bytes | None = None,
        nonce: bytes | None = None,
        genesis: bytes | None = None,
        resume_from: str | Path | None = None,
    ) -> dict[str, Any]:
        if self.state == "SCORCHED":
            raise QNSRefuse("QNM-SCORCHED", "no account resurrection")
        lock = load_lock(self.root)
        if lock and lock.get("scorched"):
            self.install_root = str(lock.get("install_root") or "")
            self.state = "SCORCHED"
            raise QNSRefuse("QNM-NO-ACCOUNT", "scorched lock cannot resume live")
        if lock:
            record = resume(self.root, from_path=resume_from or lock_path(self.root))
        else:
            if resume_from is not None:
                record = resume(self.root, from_path=resume_from)
            else:
                record = install(self.root, entropy=entropy, nonce=nonce, genesis=genesis)
        self.install_root = str(record["install_root"])
        self.outbox.resume_from_locks()
        self._load_declared()
        self.policy._load()
        if self.state == "COLD":
            self._advance("LOCAL")
        if self.policy.operator and self.state == "LOCAL":
            self._advance("LIVE")
        self._write_receipt("boot", {"install_root": self.install_root, "state": self.state})
        return self.snapshot()

    def set_policy(self, body: dict[str, Any]) -> dict[str, Any]:
        self._require_not_scorched()
        snap = self.policy.apply(body)
        if self.policy.operator and self.state == "LOCAL":
            self._advance("LIVE")
        self._write_receipt("policy", snap)
        snap["state"] = self.state
        return snap

    def declare(self, via: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        self._require_not_scorched()
        if via not in VIA_ORDER:
            raise QNSRefuse("QNS-VIA-UNKNOWN", f"unknown via:{via}")
        rec = dict(extra or {})
        rec["via"] = via
        if via == "lan" and "link" not in rec:
            rec["link"] = True
        self.declared[via] = rec
        if via == "lan" and rec.get("link"):
            self.lan_link = True
        if via == "operator" and self.state == "LOCAL":
            self.policy.operator = True
            self.policy._persist()
            self._advance("LIVE")
        self._persist_declared()
        self._write_receipt("declare", rec)
        return {
            "ok": True,
            "via": via,
            "declared": rec,
            "presence": self.stack.adapters[via].presence(self.ctx()),
            "state": self.state,
            "spec": SPEC,
            "author": AUTHOR,
        }

    def pair_offer(self, peer_root: str, nonce: bytes | str | None = None, via: str | None = None) -> dict[str, Any]:
        self._require_pairable()
        rec = self.pairs.offer(
            root_a=self.install_root or "",
            peer_root=peer_root,
            nonce_a=nonce,
            via=via,
        )
        self._write_receipt("pair_offer", {"peer": peer_root, "via": via or ""})
        return rec

    def pair_accept(
        self,
        offer: dict[str, Any],
        nonce: bytes | str | None = None,
        via: str | None = None,
    ) -> dict[str, Any]:
        self._require_pairable()
        rec = self.pairs.accept(
            offer,
            root_b=self.install_root or "",
            nonce_b=nonce,
            via=via,
        )
        self._write_receipt("pair_accept", {"pair_id": rec["pair_id"], "via": via or ""})
        return rec

    def pair_seal(self, handshake: dict[str, Any], via: str | None = None) -> dict[str, Any]:
        self._require_pairable()
        rec = self.pairs.seal(handshake, self_root=self.install_root or "", via=via)
        self._write_receipt(
            "pair_seal",
            {
                "pair_id": rec["pair_id"],
                "bearer_id": rec.get("bearer_id") or "",
                "marriage_license": False,
                "medium_independent": True,
                "os_bt": False,
                "os_wifi": False,
            },
        )
        return rec

    def pair_cut(self, pair_id: str) -> dict[str, Any]:
        self._require_not_scorched()
        result = self.pairs.cut(pair_id)
        self._write_receipt("pair_cut", {"pair_id": pair_id, "no_further_emit": True})
        return result

    def isolate(self, reason: str = "tamper") -> dict[str, Any]:
        self._require_not_scorched()
        if self.state != "ISOLATED":
            if "ISOLATED" not in _FORWARD.get(self.state, ()):
                raise QNSRefuse("QNM-TAMPER-ISOLATE", f"cannot isolate from {self.state}")
            self._advance("ISOLATED")
        cut = self.pairs.cut_all()
        self._write_receipt("tamper_isolate", {"reason": reason, "pairs_cut": cut["cut_count"]})
        return self.snapshot()

    def arm_phoenix(self) -> dict[str, Any]:
        self._require_not_scorched()
        self.phoenix.arm()
        self._advance("PHOENIX_LOCK")
        cut = self.pairs.cut_all()
        self._write_receipt(
            "phoenix_arm",
            {"waiting": "local", "controller_hunt": False, "pairs_cut": cut["cut_count"]},
        )
        snap = self.snapshot()
        snap["phoenix"] = self.phoenix.status()
        return snap

    def heal(self) -> None:
        raise QNSRefuse("QNM-NO-AUTO-HEAL", "no auto-heal")

    def cut_outbox(self, item_id: str) -> dict[str, Any]:
        self._require_not_scorched()
        result = self.outbox.cut(item_id)
        self._write_receipt("outbox_cut", {"id": item_id})
        return result

    def admit(self, raw: bytes | str, via: str = "local") -> dict[str, Any]:
        self._require_not_scorched()
        data = raw.encode("utf-8") if isinstance(raw, str) else raw
        # Light OCC without preamble is a probe — before JSON parse.
        if data.startswith(b"OOK:") or via == "light":
            decoded = light_decode(data)
            if decoded.get("kind") == "probe":
                self._write_receipt("probe", {"via": via, "is_photon": False})
                return {
                    "ok": False,
                    "probe": True,
                    "is_photon": False,
                    "code": "QNS-PROBE-NOT-PHOTON",
                    "walk": False,
                    "spec": SPEC,
                    "author": AUTHOR,
                }
            photon = photon_loads(decoded["photon"])
            self._write_receipt("admit", {"via": via, "photon_id": photon.photon_id})
            return {"ok": True, "admitted": True, "via": via, "photon": photon.to_dict()}

        # AZPIPE: frag → sweep → fold → static → fold → entry
        card = self.pipe.admit(data)
        if card.get("skip_receipt"):
            pass
        else:
            self._write_receipt("azpipe", {"h": card.get("h"), "teth": card.get("teth")})
        if card.get("fold_receipt"):
            self._write_receipt("fold", {"teth": card.get("teth")})
        inner = card.get("inner") or {}
        photon = self._photon_from_inner(inner, via_in=via)
        result = self.stack.admit(data, via=via, ctx=self.ctx())
        self._write_receipt("admit", {"via": via, "photon_id": photon.photon_id, "kind": result.kind})
        return {
            "ok": True,
            "admitted": True,
            "via": via,
            "photon": photon.to_dict(),
            "photon_id": photon.photon_id,
            "pipe": {"teth": card.get("teth"), "skip_receipt": card.get("skip_receipt")},
            "spec": SPEC,
            "author": AUTHOR,
        }

    def emit(self, photon: Photon | dict[str, Any], via: str | None = None) -> dict[str, Any]:
        self._require_active()
        body = photon.to_dict() if isinstance(photon, Photon) else dict(photon)
        pair_id = str(body.get("pair_id") or "")
        if pair_id and not self.pairs.living(pair_id):
            raise QNSRefuse("QNS-PAIR-CUT", "no further emit")
        via_in = str(body.get("via_in") or body.get("via") or "")
        if via:
            # explicit emit class — still no sticky default
            adapter = self.stack.adapters[via]
            presence = adapter.presence(self.ctx())
            if presence == "ABSENT":
                raise QNSRefuse("QNS-VIA-ABSENT", f"{via} absent")
            emitted = adapter.emit(body, self.ctx())
            if not emitted.ok:
                raise QNSRefuse(emitted.code or "QNS-EMIT-FAIL", emitted.detail)
            translated = translate_apply(body, via_in=via_in or via, via_out=via)
            out = translated.to_dict()
            self._write_receipt(
                "emit",
                {
                    "via": via,
                    "photon_id": out["photon_id"],
                    "translate": out["translate"],
                },
            )
            return {
                "ok": True,
                "emitted": True,
                "via": via,
                "via_in": via_in or via,
                "via_out": via,
                "translate": out["translate"],
                "photon_id": out["photon_id"],
                "photon": out,
                "spec": SPEC,
                "author": AUTHOR,
            }
        return self.forward_photon(body, via_in=via_in)

    def forward_photon(
        self,
        photon: Photon | dict[str, Any],
        *,
        via_in: str = "",
        hop_max: int | None = None,
        seen: list[str] | None = None,
        start_at: str | None = None,
    ) -> dict[str, Any]:
        self._require_active()
        body = photon.to_dict() if isinstance(photon, Photon) else dict(photon)
        if hop_max is not None:
            body["hop_max"] = int(hop_max)
        if seen is not None:
            body["seen"] = list(seen)
        pair_id = str(body.get("pair_id") or "")
        living = self.pairs.living(pair_id)
        walked = self.stack.walk(
            body,
            ctx=self.ctx(),
            policy=self.policy,
            via_in=via_in or str(body.get("via_in") or ""),
            pairs_living=living,
            start_at=start_at,
        )
        if walked.get("waiting"):
            item = self.outbox.wait_photon(
                walked.get("photon") or body,
                str(walked.get("via") or ""),
                str(walked.get("reason") or "wait"),
            )
            walked["outbox_id"] = item["id"]
            walked["from_locks"] = True
            self._write_receipt("qns_wait", {"id": item["id"], "via": walked.get("via")})
        elif walked.get("emitted"):
            self._write_receipt(
                "walk",
                {
                    "via": walked.get("via"),
                    "tried": walked.get("tried"),
                    "photon_id": walked.get("photon_id"),
                    "translate": walked.get("translate"),
                },
            )
        elif walked.get("dropped"):
            self._write_receipt("drop", {"code": walked.get("code")})
        return walked

    def forward(
        self,
        dest: str,
        payload: dict[str, Any] | bytes | str,
        *,
        via: str | None = None,
        via_in: str = "",
        hop_max: int = HOP_MAX_DEFAULT,
        seen: list[str] | None = None,
        pair_id: str = "",
        start_at: str | None = None,
    ) -> dict[str, Any]:
        self._require_active()
        if isinstance(payload, (bytes, str)):
            admitted = self.admit(payload, via=via_in or via or "local")
            if admitted.get("probe"):
                return admitted
            inner = admitted["photon"]["payload"]
            photon = photon_loads(admitted["photon"])
            photon.dst = dest or photon.dst
            photon.hop_max = hop_max
            if seen is not None:
                photon.seen = list(seen)
            if pair_id:
                photon.pair_id = pair_id
        else:
            raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            self.apg.scan_raw(raw)
            photon = make_photon(
                src=self.install_root or "",
                dst=dest,
                pair_id=pair_id,
                payload=payload,
                via=via_in or via or "",
                hop_max=hop_max,
                seen=seen,
            )
        if via and self.policy.force_via is None and not self.policy.always_try:
            return self.emit(photon, via=via)
        return self.forward_photon(
            photon,
            via_in=via_in or via or "",
            hop_max=hop_max,
            seen=seen,
            start_at=start_at,
        )

    def ingress(self, raw: bytes | str, via: str = "local") -> dict[str, Any]:
        return self.admit(raw, via=via)

    def _photon_from_inner(self, inner: dict[str, Any], via_in: str) -> Photon:
        if inner.get("magic") == "QNS1":
            photon = photon_loads(inner)
        else:
            photon = make_photon(
                src=self.install_root or str(inner.get("src") or ""),
                dst=str(inner.get("dst") or inner.get("dest") or ""),
                pair_id=str(inner.get("pair_id") or ""),
                payload=inner if "payload" not in inner else dict(inner.get("payload") or {}),
                via=via_in,
            )
        photon.via_in = via_in
        photon.via = via_in
        if not photon.photon_id:
            photon.seal_id()
        return photon

    def _require_not_scorched(self) -> None:
        if self.state == "SCORCHED":
            raise QNSRefuse("QNM-SCORCHED", "node scorched")
        lock = load_lock(self.root)
        if lock and lock.get("scorched"):
            self.state = "SCORCHED"
            raise QNSRefuse("QNM-NO-ACCOUNT", "scorched lock")

    def _require_active(self) -> None:
        self._require_not_scorched()
        if self.state in ("COLD", "ISOLATED", "PHOENIX_LOCK"):
            if self.state == "COLD":
                return
            raise QNSRefuse("QNM-STATE-LOCKED", f"inactive in {self.state}")

    def handle(self, method: str, path: str, body: bytes = b"") -> tuple[int, dict[str, Any]]:
        from qnsd.api import handle_node

        return handle_node(self, method, path, body)

    def _require_pairable(self) -> None:
        self._require_not_scorched()
        if self.state in ("COLD", "ISOLATED", "PHOENIX_LOCK"):
            raise QNSRefuse("AIH-NO-EDGES", f"no pair in {self.state}")
        if not self.install_root:
            raise QNSRefuse("AIH-HANDSHAKE", "boot before pair-bind")

    def _declared_path(self) -> Path:
        return self.root / "data" / "locks" / "declared.json"

    def _persist_declared(self) -> None:
        path = self._declared_path()
        path.write_text(
            json.dumps(self.declared, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    def _load_declared(self) -> None:
        path = self._declared_path()
        if path.is_file():
            self.declared = json.loads(path.read_text(encoding="utf-8"))
            if self.declared.get("lan", {}).get("link"):
                self.lan_link = True

    def _persist_state(self) -> None:
        path = self.root / "data" / "locks" / "state.json"
        path.write_text(
            json.dumps(
                {
                    "state": self.state,
                    "install_root": self.install_root,
                    "spec": SPEC,
                    "author": AUTHOR,
                },
                sort_keys=True,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    def _load_state_lock(self) -> None:
        path = self.root / "data" / "locks" / "state.json"
        if path.is_file():
            data = json.loads(path.read_text(encoding="utf-8"))
            stored = str(data.get("state") or "")
            if stored in STATES and stored != "COLD":
                # Resume posture from locks without reversing the machine.
                self.state = stored if stored != "LIVE" else "LOCAL"
                # LIVE still requires operator policy on this process.
                if stored == "LIVE" and self.policy.operator:
                    self.state = "LIVE"
