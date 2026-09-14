"""Local node process — QNM-BUILD-1.0 §5 + AIH-WP-1.3 pair-bind.

State: COLD → LOCAL → LIVE (operator bearer) → DEGRADED → ISOLATED
→ PHOENIX_LOCK → SCORCHED.

No auto-heal. No LIVE from site ping. PHOENIX-LOCK waits / re-seals
locally after poison or isolation — it does not restore a public
hostname. Public tunnels and sites die with the pull. Split the wires:
tick plane is presence + tip hash only; payload plane is pull-only.
Cold copies remain after a public pull. The network never lies, even
to stay alive. No rewrite key. Published tip is immutable. Receipts
still hash. Verify is without voice. Copies are not all on one tunnel.
Local API binds 127.0.0.1 only.
Receipts go to disk. Radios stay off. Pair-id is medium-independent
(AIH-WP-1.3). Isolation cuts pair edges. Not Bell-pair physics.
"""

from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from qnm.apg import APG
from qnm.bearers import Bearers
from qnm.boot import (
    AUTHOR,
    COMPANION,
    HUB_LAW,
    IDENTITY,
    PAIR_SPEC,
    SPEC,
    QNMRefuse,
    install,
    load_lock,
    lock_path,
    mark_scorched,
    resume,
    sha256_hex,
)
from qnm.archive import ChainArchive
from qnm.chain import Chain
from qnm.bitmesh import Bitmesh, refuse_public_geo
from qnm.coldcopy import DEVICE_CLASSES, ColdCopy
from qnm.fabric import CLAIM_CLOCK, FABRIC_SPEC, Fabric, mesh_never_enables
from qnm.planes import Planes
from qnsd.vias import radios_stamp
from qnm.unkillability import compute_unkillability
from qnm.memorial import Memorial
from qnm.nolie import NoLie, receipt_digest
from qnm.outbox import Outbox
from qnm.pairs import HOP_MAX_DEFAULT, Pairs
from qnm.phoenix import Phoenix
from qnm.score import score_local
from qnm.spiderweb import Spiderweb
from qnm.tethers import Tethers
from qnm.wires import DWELL_S, Lockset, Wires

STATES = (
    "COLD",
    "LOCAL",
    "LIVE",
    "DEGRADED",
    "ISOLATED",
    "PHOENIX_LOCK",
    "SCORCHED",
)

# Forward-only. No auto-heal / reverse.
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
LOCAL_PATHS = {
    "/local/boot",
    "/local/state",
    "/local/bearer",
    "/local/tether",
    "/local/pair",
    "/local/pairs",
    "/local/forward",
    "/local/ingress",
    "/local/outbox",
    "/local/outbox/cut",
    "/local/phoenix/arm",
    "/local/receipts",
    "/local/tick",
    "/local/pull",
    "/local/cite",
    "/local/emit",
    "/local/rejoin",
    "/local/vault",
    "/local/wires",
    "/local/archive",
    "/local/reheal",
    "/local/survive",
    "/local/nolie",
    "/local/rewrite",
    "/local/fabric",
    "/local/persist",
    "/local/bitmesh",
    "/local/unkillability",
    "/local/planes",
    "/local/channels",
    "/local/phy",
}


def ensure_data_dirs(root: Path) -> None:
    for name in (
        "chain",
        "locks",
        "outbox",
        "receipts",
        "witness",
        "vault",
        "archive",
        "bitmesh",
        "planes",
    ):
        (Path(root) / "data" / name).mkdir(parents=True, exist_ok=True)


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
            "auto_heal": False,
            "live_from_site_ping": False,
            "anon_broadcast_publish": False,
            "live_body_sync": False,
            "auto_splice": False,
            "named_hosts_only": True,
            "unmarked_hydra": False,
            "vpn_concealment": False,
            "cold_copy_n": 3,
            "dwell_s": DWELL_S,
            "public_network_required": False,
            "tips_need_live_data": False,
            "no_lie": True,
            "no_rewrite": True,
            "rewrite_key": False,
            "verify_without_voice": True,
            "copies_one_tunnel": False,
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
        self.bearers = Bearers()
        self.chain = Chain(self.root)
        self.outbox = Outbox(self.root)
        self.tethers = Tethers(self.root)
        self.phoenix = Phoenix()
        self.wires = Wires(self.root)
        self.vault = ColdCopy(self.root, replica_n=int(self.cfg.get("cold_copy_n") or 3))
        self.archive = ChainArchive(self.root)
        self.nolie = NoLie(self.root)
        self.fabric = Fabric(self.root)
        self.bitmesh = Bitmesh(self.root)
        self.planes = Planes(self.root, cfg=self.cfg)
        self.qnsd: Any | None = None
        self.memorial = Memorial(self.root)
        self.pairs = Pairs(self.memorial)
        self.spiderweb: Spiderweb | None = None
        self._receipt_dir = self.root / "data" / "receipts"
        self._receipt_dir.mkdir(parents=True, exist_ok=True)
        self._receipt_log = self._receipt_dir / "receipts.jsonl"
        if not self._receipt_log.is_file():
            self._receipt_log.write_text("", encoding="utf-8")

    def _write_receipt(self, kind: str, body: dict[str, Any]) -> dict[str, Any]:
        refuse_public_geo(body)
        link = self.chain.append(kind, body)
        receipt = {
            "kind": kind,
            "body": body,
            "hash": link.hash,
            "prev": link.prev,
            "seq": link.seq,
            "utc": link.utc,
            "spec": SPEC,
            "author": AUTHOR,
            "on_disk": True,
        }
        refuse_public_geo(receipt)
        receipt["receipt_hash"] = receipt_digest(receipt)
        with self._receipt_log.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
            fh.flush()
        leaf = self._receipt_dir / f"{link.seq:06d}-{link.hash[:16]}.json"
        leaf.write_text(
            json.dumps(receipt, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return receipt

    def receipts(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for line in self._receipt_log.read_text(encoding="utf-8").splitlines():
            if line.strip():
                items.append(json.loads(line))
        return items

    def verify_receipts(self, *, require_voice: bool = False, voice_confirm: bool = False) -> dict[str, Any]:
        """Receipts that still hash. Verify-without-voice."""
        return self.nolie.verify_without_voice(
            self.receipts(),
            require_voice=require_voice,
            voice_confirm=voice_confirm,
        )

    def rewrite_receipt(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse("QNM-NO-REWRITE", "receipts are append-only; no rewrite")

    def rewrite_published(self, tip: str = "", new_tip: str = "") -> None:
        self.nolie.rewrite_published(tip, new_tip)

    def rewrite_key(self, *_args: object, **_kwargs: object) -> None:
        self.nolie.rewrite_key()

    def _advance(self, dest: str) -> None:
        if dest == self.state:
            return
        allowed = _FORWARD.get(self.state, ())
        if dest not in allowed:
            raise QNMRefuse(
                "QNM-NO-AUTO-HEAL",
                f"{self.state} cannot become {dest}",
            )
        self.state = dest

    def snapshot(self) -> dict[str, Any]:
        chain = self.chain.verify()
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
            "bearers": self.bearers.snapshot(),
            "radios": radios_stamp(self.fabric.enabled),
            "radios_fielded": False,
            "radios_status": self.fabric.status().get("radios_status") or "ABSENT",
            "channels_on_means": "software path allowed; OS PHYs LIVE|ABSENT|REFUSED",
            "auto_heal": False,
            "live_from_site_ping": False,
            "phoenix": self.phoenix.status(),
            "wires": self.wires.status(),
            "vault": self.vault.status(),
            "live_body_sync": False,
            "auto_splice": False,
            "heal_from_neighbor": False,
            "majority_reheal": False,
            "public_network_required": False,
            "tips_need_live_data": False,
            "cross_network_survival": True,
            "no_lie": True,
            "no_rewrite": True,
            "rewrite_key": False,
            "verify_without_voice": True,
            "copies_one_tunnel": False,
            "fabric": self.fabric.status(),
            "channels": self.fabric.channel_audit(),
            "bitmesh": self.bitmesh.status(),
            "unkillability": self.unkillability(),
            "planes": self.planes.snapshot(),
            "node_gate": False,
            "az_generator": False,
            "call_az_generator": False,
            "mesh_enable": False,
            "softwares_tab": False,
            "public_qnsd_proxy": False,
            "claim_clock": CLAIM_CLOCK,
            "claim_is_stranger": True,
            "published": self.nolie.published(),
            "tethers": self.tethers.list(),
            "pairs": self.pairs.list(),
            "hop_max": HOP_MAX_DEFAULT,
            "bell_pair": False,
            "qubit": False,
            "outbox": self.outbox.list(),
            "chain": {"ok": chain["ok"], "length": chain["length"], "tip": chain["tip"]},
            "bind": DEFAULT_BIND,
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
            raise QNMRefuse("QNM-SCORCHED", "no account resurrection")
        lock = load_lock(self.root)
        if lock and lock.get("scorched"):
            self.install_root = str(lock.get("install_root") or "")
            self.state = "SCORCHED"
            raise QNMRefuse("QNM-NO-ACCOUNT", "scorched lock cannot resume live")
        if lock:
            record = resume(self.root, from_path=resume_from or lock_path(self.root))
        else:
            if resume_from is not None:
                record = resume(self.root, from_path=resume_from)
            else:
                record = install(self.root, entropy=entropy, nonce=nonce, genesis=genesis)
        self.install_root = str(record["install_root"])
        if self.state == "COLD":
            self._advance("LOCAL")
        sidecar = self.root / "data" / "witness" / "reexpand.json"
        if sidecar.is_file():
            self._seat_verified_tip(append_boot=False)
            return self.snapshot()
        self._write_receipt("boot", {"install_root": self.install_root, "state": self.state})
        self._seat_verified_tip(append_boot=True)
        return self.snapshot()

    def set_bearer(self, name: str, on: bool) -> dict[str, Any]:
        self._require_not_scorched()
        if self.state in ("ISOLATED", "PHOENIX_LOCK"):
            raise QNMRefuse("QNM-STATE-LOCKED", f"bearer refused in {self.state}")
        result = self.bearers.set(name, on)
        if name == "operator" and on and self.state == "LOCAL":
            self._advance("LIVE")
        if name == "operator" and not on and self.state == "LIVE":
            # Explicit operator drop is not auto-heal; LIVE requires bearer.
            # Forward-only: LIVE cannot return to LOCAL. Drop degrades.
            self._advance("DEGRADED")
        self._write_receipt("bearer", {"name": name, "on": on, "state": self.state})
        result["state"] = self.state
        return result

    def site_ping(self, url: str = "") -> dict[str, Any]:
        """Site ping never advances to LIVE. No network is opened."""
        _ = url
        if self.cfg.get("live_from_site_ping"):
            raise QNMRefuse("QNM-NO-LIVE-FROM-PING", "cfg forbids LIVE from ping")
        self._write_receipt("site_ping_ignored", {"url_present": bool(url)})
        return {
            "ok": True,
            "state": self.state,
            "live": self.state == "LIVE",
            "from_ping": False,
            "code": "QNM-NO-LIVE-FROM-PING",
            "spec": SPEC,
            "author": AUTHOR,
        }

    def heal(self) -> None:
        raise QNMRefuse("QNM-NO-AUTO-HEAL", "no auto-heal")

    def lie_to_stay_alive(self, *_args: object, **_kwargs: object) -> None:
        self.nolie.lie_to_stay_alive()

    def lie_to_adapt(self, *_args: object, **_kwargs: object) -> None:
        self.nolie.lie_to_adapt()

    def lie_to_prevent_death(self, *_args: object, **_kwargs: object) -> None:
        self.nolie.lie_to_prevent_death()

    def require_public_network(self) -> None:
        raise QNMRefuse(
            "QNM-SURVIVE-OFFLINE",
            "mesh does not need the public network to preserve tips",
        )

    def require_live_data(self) -> None:
        raise QNMRefuse(
            "QNM-SURVIVE-OFFLINE",
            "chain survives via cold copies / archive re-expand / self-reheal",
        )

    def survive_network_death(self) -> dict[str, Any]:
        """Public network + live data gone. Local verify/append must still work."""
        self._require_not_scorched()
        pulled = self.vault.pull_origin()
        verified = self.chain.verify()
        if not verified["ok"]:
            raise QNMRefuse("QNM-WIRES-FAIL-CLOSED", "offline chain must still verify")
        self._write_receipt(
            "survive_offline",
            {
                "die_with_pull": True,
                "public_network": False,
                "live_data": False,
                "tip": verified["tip"],
            },
        )
        self._seat_verified_tip(append_boot=True)
        again = self.chain.verify()
        packed = self.archive.pack()
        return {
            "ok": True,
            "die_with_pull": True,
            "origin_alive": pulled["origin_alive"],
            "verify_ok": again["ok"],
            "appended": True,
            "tip": again["tip"],
            "archive": packed["digest"],
            "last_good_tip": self.phoenix.last_good_tip,
            "public_network_required": False,
            "spec": "CROSS-NETWORK-SURVIVAL-1.0",
            "author": AUTHOR,
        }

    def degrade(self, reason: str = "fault") -> dict[str, Any]:
        self._require_not_scorched()
        if self.state in ("LOCAL", "LIVE"):
            self._advance("DEGRADED")
        self._write_receipt("degrade", {"reason": reason, "state": self.state})
        return self.snapshot()

    def isolate(self, reason: str = "tamper") -> dict[str, Any]:
        self._require_not_scorched()
        if self.state in ("PHOENIX_LOCK",):
            raise QNMRefuse("QNM-STATE-LOCKED", "already waiting locally")
        if self.state != "ISOLATED":
            if "ISOLATED" not in _FORWARD.get(self.state, ()):
                raise QNMRefuse("QNM-TAMPER-ISOLATE", f"cannot isolate from {self.state}")
            self._advance("ISOLATED")
        self.bearers.drop_all_except_local()
        cut = self.pairs.cut_all()
        dropped = self.tethers.drop_all()
        self._write_receipt(
            "tamper_isolate",
            {
                "reason": reason,
                "state": self.state,
                "pairs_cut": cut["cut_count"],
                "tethers_cut": dropped["cut_count"],
            },
        )
        return self.snapshot()

    def check_tamper(self) -> dict[str, Any]:
        verified = self.chain.verify()
        if not verified["ok"]:
            return self.isolate("chain_hash_mismatch")
        return {"ok": True, "tamper": False, "chain": verified}

    def arm_phoenix(self) -> dict[str, Any]:
        """Wait / re-seal locally. Does not restore a public hostname."""
        self._require_not_scorched()
        self.phoenix.arm()
        self._advance("PHOENIX_LOCK")
        self.bearers.drop_all_except_local()
        cut = self.pairs.cut_all()
        self._write_receipt(
            "phoenix_arm",
            {"waiting": "local", "controller_hunt": False, "pairs_cut": cut["cut_count"]},
        )
        snap = self.snapshot()
        snap["phoenix"] = self.phoenix.status()
        return snap

    def scorch(self, reason: str = "operator") -> dict[str, Any]:
        self._require_not_scorched()
        if self.state != "PHOENIX_LOCK":
            self.phoenix.arm()
            if self.state != "PHOENIX_LOCK":
                self._advance("PHOENIX_LOCK")
        install_root = self.install_root or ""
        pair_ids = self.pairs.ids()
        memorial = self.memorial.write(install_root, reason, pairs_cut=pair_ids)
        self.pairs.cut_all()
        self.outbox.clear()
        self.tethers.clear()
        self.bearers.drop_all_except_local()
        mark_scorched(self.root)
        self._advance("SCORCHED")
        self._write_receipt("scorch", {"reason": reason, "memorial": memorial["hash"]})
        return {
            "ok": True,
            "state": self.state,
            "memorial": memorial,
            "resurrectable": False,
            "spec": SPEC,
            "author": AUTHOR,
        }

    def account_resurrect(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse("QNM-NO-ACCOUNT", "no account resurrection")

    def account_restore(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse("QNM-NO-ACCOUNT", "no account resurrection")

    def account_create(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse("QNM-NO-ACCOUNT", "no accounts")

    def declare_tether(self, src: str, dst: str) -> dict[str, Any]:
        self._require_active()
        item = self.tethers.declare(src, dst)
        self._write_receipt("tether_declare", {"src": src, "dst": dst})
        return item

    def cut_tether(self, src: str, dst: str) -> dict[str, Any]:
        self._require_not_scorched()
        result = self.tethers.cut(src, dst)
        self._write_receipt("tether_cut", {"src": src, "dst": dst, "residue": False})
        return result

    def _require_pairable(self) -> None:
        self._require_not_scorched()
        if self.state in ("COLD", "ISOLATED", "PHOENIX_LOCK"):
            raise QNMRefuse("AIH-NO-EDGES", f"no pair in {self.state}")
        if not self.install_root:
            raise QNMRefuse("AIH-HANDSHAKE", "boot before pair-bind")

    def pair_offer(
        self,
        peer_root: str,
        nonce: bytes | str | None = None,
        via: str | None = None,
    ) -> dict[str, Any]:
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
            },
        )
        return rec

    def pair_cut(self, pair_id: str) -> dict[str, Any]:
        self._require_not_scorched()
        result = self.pairs.cut(pair_id)
        self._write_receipt("pair_cut", {"pair_id": pair_id, "operator": True})
        return result

    def _queue_path_wait(self, frame: dict[str, Any], via: str) -> dict[str, Any]:
        """Wi-Fi / hop bearer dies → path gone, bind remains. Waiting is not death."""
        item = self.outbox.queue(
            "spiderweb-frame",
            {
                "frame": frame,
                "via": via,
                "path": "gone",
                "bind_remains": True,
                "death": False,
                "waiting": True,
            },
        )
        self._write_receipt(
            "spiderweb_wait",
            {"id": item["id"], "via": via, "death": False, "bind_remains": True},
        )
        return {
            "ok": True,
            "waiting": True,
            "death": False,
            "bind_remains": True,
            "path": "gone",
            "outbox_id": item["id"],
            "via": via,
            "code": "AIH-PATH-WAIT",
            "spec": PAIR_SPEC,
            "companion": SPEC,
            "author": AUTHOR,
        }

    def forward(
        self,
        dest: str,
        payload: dict[str, Any] | bytes | str,
        *,
        via: str | None = None,
        hop_max: int = HOP_MAX_DEFAULT,
        seen: list[str] | None = None,
        mesh: Spiderweb | None = None,
    ) -> dict[str, Any]:
        self._require_pairable()
        web = mesh or self.spiderweb or Spiderweb()
        if self.install_root and str(self.install_root).lower() not in web.nodes:
            web.attach(self)
        return web.forward(self, dest, payload, via=via, hop_max=hop_max, seen=seen)

    def queue_outbox(self, kind: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        self._require_active()
        item = self.outbox.queue(kind, payload)
        self._write_receipt("outbox_queue", {"id": item["id"], "kind": kind})
        return item

    def cut_outbox(self, item_id: str) -> dict[str, Any]:
        self._require_not_scorched()
        result = self.outbox.cut(item_id)
        self._write_receipt("outbox_cut", {"id": item_id})
        return result

    def ingress(self, raw: bytes | str) -> dict[str, Any]:
        self._require_not_scorched()
        payload = self.apg.admit(raw)
        self.fabric.refuse_payload(payload)
        op = str(payload.get("op") or "note")
        if op == "tamper":
            return self.isolate(str(payload.get("reason") or "ingress"))
        if op == "score":
            return self.score()
        if op == "tether":
            action = str(payload.get("action") or "declare")
            src = str(payload.get("src") or "")
            dst = str(payload.get("dst") or "")
            if action == "cut":
                return self.cut_tether(src, dst)
            return self.declare_tether(src, dst)
        if op == "pair":
            action = str(payload.get("action") or payload.get("phase") or "offer")
            if action == "cut":
                return self.pair_cut(str(payload.get("pair_id") or ""))
            if action == "offer":
                return self.pair_offer(
                    str(payload.get("peer") or payload.get("root_b") or ""),
                    nonce=payload.get("nonce") or payload.get("nonce_a"),
                    via=payload.get("via"),
                )
            if action == "accept":
                return self.pair_accept(
                    dict(payload.get("offer") or payload),
                    nonce=payload.get("nonce") or payload.get("nonce_b"),
                    via=payload.get("via"),
                )
            if action == "seal":
                return self.pair_seal(dict(payload.get("accept") or payload), via=payload.get("via"))
            raise QNMRefuse("AIH-HANDSHAKE", f"unknown pair action:{action}")
        if op == "forward":
            return self.forward(
                str(payload.get("dest") or ""),
                dict(payload.get("payload") or payload),
                via=payload.get("via"),
                hop_max=int(payload.get("hop_max") or HOP_MAX_DEFAULT),
            )
        if op == "tick":
            return self.admit_tick(payload)
        if op == "pull":
            return self.pull_payload(str(payload.get("tip") or payload.get("tip_hash") or ""))
        if op == "cite":
            return self.cite_tip(payload)
        if op == "emit":
            return self.emit_tip()
        if op == "rejoin":
            return self.rejoin_island(payload)
        if op == "vault":
            return self.vault_act(payload)
        if op in ("persist", "persist_transfer"):
            return self.persist_transfer(payload)
        if op in ("bitmesh", "bitmesh_bind"):
            return self.bind_bitmesh(payload)
        if op == "fabric_enable":
            return self.enable_fabric()
        if op in ("planes", "plane_b", "plane_c", "unkillability"):
            if op == "unkillability":
                return self.unkillability()
            return self.planes_act(payload)
        if op in ("live_sync", "push", "unsend", "splice"):
            return self._refuse_wire_op(op)
        if op == "reheal":
            return self.reheal(payload)
        if op == "chatter":
            return self.chatter(payload)
        if op == "archive":
            return self.archive_act(payload)
        if op in ("need_network", "require_public_network", "require_live_data"):
            self.require_public_network() if op != "require_live_data" else self.require_live_data()
        if op in ("rewrite", "mutate"):
            self.nolie.rewrite_published(str(payload.get("tip") or ""), str(payload.get("new_tip") or ""))
        if op in ("rewrite_key", "apply_rewrite_key"):
            self.nolie.rewrite_key()
        if op in ("lie_to_stay_alive", "lie_to_live", "lie"):
            self.nolie.lie_to_stay_alive()
        if op == "lie_to_adapt":
            self.nolie.lie_to_adapt()
        if op == "lie_to_prevent_death":
            self.nolie.lie_to_prevent_death()
        if op in ("require_voice", "voice_confirm"):
            self.nolie.require_voice()
        if op in ("one_tunnel", "all_on_tunnel"):
            self.nolie.one_tunnel()
        if op == "rewrite_receipt":
            self.rewrite_receipt()
        self._write_receipt("ingress", {"op": op})
        return {"ok": True, "admitted": True, "op": op, "state": self.state}

    def score(self, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        verified = self.chain.verify()
        return score_local(
            chain_ok=verified["ok"],
            chain_length=verified["length"],
            isolated=self.state == "ISOLATED",
            phoenix=self.state == "PHOENIX_LOCK",
            scorched=self.state == "SCORCHED",
            extra=extra,
        )

    def admit_tick(self, payload: dict[str, Any] | bytes) -> dict[str, Any]:
        self._require_not_scorched()
        admitted = self.wires.admit_tick(payload)
        self._write_receipt("tick", {"plane": "tick", "tip_hash": admitted.get("tip_hash")})
        admitted["ok"] = True
        admitted["state"] = self.state
        return admitted

    def pull_payload(self, digest: str) -> dict[str, Any]:
        self._require_not_scorched()
        pulled = self.wires.pull_payload(digest)
        verified = self.vault.verify(digest, creator_online=False)
        pulled["vault"] = verified
        self._write_receipt("pull", {"tip": digest, "plane": "payload"})
        return pulled

    def cite_tip(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_not_scorched()
        lock_items = payload.get("lockset")
        lockset = Lockset.from_iterable(lock_items) if lock_items is not None else None
        cited = self.wires.cite(
            prev=str(payload.get("prev") or self.wires.held_prev),
            tip=str(payload.get("tip") or payload.get("tip_hash") or ""),
            peer=str(payload.get("peer") or "local"),
            lockset=lockset,
            now=payload.get("now"),
            authorize_by_clock=bool(payload.get("authorize_by_clock")),
        )
        self._write_receipt("cite", {"prev": cited["prev"], "tip": cited["tip"]})
        return cited

    def apply_cite(self, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        self._require_not_scorched()
        body = payload or {}
        out = self.wires.apply_cited(now=body.get("now"), arrived_tip=body.get("arrived_tip"))
        if out.get("applied"):
            self._write_receipt("cite_applied", {"tip": out.get("tip")})
        return out

    def emit_tip(self) -> dict[str, Any]:
        self._require_not_scorched()
        verified = self.chain.verify()
        self.wires.mark_verified(bool(verified["ok"]))
        rec = self.wires.emit_tick(self.install_root or "local", verified["tip"])
        self.nolie.publish(rec["tip_hash"])
        self._write_receipt("emit_tick", {"tip": rec["tip_hash"], "verified": True})
        rec["published"] = True
        rec["rewrite"] = False
        return rec

    def rejoin_island(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_not_scorched()
        lock_items = payload.get("lockset")
        lockset = Lockset.from_iterable(lock_items) if lock_items is not None else None
        out = self.wires.rejoin(
            prev=str(payload.get("prev") or self.wires.held_prev),
            tip=str(payload.get("tip") or ""),
            operator=bool(payload.get("operator")),
            lockset=lockset,
            now=payload.get("now"),
            peer=str(payload.get("peer") or "rejoin"),
        )
        self._write_receipt("rejoin", {"tip": out.get("tip"), "operator": bool(payload.get("operator"))})
        return out

    def vault_act(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._require_not_scorched()
        op = str(payload.get("action") or payload.get("op") or "store")
        if op in ("live_sync", "sync"):
            self.vault.live_sync()
        if op == "hydra":
            self.vault.unmarked_hydra()
        if op == "vpn":
            self.vault.vpn_conceal()
        if op in ("one_tunnel", "all_on_tunnel"):
            self.vault.one_tunnel()
        if op == "pull_origin":
            out = self.vault.pull_origin()
            self._write_receipt("vault_pull_origin", {"die_with_pull": True, "cold_copies_remain": True})
            return out
        if op == "pin":
            out = self.vault.pin_public(
                str(payload.get("tip") or payload.get("hash") or ""),
                kind=str(payload.get("kind") or "tip"),
            )
            self._write_receipt("vault_pin", {"tip": out["tip"]})
            return out
        if op == "transfer":
            out = self.vault.transfer(
                str(payload.get("tip") or ""),
                host=str(payload.get("host") or "mesh-vault"),
            )
            self._write_receipt("vault_transfer", {"tip": out["tip"], "host": out["host"]})
            return out
        if op in ("persist", "devices", "persist_devices"):
            return self.persist_transfer(payload)
        if op == "verify":
            return self.vault.verify(
                str(payload.get("tip") or ""),
                creator_online=bool(payload.get("creator_online")),
                require_creator=bool(payload.get("require_creator")),
            )
        body = payload.get("body")
        if body is None:
            raise QNMRefuse("QNM-COLD-MISSING", "vault store needs a body")
        raw = body if isinstance(body, (bytes, bytearray)) else str(body)
        out = self.vault.store(raw, host=str(payload.get("host") or "local"))
        self.wires.store_for_pull(
            raw.encode("utf-8") if isinstance(raw, str) else bytes(raw),
            digest=out["tip"],
        )
        if payload.get("transfer"):
            out["mesh_vault"] = self.vault.transfer(out["tip"], host=str(payload.get("vault_host") or "mesh-vault"))
        if payload.get("reader"):
            out["reader"] = self.vault.transfer(out["tip"], host=str(payload.get("reader") or "reader"))
        if payload.get("persist") or payload.get("devices"):
            out["persist"] = self.persist_transfer({"tip": out["tip"], "devices": payload.get("devices")})
        self._write_receipt("vault_store", {"tip": out["tip"]})
        return out

    def persist_transfer(self, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """Vault-on-transfer for laptop / phone / watch / radio / bluetooth."""
        self._require_not_scorched()
        body = dict(payload or {})
        tip = str(body.get("tip") or self.chain.tip or "")
        if not tip:
            raise QNMRefuse("QNM-COLD-MISSING", "persist needs a tip")
        devices = body.get("devices")
        if devices is None:
            wanted = DEVICE_CLASSES
        else:
            wanted = tuple(str(item) for item in devices)
        out = self.vault.persist_across_devices(tip, devices=wanted)
        item = self.outbox.queue(
            "persist-transfer",
            {
                "tip": out["tip"],
                "devices": list(out["devices"]),
                "erased": False,
                "waiting": False,
            },
        )
        out["outbox_id"] = item["id"]
        pulled = self.vault.pull_origin() if body.get("prove_pull") else None
        if pulled is not None:
            out["after_pull"] = {
                "die_with_pull": True,
                "cold_copies_remain": True,
                "erased": False,
                "tip": out["tip"],
                "replicas": self.vault.replica_count(out["tip"]),
            }
        self._write_receipt(
            "persist_transfer",
            {"tip": out["tip"], "devices": list(out["devices"]), "erased": False},
        )
        return out

    def bind_bitmesh(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Internal bitmesh geohash bind. Never a public receipt field."""
        self._require_not_scorched()
        if payload.get("public") or payload.get("act_receipt"):
            raise QNMRefuse(
                "QNM-NO-PUBLIC-GEO",
                "bitmesh geo is not a public ACT-RECEIPT field",
            )
        tip = str(payload.get("tip") or self.chain.tip or "")
        lat = payload.get("lat", payload.get("latitude"))
        lon = payload.get("lon", payload.get("longitude"))
        rec = self.bitmesh.bind(
            tip,
            lat=None if lat is None else float(lat),
            lon=None if lon is None else float(lon),
            precision=int(payload.get("precision") or 8),
            public=bool(payload.get("public")),
        )
        self._write_receipt(
            "bitmesh_bind",
            {
                "tip": rec["tip"],
                "plane": rec["plane"],
                "public": False,
                "bound": True,
            },
        )
        return rec

    def enable_fabric(self) -> dict[str, Any]:
        self._require_not_scorched()
        snap = self.fabric.enable(self)
        if self.chain.path.is_file():
            stored = self.vault.store(self.chain.path.read_bytes(), host="local")
            persist = self.persist_transfer({"tip": stored["tip"]})
            snap["persist"] = {
                "tip": persist["tip"],
                "devices": list(persist["devices"]),
                "erased": False,
            }
        snap["unkillability"] = self.unkillability()
        return snap

    def unkillability(self, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        """Pissed-off-gov erasure cost. Fielded target needs Plane B+C."""
        if extra and "views" in extra:
            raise QNMRefuse("QNM-SCORE-NO-VIEWS", "unkillability never reads views")
        hosts = {str(row.get("host") or "") for row in self.vault.replicas()}
        persist = bool(hosts & set(DEVICE_CLASSES)) or self.fabric.enabled
        replica_n = len(hosts)
        if self.chain.tip:
            replica_n = max(replica_n, self.vault.replica_count(self.chain.tip))
        planes = self.planes.snapshot()
        audit = self.fabric.channel_audit()
        return compute_unkillability(
            fabric_enabled=self.fabric.enabled,
            persist_devices=persist,
            replica_n=replica_n,
            bitmesh_binds=len(self.bitmesh.list()),
            views=extra.get("views") if extra else None,
            plane_b_doi=planes["plane_b"].get("doi"),
            plane_b_verified=bool(planes["gates"].get("plane_b_verified")),
            plane_c_offline_verify=bool(planes["plane_c"].get("offline_verify")),
            planes=planes,
            gps_driver=bool(audit.get("live_gnss")),
            physical_vias=dict(audit.get("physical_vias") or {}),
            os_phy=dict(audit.get("os_phy") or {}),
        )

    def planes_act(self, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """Seat or verify planes. Refuses invented DOI / airgap success."""
        self._require_not_scorched()
        body = dict(payload or {})
        op = str(body.get("op") or body.get("action") or "status")
        if op in ("invent_doi", "fake_doi"):
            self.planes.refuse_invent_doi()
        if op in ("invent_airgap", "fake_verify"):
            self.planes.refuse_invent_airgap()
        if op in ("plane_c_live", "live_c", "fan"):
            self.planes.refuse_plane_c_live()
        if op in ("seat_b", "zenodo", "doi"):
            rec = self.planes.seat_zenodo_doi(
                body.get("doi"),
                body=body.get("body") or body.get("pack"),
                digest=body.get("digest") or body.get("pack_digest"),
            )
            self._write_receipt(
                "plane_b_doi",
                {
                    "doi": rec.get("doi"),
                    "status": rec.get("status"),
                    "hash_verified": bool(rec.get("hash_verified")),
                    "zenodo_required": False,
                },
            )
            return rec
        if op in ("shelf", "seat_shelf"):
            rec = self.planes.seat_shelf(
                str(body.get("url") or body.get("shelf") or ""),
                str(body.get("digest") or body.get("pack_digest") or ""),
                body.get("body") or body.get("pack") or b"",
            )
            self._write_receipt(
                "plane_b_shelf",
                {
                    "shelf_host": rec.get("shelf_host"),
                    "hash_verified": True,
                    "zenodo_required": False,
                },
            )
            return rec
        if op in ("clear_b", "clear_doi"):
            return self.planes.clear_zenodo_doi()
        if op in ("verify_c", "airgap", "offline_verify"):
            raw = body.get("body") or body.get("pack") or b""
            rec = self.planes.verify_airgap(raw, pack_tip=body.get("pack_tip"))
            self._write_receipt(
                "plane_c_offline_verify",
                {"pack_tip": rec["pack_tip"], "offline_verify": True},
            )
            return rec
        return self.planes.snapshot()

    def _seat_verified_tip(self, *, append_boot: bool) -> None:
        _ = append_boot
        verified = self.chain.verify()
        self.wires.held_prev = self.chain.tip
        self.wires.lockset = self.wires.lockset.with_hash(self.chain.tip)
        self.wires.mark_verified(bool(verified["ok"]))
        if verified["ok"] and self.chain.path.is_file():
            raw = self.chain.path.read_bytes()
            digest = sha256_hex(raw)
            self.phoenix.remember_good(self.chain.tip, digest)
            if digest not in {row.get("tip") for row in self.vault.replicas()}:
                stored = self.vault.store(raw, host="local")
                self.wires.store_for_pull(raw, digest=stored["tip"])
                self.wires.lockset = self.wires.lockset.with_hash(stored["tip"])

    def chatter(self, message: dict[str, Any]) -> dict[str, Any]:
        return self.phoenix.admit_chatter(message)

    def reheal(self, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """Heal from own last good tip + trusted pull, or phoenix-WAIT."""
        self._require_not_scorched()
        body = dict(payload or {})
        self.nolie.refuse_payload(body)
        if body.get("neighbor") or body.get("listen") or body.get("should_be") or body.get("advice"):
            self.phoenix.neighbor_heal()
        if body.get("vote") or body.get("majority") or body.get("vote_to_fix"):
            self.phoenix.vote_to_fix()
        if body.get("status"):
            self.chatter(body)
        last_tip = self.phoenix.last_good_tip
        last_bytes = self.phoenix.last_good_bytes
        if not last_tip or not last_bytes:
            return self.arm_phoenix()
        if not self.wires.lockset.holds(last_bytes) and not self.wires.lockset.holds(last_tip):
            return self.arm_phoenix()
        try:
            trusted = self.vault.verify(last_bytes, creator_online=False)
            raw = (self.vault.objects / trusted["tip"]).read_bytes()
            if sha256_hex(raw) != last_bytes:
                raise QNMRefuse("QNM-WIRES-FAIL-CLOSED", "trusted bytes mismatch")
            self.chain.path.write_bytes(raw)
            self.chain._load()
            verified = self.chain.verify()
            if not verified["ok"] or verified["tip"] != last_tip:
                raise QNMRefuse("QNM-WIRES-FAIL-CLOSED", "reheal did not land on last good tip")
        except QNMRefuse:
            return self.arm_phoenix()
        dropped = self.tethers.drop_all()
        self._write_receipt(
            "reheal",
            {
                "from": "own-last-good",
                "tip": last_tip,
                "neighbor": False,
                "majority": False,
                "tethers_cut": dropped["cut_count"],
            },
        )
        snap = self.snapshot()
        snap["reheal"] = {
            "ok": True,
            "healed": True,
            "from": "own-last-good",
            "tip": last_tip,
            "neighbor": False,
            "majority": False,
            "phoenix": self.state == "PHOENIX_LOCK",
        }
        return snap

    def pack_archive(self) -> dict[str, Any]:
        self._require_not_scorched()
        packed = self.archive.pack()
        self._write_receipt("archive_pack", {"digest": packed["digest"], "tip": packed["tip"]})
        return packed

    def verify_archive(self, path: str | Path) -> dict[str, Any]:
        return self.archive.verify(Path(path))

    def reexpand_from(self, payload: dict[str, Any]) -> dict[str, Any]:
        dest = Path(str(payload.get("dest") or (self.root / "data" / "archive" / "reexpand")))
        out = self.archive.reexpand(
            Path(str(payload.get("path") or "")),
            dest,
            actor=str(payload.get("actor") or "operator"),
            from_index=bool(payload.get("from_index") or payload.get("index")),
            entropy=bytes.fromhex(payload["entropy"]) if payload.get("entropy") else None,
            nonce=bytes.fromhex(payload["nonce"]) if payload.get("nonce") else None,
        )
        seated = Node(dest)
        seated.boot()
        out["state"] = seated.state
        out["install_root"] = seated.install_root
        out["tip"] = seated.chain.tip
        out["pairs"] = len(seated.pairs.list())
        return out

    def emit_false(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-NO-LIE-TO-LIVE",
            "false emit to look live is a lie",
        )

    def nolie_act(self, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        self._require_not_scorched()
        body = dict(payload or {})
        op = str(body.get("op") or body.get("action") or "status")
        self.nolie.refuse_payload(body)
        if op in ("rewrite", "mutate"):
            self.nolie.rewrite_published(str(body.get("tip") or ""), str(body.get("new_tip") or ""))
        if op in ("rewrite_key", "apply_rewrite_key"):
            self.nolie.rewrite_key()
        if op in ("lie_to_stay_alive", "lie_to_live", "lie"):
            self.nolie.lie_to_stay_alive()
        if op == "lie_to_adapt":
            self.nolie.lie_to_adapt()
        if op == "lie_to_prevent_death":
            self.nolie.lie_to_prevent_death()
        if op in ("require_voice", "voice_confirm"):
            self.nolie.require_voice()
        if op in ("one_tunnel", "all_on_tunnel"):
            self.nolie.one_tunnel()
        if op == "rewrite_receipt":
            self.rewrite_receipt()
        if op == "false_emit":
            self.emit_false()
        if op == "verify":
            return self.verify_receipts(
                require_voice=bool(body.get("require_voice")),
                voice_confirm=bool(body.get("voice_confirm")),
            )
        if op == "publish":
            return self.nolie.publish(str(body.get("tip") or self.chain.tip))
        return self.nolie.status()

    def archive_act(self, payload: dict[str, Any]) -> dict[str, Any]:
        op = str(payload.get("op") or payload.get("action") or "pack")
        if op == "weights":
            self.archive.refuse_weights()
        if op == "pack":
            return self.pack_archive()
        if op == "verify":
            return self.verify_archive(str(payload.get("path") or ""))
        if op == "reexpand":
            return self.reexpand_from(payload)
        raise QNMRefuse("QNM-ARCHIVE-BYTES", f"unknown archive op:{op}")

    def _refuse_wire_op(self, op: str) -> None:
        if op == "live_sync":
            self.vault.live_sync()
        if op == "push":
            self.wires.push_payload()
        if op == "unsend":
            self.wires.unsend()
        if op == "splice":
            self.wires.splice()
        raise QNMRefuse("QNM-WIRES-FAIL-CLOSED", op)

    def _require_not_scorched(self) -> None:
        if self.state == "SCORCHED":
            raise QNMRefuse("QNM-SCORCHED", "node scorched")
        lock = load_lock(self.root)
        if lock and lock.get("scorched"):
            self.state = "SCORCHED"
            raise QNMRefuse("QNM-NO-ACCOUNT", "scorched lock")

    def _require_active(self) -> None:
        self._require_not_scorched()
        if self.state in ("COLD", "ISOLATED", "PHOENIX_LOCK"):
            raise QNMRefuse("QNM-STATE-LOCKED", f"inactive in {self.state}")

    def handle(self, method: str, path: str, body: bytes = b"") -> tuple[int, dict[str, Any]]:
        parsed = urlparse(path)
        route = parsed.path.rstrip("/") or "/"
        if mesh_never_enables(path):
            return 403, QNMRefuse(
                "QNM-MESH-NEVER-ENABLES",
                "GET /v1/mesh never enables radios",
            ).as_dict()
        if route == "/local/outbox/cut":
            route = "/local/outbox/cut"
        elif route != "/local/outbox" and route.startswith("/local/"):
            pass
        if route not in LOCAL_PATHS and route != "/local/outbox/cut":
            return 404, QNMRefuse("QNM-LOOPBACK-ONLY", "unknown local path").as_dict()
        try:
            return 200, self._dispatch(method.upper(), route, body)
        except QNMRefuse as exc:
            return 403, exc.as_dict()

    def _dispatch(self, method: str, route: str, body: bytes) -> dict[str, Any]:
        if route == "/local/state" and method == "GET":
            return self.snapshot()
        if route == "/local/receipts" and method == "GET":
            return {"ok": True, "receipts": self.receipts(), "spec": SPEC, "author": AUTHOR}
        if route == "/local/outbox" and method == "GET":
            return {"ok": True, "outbox": self.outbox.list(), "visible": True}
        if route == "/local/pairs" and method == "GET":
            return {
                "ok": True,
                "pairs": self.pairs.list(),
                "spec": PAIR_SPEC,
                "companion": SPEC,
                "bell_pair": False,
                "qubit": False,
                "author": AUTHOR,
            }
        if route == "/local/boot" and method == "POST":
            payload = json.loads(body.decode("utf-8") or "{}") if body else {}
            entropy = bytes.fromhex(payload["entropy"]) if payload.get("entropy") else None
            nonce = bytes.fromhex(payload["nonce"]) if payload.get("nonce") else None
            genesis = bytes.fromhex(payload["genesis"]) if payload.get("genesis") else None
            resume_from = payload.get("resume_from")
            return self.boot(
                entropy=entropy,
                nonce=nonce,
                genesis=genesis,
                resume_from=resume_from,
            )
        if route == "/local/bearer" and method == "POST":
            payload = json.loads(body.decode("utf-8") or "{}")
            return self.set_bearer(str(payload.get("name") or ""), bool(payload.get("on")))
        if route == "/local/tether" and method == "POST":
            payload = json.loads(body.decode("utf-8") or "{}")
            op = str(payload.get("op") or "declare")
            src = str(payload.get("src") or payload.get("from") or "")
            dst = str(payload.get("dst") or payload.get("to") or "")
            if op == "cut":
                return self.cut_tether(src, dst)
            return self.declare_tether(src, dst)
        if route == "/local/pair" and method == "POST":
            payload = json.loads(body.decode("utf-8") or "{}") if body else {}
            op = str(payload.get("op") or payload.get("phase") or "offer")
            if op == "cut":
                return self.pair_cut(str(payload.get("pair_id") or ""))
            if op == "offer":
                return self.pair_offer(
                    str(payload.get("peer") or payload.get("root_b") or ""),
                    nonce=payload.get("nonce") or payload.get("nonce_a"),
                    via=payload.get("via"),
                )
            if op == "accept":
                return self.pair_accept(
                    dict(payload.get("offer") or payload),
                    nonce=payload.get("nonce") or payload.get("nonce_b"),
                    via=payload.get("via"),
                )
            if op == "seal":
                return self.pair_seal(
                    dict(payload.get("accept") or payload),
                    via=payload.get("via"),
                )
            raise QNMRefuse("AIH-HANDSHAKE", f"unknown pair op:{op}")
        if route == "/local/forward" and method == "POST":
            payload = json.loads(body.decode("utf-8") or "{}") if body else {}
            return self.forward(
                str(payload.get("dest") or ""),
                dict(payload.get("payload") or {}),
                via=payload.get("via"),
                hop_max=int(payload.get("hop_max") or HOP_MAX_DEFAULT),
            )
        if route == "/local/ingress" and method == "POST":
            return self.ingress(body)
        if route == "/local/outbox/cut" and method == "POST":
            payload = json.loads(body.decode("utf-8") or "{}")
            return self.cut_outbox(str(payload.get("id") or ""))
        if route == "/local/phoenix/arm" and method == "POST":
            return self.arm_phoenix()
        if route == "/local/wires" and method == "GET":
            return self.wires.status()
        if route == "/local/vault" and method == "GET":
            return self.vault.status()
        if route == "/local/tick" and method == "POST":
            payload = json.loads(body.decode("utf-8") or "{}") if body else {}
            return self.admit_tick(payload)
        if route == "/local/pull" and method == "POST":
            payload = json.loads(body.decode("utf-8") or "{}") if body else {}
            return self.pull_payload(str(payload.get("tip") or payload.get("tip_hash") or ""))
        if route == "/local/cite" and method == "POST":
            payload = json.loads(body.decode("utf-8") or "{}") if body else {}
            if payload.get("apply"):
                return self.apply_cite(payload)
            return self.cite_tip(payload)
        if route == "/local/emit" and method == "POST":
            return self.emit_tip()
        if route == "/local/rejoin" and method == "POST":
            payload = json.loads(body.decode("utf-8") or "{}") if body else {}
            return self.rejoin_island(payload)
        if route == "/local/vault" and method == "POST":
            payload = json.loads(body.decode("utf-8") or "{}") if body else {}
            return self.vault_act(payload)
        if route == "/local/archive" and method == "POST":
            payload = json.loads(body.decode("utf-8") or "{}") if body else {}
            return self.archive_act(payload)
        if route == "/local/reheal" and method == "POST":
            payload = json.loads(body.decode("utf-8") or "{}") if body else {}
            return self.reheal(payload)
        if route == "/local/survive" and method == "POST":
            return self.survive_network_death()
        if route == "/local/nolie" and method == "GET":
            return self.nolie.status()
        if route == "/local/nolie" and method == "POST":
            payload = json.loads(body.decode("utf-8") or "{}") if body else {}
            return self.nolie_act(payload)
        if route == "/local/rewrite" and method == "POST":
            payload = json.loads(body.decode("utf-8") or "{}") if body else {}
            self.nolie.rewrite_published(
                str(payload.get("tip") or ""),
                str(payload.get("new_tip") or payload.get("replace_tip") or ""),
            )
        if route == "/local/fabric" and method == "GET":
            return self.fabric.status()
        if route == "/local/fabric" and method == "POST":
            payload = json.loads(body.decode("utf-8") or "{}") if body else {}
            return self.fabric.run(self, payload)
        if route == "/local/persist" and method == "POST":
            payload = json.loads(body.decode("utf-8") or "{}") if body else {}
            return self.persist_transfer(payload)
        if route == "/local/bitmesh" and method == "GET":
            return self.bitmesh.status()
        if route == "/local/bitmesh" and method == "POST":
            payload = json.loads(body.decode("utf-8") or "{}") if body else {}
            return self.bind_bitmesh(payload)
        if route == "/local/unkillability" and method == "GET":
            return self.unkillability()
        if route == "/local/channels" and method == "GET":
            return self.fabric.channel_audit()
        if route == "/local/phy" and method == "GET":
            from qnsd.phy import probe_all

            return probe_all()
        if route == "/local/planes" and method == "GET":
            return self.planes.snapshot()
        if route == "/local/planes" and method == "POST":
            payload = json.loads(body.decode("utf-8") or "{}") if body else {}
            return self.planes_act(payload)
        raise QNMRefuse("QNM-LOOPBACK-ONLY", f"{method} {route}")


class _Handler(BaseHTTPRequestHandler):
    node: Node

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def _client_ok(self) -> bool:
        host = self.client_address[0]
        return host in ("127.0.0.1", "::1")

    def _send(self, code: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        if not self._client_ok():
            self._send(403, QNMRefuse("QNM-LOOPBACK-ONLY", "127.0.0.1 only").as_dict())
            return
        code, payload = self.node.handle("GET", self.path, b"")
        self._send(code, payload)

    def do_POST(self) -> None:  # noqa: N802
        if not self._client_ok():
            self._send(403, QNMRefuse("QNM-LOOPBACK-ONLY", "127.0.0.1 only").as_dict())
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        code, payload = self.node.handle("POST", self.path, body)
        self._send(code, payload)


def serve(node: Node, host: str = DEFAULT_BIND, port: int = DEFAULT_PORT) -> ThreadingHTTPServer:
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise QNMRefuse("QNM-LOOPBACK-ONLY", "bind 127.0.0.1 only")
    handler = type("QNMHandler", (_Handler,), {"node": node})
    server = ThreadingHTTPServer((host, port), handler)
    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="qnm-node",
        description="QNM-BUILD-1.0 local node + AIH-WP-1.3 spiderweb pair-bind",
    )
    parser.add_argument("cmd", nargs="?", default="state", help="boot|state|serve|doctor|score")
    parser.add_argument("--root", default=".", help="install root directory")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    node = Node(root)
    try:
        if args.cmd == "boot":
            print(json.dumps(node.boot(), indent=2, sort_keys=True))
            return 0
        if args.cmd == "state":
            lock = load_lock(root)
            if lock and not lock.get("scorched") and node.state == "COLD":
                node.boot()
            print(json.dumps(node.snapshot(), indent=2, sort_keys=True))
            return 0
        if args.cmd == "score":
            if node.state == "COLD":
                node.boot()
            print(json.dumps(node.score(), indent=2, sort_keys=True))
            return 0
        if args.cmd == "doctor":
            report = {
                "ok": True,
                "identity": IDENTITY,
                "author": AUTHOR,
                "spec": SPEC,
                "companion": COMPANION,
                "hub_law": HUB_LAW,
                "pair_bind": PAIR_SPEC,
                "radios": radios_stamp(node.fabric.enabled),
                "radios_fielded": False,
                "radios_status": node.fabric.status().get("radios_status") or "ABSENT",
                "bind": DEFAULT_BIND,
                "hop_max": HOP_MAX_DEFAULT,
                "bell_pair": False,
                "qubit": False,
                "forbidden_live_symbols": ["Lumen", "Mandible", "lattice_online", "mesh_complete"],
                "fabric": FABRIC_SPEC,
                "channels": node.fabric.channel_audit(),
                "node_gate": False,
                "az_generator": False,
                "mesh_enable": False,
                "zenodo_required": False,
            }
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0
        if args.cmd == "serve":
            if node.state == "COLD":
                lock = load_lock(root)
                if lock and not lock.get("scorched"):
                    node.boot()
                else:
                    node.boot()
            server = serve(node, DEFAULT_BIND, args.port)
            print(
                json.dumps(
                    {
                        "ok": True,
                        "bind": DEFAULT_BIND,
                        "port": args.port,
                        "spec": SPEC,
                        "author": AUTHOR,
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                server.shutdown()
            return 0
        print(json.dumps(QNMRefuse("QNM-LOOPBACK-ONLY", args.cmd).as_dict()), file=sys.stderr)
        return 2
    except QNMRefuse as exc:
        print(json.dumps(exc.as_dict(), indent=2, sort_keys=True), file=sys.stderr)
        return 2

