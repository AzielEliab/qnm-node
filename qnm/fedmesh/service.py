"""Local-first edge mesh on one qnm daemon.

Inner core (keys, objects, tasks) stays on this process. Outbound
posts pass through the policy filter. Cluster peers are preferred.
Relays are a fallback, and any daemon can opt in to be one. The
Worker URL is just a configurable relay, off unless the operator
points at it.

Author: Aziel Eliab only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import stat
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote

from qnm.boot import AUTHOR, QNMRefuse
from qnm.fedmesh.access import ROLES, Actor
from qnm.fedmesh.airlock import Airlock, check_sha256sums, sha256sums_text
from qnm.fedmesh.chain import Ledger
from qnm.fedmesh.design import (
    DesignBook,
    collect_texts,
    draft_document,
    image_hashes,
    move_block,
    page_html,
    preview_html,
    self_name,
    site_bytes,
)
from qnm.fedmesh.discover import Directory, LanSocket
from qnm.fedmesh.ethics import EthicsGate
from qnm.fedmesh.mirrors import MirrorStore
from qnm.fedmesh.identity import Identity, create_keystore, load_or_create_owner, open_keystore
from qnm.fedmesh.objects import ObjectStore, RefLog, digest_status
from qnm.fedmesh.peers import PeerGuard
from qnm.fedmesh.policy import Outbound
from qnm.fedmesh.relay import Spool, http_json
from qnm.fedmesh.sandbox import run_job
from qnm.fedmesh.secwire import (
    blind_info,
    hop_exit_view,
    hop_info,
    local_statement,
    open_layer,
    signing_public_b64url,
    verify_statement,
    wrap_two_hop,
)
from qnm.fedmesh.tor import TorAdapter
from qnm.fedmesh.wire import (
    DEFAULT_RELAY,
    E2E_ALG,
    PREFIX_CAP,
    VERSION,
    b64d,
    b64e,
    canonical,
    envelope_id,
    make_rollup,
    open_envelope,
    payload_hash,
    projection_of,
    seal_envelope,
    sha256_hex,
    sign_fetch,
    sign_multisig,
    sign_peer_list,
    sign_ref,
    utc_now,
    verify_box_binding,
    verify_committed_inner,
    verify_envelope,
    verify_fetch,
    verify_multisig,
    verify_rollup,
    rollup_batch_hash,
)

REPLICA_COPIES = 2


_TOR_FATAL = frozenset({"FED-TOR-ABSENT", "FED-TOR-OFF"})


def _reraise_transport(exc: QNMRefuse) -> None:
    """A dead Tor proxy is not a relay miss. Do not fall through to clearnet."""
    if exc.code in _TOR_FATAL:
        raise exc


def _b64_bytes(value: object) -> bytes:
    try:
        return base64.b64decode(str(value), validate=True)
    except Exception as exc:  # noqa: BLE001
        raise QNMRefuse("FG-GATE-REFUSE", "image encoding refused") from exc


def _decode_files(value: object) -> dict[str, bytes]:
    if not isinstance(value, dict):
        raise QNMRefuse("FED-TAMPER", "mirror files refused")
    decoded: dict[str, bytes] = {}
    for name, item in value.items():
        try:
            decoded[str(name)] = base64.b64decode(str(item), validate=True)
        except Exception as exc:  # noqa: BLE001
            raise QNMRefuse("FG-GATE-REFUSE", "mirror file encoding refused") from exc
    return decoded


_CONTENT_KEYS = frozenset({"text", "plaintext", "content", "content_b64", "image", "body", "image_b64"})


def _has_content_key(value: object) -> bool:
    if isinstance(value, dict):
        return any(key in _CONTENT_KEYS or _has_content_key(item) for key, item in value.items())
    if isinstance(value, list):
        return any(_has_content_key(item) for item in value)
    return False


def _prepare_blocks(svc: FedService, blocks: list[Any]) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """Land image bytes only after the local image checks clear. A missing model writes nothing."""
    staged: list[dict[str, Any]] = []
    raw_images: list[bytes] = []
    pending: list[tuple[str, list[bytes], dict[str, Any]]] = []
    for block in blocks:
        if not isinstance(block, dict):
            raise QNMRefuse("FED-SLOT", "block refused")
        if block.get("type") == "image" and block.get("image_b64"):
            raw = _b64_bytes(block.get("image_b64"))
            raw_images.append(raw)
            pending.append(("image", [raw], block))
            continue
        if block.get("type") == "gallery" and block.get("image_b64"):
            blobs = [_b64_bytes(item) for item in list(block.get("image_b64") or [])]
            raw_images.extend(blobs)
            pending.append(("gallery", blobs, block))
            continue
        staged.append(block)
        pending.append(("keep", [], block))
    verdict = None
    if raw_images:
        verdict = svc.ethics.check(texts=[], images=raw_images)
        if not verdict.get("ok"):
            return verdict, []
    cleaned: list[dict[str, Any]] = []
    for kind, blobs, block in pending:
        if kind == "keep":
            cleaned.append(block)
            continue
        if kind == "image":
            landed = svc.airlock.land(blobs[0])
            cleaned.append({"type": "image", "sha256": landed["sha256"], "alt": str(block.get("alt") or "")})
            continue
        cleaned.append({"type": "gallery", "images": [svc.airlock.land(blob)["sha256"] for blob in blobs]})
    return None, cleaned


class _Quota:
    def __init__(
        self,
        *,
        cpu_seconds: float = 2,
        wall_seconds: float = 3,
        memory_bytes: int = 32 * 1024 * 1024,
        storage_bytes: int = 1_000_000,
        tasks_per_minute: int = 30,
    ) -> None:
        self.cpu_seconds = cpu_seconds
        self.wall_seconds = wall_seconds
        self.memory_bytes = memory_bytes
        self.storage_bytes = storage_bytes
        self.tasks_per_minute = tasks_per_minute


class FedService:
    def __init__(self, root: Path, cfg: dict[str, Any] | None = None, passphrase: str | None = None) -> None:
        self.root = Path(root)
        self.cfg = cfg or {}
        block = self.cfg.get("fedmesh") if isinstance(self.cfg.get("fedmesh"), dict) else {}
        self.owner = load_or_create_owner(self.root / "data" / "identity", passphrase)
        mesh = self.root / "data" / "fedmesh"
        mesh.mkdir(parents=True, exist_ok=True)
        self.ledger = Ledger(mesh / "anchors.jsonl")
        self.refs = RefLog(mesh / "refs.jsonl")
        self.store = ObjectStore(mesh / "objects")
        self.spool = Spool(mesh / "spool")
        self.airlock = Airlock(mesh / "airlock")
        self.ethics = EthicsGate()
        self.design = DesignBook(mesh / "design")
        self.mirrors = MirrorStore(mesh / "mirrors")
        self.peers = PeerGuard()
        self.tor = TorAdapter()
        self.policy = Outbound()
        self.directory = Directory()
        self.directory.remember_card(self.owner.card)
        self.cluster: set[str] = set()
        self.relay_on = False
        self.direct_on = False
        self.lan_on = False
        self.edge_on = False
        self.upstream_enabled = True
        self.use_default_relay = False
        self.relay_urls: list[str] = []
        self.down: set[str] = set()
        self.base_url = ""
        self.transport = None
        self._writer = None
        self._lock = threading.RLock()
        self.unlocked: dict[str, Identity] = {self.owner.handle: self.owner}
        self.tenants: dict[str, dict[str, Any]] = {}
        self.tokens: dict[str, dict[str, str]] = {}
        self.quotas: dict[str, _Quota] = {self.owner.handle: _Quota()}
        self.storage: dict[str, int] = {}
        self.rate: dict[str, list[float]] = {}
        self.objects_owner: dict[str, str] = {}
        self.shares: dict[str, list[str]] = {}
        self.pending_refs: list[dict[str, Any]] = []
        self.pending_rollups: list[dict[str, Any]] = []
        self.inbox: list[dict[str, Any]] = []
        self.sandbox_runs = 0
        self.relay_seen: dict[tuple[str, int], str] = {}
        self.held_rollups: list[dict[str, Any]] = []
        self.held_refs: list[dict[str, Any]] = []
        self.seen_envelopes: set[str] = set()
        self.two_hop = {"enabled": False, "entry": "", "exit": "", "exit_handle": ""}
        self.hop_sources: list[str] = []
        self.island = False
        self._island_saved: dict[str, Any] | None = None
        self.isolated_local: dict[str, dict[str, Any]] = {}
        self.isolated_seen: dict[str, dict[str, Any]] = {}
        self._design_nonces: dict[str, str] = {}
        self._design_open: set[str] = set()
        self.guard_seq = 0
        self.guard_prev = "0" * 64
        self._hop_queue: list[dict[str, Any]] = []
        self._blinds: dict[str, list[dict[str, Any]]] = {}
        self.delivered_hop_views: list[dict[str, Any]] = []
        self.proposals: dict[str, dict[str, Any]] = {}
        self.vault = {"enabled": False, "m": 0, "n": 0, "members": []}
        self.lan: LanSocket | None = None
        self._load_book()
        if block.get("relays"):
            self.relay_urls = [str(url) for url in block.get("relays") or []]
        if block.get("use_default_relay") is True:
            self.use_default_relay = True
            if DEFAULT_RELAY not in self.relay_urls:
                self.relay_urls.append(DEFAULT_RELAY)
        if self.island:
            self.relay_urls = []
            self.upstream_enabled = False
            self.direct_on = False
            self.cluster.clear()

    def bind(self, node: Any) -> None:
        self._writer = node._write_receipt

    def anchor(self, projection: dict[str, Any], signer: Identity | None = None) -> dict[str, Any]:
        from qnm.fedmesh.wire import make_anchor

        ident = signer or self.owner
        with self._lock:
            seq, prev = self.ledger.tip(ident.handle)
            row = make_anchor(
                ident.sign_private,
                handle=ident.handle,
                key_id=ident.key_id,
                sign_pub=str(ident.card["sign_pub"]),
                seq=seq + 1,
                prev=prev,
                payload_hash_hex=payload_hash(projection),
            )
            self.ledger.submit(row)
            return row

    def public_status(self) -> dict[str, Any]:
        seq, tip = self.ledger.tip(self.owner.handle)
        return {
            "ok": True,
            "v": VERSION,
            "author": AUTHOR,
            "handle": self.owner.handle,
            "key_id": self.owner.key_id,
            "seal": self.owner.seal_kind,
            "relay_listen": self.relay_on,
            "direct_inbox": self.direct_on,
            "lan_discovery": self.lan_on,
            "edge_compute": self.edge_on,
            "upstream_enabled": self.upstream_enabled,
            "use_default_relay": self.use_default_relay,
            "default_relay": DEFAULT_RELAY,
            "relays": list(self.relay_urls),
            "e2e": E2E_ALG,
            "e2e_forward_secrecy": False,
            "anonymity": False,
            "nat_traversal": False,
            "relay_plaintext": False,
            "local_first": True,
            "raw_leaves_only_on_share": True,
            "e2e_mandatory": True,
            "two_hop": bool(self.two_hop["enabled"]),
            "tor": self.tor.status(),
            "island": self.island,
            "isolated_local": sorted(self.isolated_local),
            "design_mode": "localhost-and-key-unlock",
            "design_remote": False,
            "ethics_fail_closed": True,
            "ethics_models_absent": bool(self.ethics.status()["absent"]),
            "user_slots": 3,
            "reserved_slots": ["ae", "corpus", "godlock", "hdj"],
            "cap7_factory_unchanged": True,
            "zero_knowledge": False,
            "state_level_adversary": False,
            "temporal_lock": False,
            "chainlock_upstream": False,
            "sandbox": "subprocess-allowlist",
            "bluetooth": {
                "bearer": "bt",
                "mesh_transport": False,
                "default_on": False,
                "note": (
                    "bt is an existing opt-in PHY bearer, default off, "
                    "LIVE only when BlueZ is present. This mesh does not "
                    "send over Bluetooth and does not claim a tested radio link."
                ),
            },
            "needs_bootstrap": self._needs_bootstrap(),
            "receipt_seq": seq,
            "receipt_tip": tip,
            "cluster": sorted(self.cluster),
            "multisig": {
                "enabled": self.vault["enabled"],
                "m": self.vault["m"],
                "n": self.vault["n"],
            },
            "spec_alignment": "draft-not-on-aziel-runtime-main",
        }

    def _needs_bootstrap(self) -> bool:
        return not self.relay_urls and not self.directory.addrs and not self.lan_on and not self.cluster

    def actor_from_headers(self, headers: Any) -> Actor:
        token = ""
        if headers is not None and hasattr(headers, "get"):
            token = str(headers.get("X-QNM-Role-Token") or headers.get("x-qnm-role-token") or "")
        if token:
            return self.actor_for_token(token)
        return Actor("admin", self.owner.handle, via="loopback")

    def actor_for_token(self, token: str) -> Actor:
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        row = self.tokens.get(digest)
        if not row:
            raise QNMRefuse("FED-ROLE", "unknown role token")
        return Actor(str(row["role"]), str(row["handle"]), via="token")

    def note_base(self, url: str) -> None:
        self.base_url = str(url).rstrip("/")

    def set_relays(self, urls: list[str]) -> None:
        self.relay_urls = [str(url).rstrip("/") for url in urls if url]

    def mark_cluster(self, handle: str, url: str | None = None) -> None:
        self.cluster.add(handle)
        if url:
            self.directory.addrs.setdefault(handle, [])
            if url not in self.directory.addrs[handle]:
                self.directory.addrs[handle].append(url.rstrip("/"))

    def local_op(self, actor: Actor, payload: dict[str, Any], peer: str = "127.0.0.1") -> dict[str, Any]:
        op = str(payload.get("op") or "")
        if op in ("relay_on", "relay_off"):
            self._admin(actor)
            self.relay_on = op == "relay_on"
            return self.public_status()
        if op in ("direct_on", "direct_off"):
            self._admin(actor)
            self.direct_on = op == "direct_on"
            return self.public_status()
        if op in ("lan_on", "lan_off"):
            self._admin(actor)
            self.lan_on = op == "lan_on"
            if not self.lan_on and self.lan is not None:
                self.lan.close()
                self.lan = None
            return self.public_status()
        if op in ("edge_on", "edge_off"):
            self._admin(actor)
            self.edge_on = op == "edge_on"
            return self.public_status()
        if op in ("upstream_on", "upstream_off"):
            self._admin(actor)
            self.upstream_enabled = op == "upstream_on"
            return self.public_status()
        if op == "bootstrap":
            self._admin(actor)
            self.set_relays(list(payload.get("relays") or []))
            return self.public_status()
        if op == "create_tenant":
            self._admin(actor)
            return self.create_tenant(str(payload.get("passphrase") or ""), role=str(payload.get("role") or "developer"))
        if op == "set_quota":
            self._admin(actor)
            return self.set_quota(str(payload.get("handle") or ""), payload)
        if op == "grant_role":
            self._admin(actor)
            token = self.grant_role(str(payload.get("role") or ""), str(payload.get("handle") or ""))
            return {"ok": True, "token": token, "role": payload.get("role"), "handle": payload.get("handle")}
        if op == "unlock":
            return self.unlock(actor, str(payload.get("handle") or actor.handle), str(payload.get("passphrase") or ""))
        if op == "message":
            return self.send_message(actor, str(payload.get("to") or ""), str(payload.get("text") or ""), share=bool(payload.get("share")))
        if op == "file":
            return self.send_file(
                actor,
                str(payload.get("to") or ""),
                str(payload.get("name") or "file"),
                str(payload.get("text") or ""),
                share=bool(payload.get("share")),
            )
        if op == "inbox":
            return self._inbox_for(actor)
        if op == "poll":
            return {"ok": True, "messages": self.poll()}
        if op == "task":
            return self.run_task(actor, dict(payload.get("job") or {}))
        if op == "edge":
            return self.send_edge(
                actor,
                str(payload.get("to") or ""),
                dict(payload.get("job") or {}),
                share=bool(payload.get("share")),
            )
        if op == "put":
            raw = str(payload.get("text") or "").encode("utf-8")
            return {"ok": True, "object": self.put_object(actor, raw)}
        if op == "push":
            return {"ok": True, "ref": self.push_ref(actor, str(payload.get("ref") or "main"), str(payload.get("object") or ""))}
        if op == "share":
            return self.share_object(actor, str(payload.get("object") or ""), str(payload.get("to") or ""))
        if op == "fetch":
            data = self.fetch_object(actor, str(payload.get("object") or ""))
            return {"ok": True, "object": payload.get("object"), "sha256": sha256_hex(data), "bytes": len(data)}
        if op == "sync":
            return self.sync()
        if op == "sign_rollup":
            return self.sign_rollup(actor, list(payload.get("changes") or []))
        if op == "rollup":
            return self.build_rollup(actor, list(payload.get("changes") or []), list(payload.get("signers") or []))
        if op == "push_rollup":
            return self.stage_rollup(dict(payload.get("rollup") or {}))
        if op == "multisig_on":
            self._admin(actor)
            return self.configure_vault(
                int(payload.get("m") or 0),
                int(payload.get("n") or 0),
                list(payload.get("members") or []),
                enabled=True,
            )
        if op == "multisig_off":
            self._admin(actor)
            self.vault["enabled"] = False
            return self.public_status()
        if op == "multisig_approve":
            return self.approve(actor, str(payload.get("subject") or ""))
        if op == "peers":
            return self.directory.merge_peer_list(dict(payload.get("card") or {}), rate_limit=int(payload.get("rate_limit") or 3))
        if op == "digest":
            return self.engine_digest()
        if op == "e2e_off":
            raise QNMRefuse("FED-POLICY", "end-to-end encryption is mandatory for mesh payloads")
        if op == "name":
            raise QNMRefuse("FED-WITNESS", "this daemon does not finalize name claims")
        if op == "quarantine":
            self._admin(actor)
            return self.quarantine_peer(str(payload.get("peer") or ""), cut=True)
        if op == "unquarantine":
            self._admin(actor)
            return self.quarantine_peer(str(payload.get("peer") or ""), cut=False)
        if op == "island_on":
            self._admin(actor)
            return self.enter_island()
        if op == "island_off":
            self._admin(actor)
            return self.leave_island()
        if op == "two_hop_on":
            self._admin(actor)
            return self.enable_two_hop(
                str(payload.get("entry") or ""),
                str(payload.get("exit") or ""),
                str(payload.get("exit_handle") or ""),
            )
        if op == "two_hop_off":
            self._admin(actor)
            self.two_hop["enabled"] = False
            self._save_book()
            return self.public_status()
        if op == "tor_on":
            self._admin(actor)
            self.tor.configure(str(payload.get("proxy") or "127.0.0.1:9050"), enabled=True)
            return self.public_status()
        if op == "tor_off":
            self._admin(actor)
            self.tor.enabled = False
            return self.public_status()
        if op == "trust":
            return self.trust_view(str(payload.get("peer") or actor.handle))
        if op == "advisory_subscribe":
            self._admin(actor)
            return self.subscribe_advisory(dict(payload.get("statement") or {}))
        if op == "vouch":
            self._admin(actor)
            return self.vouch_peer(str(payload.get("peer") or ""))
        if op == "airlock_promote":
            return self.promote_airlock(actor, str(payload.get("object") or ""), override=bool(payload.get("override")))
        if op == "airgap_export":
            self._admin(actor)
            return self.export_airgap(str(payload.get("dest") or ""), list(payload.get("objects") or []))
        if op == "airgap_import":
            self._admin(actor)
            return self.import_airgap(str(payload.get("src") or ""))
        if op == "design_status":
            return self.design_status(actor, peer)
        if op == "design_challenge":
            return self.design_challenge(actor, peer)
        if op == "design_unlock":
            return self.design_unlock(actor, str(payload.get("sig") or ""), str(payload.get("public_key") or ""), peer)
        if op == "design_put":
            return self.design_put(actor, payload, peer)
        if op == "design_move":
            return self.design_move(actor, payload, peer)
        if op == "design_preview":
            return self.design_preview(actor, int(payload.get("slot") or 0), peer)
        if op == "design_publish":
            return self.design_publish(actor, int(payload.get("slot") or 0), peer, override=bool(payload.get("override")))
        if op == "appeal":
            return self.appeal(actor, peer)
        if op == "mirror_status":
            self._require_local(peer)
            return self.mirrors.status()
        if op == "mirror_restore":
            self._admin(actor)
            self._require_local(peer)
            return self.mirrors.restore(dict(payload.get("statement") or {}), _decode_files(payload.get("files")))
        if op == "mirror_serve":
            self._require_local(peer)
            return self.mirrors.serve(str(payload.get("slot") or ""))
        if op == "hop_sources":
            self._admin(actor)
            self.hop_sources = [str(url).rstrip("/") for url in list(payload.get("urls") or [])]
            return {"ok": True, "hop_sources": list(self.hop_sources)}
        if op == "pull_hops":
            return {"ok": True, "blinds": self.pull_hops()}
        if op == "pull_blinds":
            return {"ok": True, "messages": self.pull_blinds()}
        if op in ("keystore", "export_key", "tenant_key"):
            raise QNMRefuse("FED-TENANT", "private keys are not readable through the API")
        raise QNMRefuse("FED-ROLE", f"unknown fedmesh op:{op}")

    def _admin(self, actor: Actor) -> None:
        if actor.role != "admin":
            raise QNMRefuse("FED-ROLE", "admin only")

    def _signer(self, actor: Actor) -> Identity:
        if actor.role == "admin" and actor.handle != self.owner.handle:
            raise QNMRefuse("FED-TENANT", "admin acts as the host identity")
        ident = self.unlocked.get(actor.handle)
        if ident is None:
            raise QNMRefuse("FED-PASSPHRASE", "identity is locked")
        if actor.handle != ident.handle:
            raise QNMRefuse("FED-TENANT", "actor does not match the key")
        return ident

    def grant_role(self, role: str, handle: str) -> str:
        if role not in ROLES:
            raise QNMRefuse("FED-ROLE", "unknown role")
        token = secrets.token_urlsafe(24)
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        self.tokens[digest] = {"role": role, "handle": handle}
        self._save_book()
        return token

    def create_tenant(self, passphrase: str, *, role: str = "developer") -> dict[str, Any]:
        if len(passphrase) < 8:
            raise QNMRefuse("FED-PASSPHRASE", "tenant passphrase too short")
        if role not in ("developer", "guest"):
            raise QNMRefuse("FED-ROLE", "tenant role refused")
        slot = self.root / "data" / "tenants" / secrets.token_hex(8)
        ident = create_keystore(slot, passphrase.encode("utf-8"), seal_kind="scrypt-passphrase")
        card = dict(ident.card)
        handle = ident.handle
        del ident
        self.tenants[handle] = {"card": card, "dir": str(slot), "role": role}
        self.directory.remember_card(card)
        self.quotas[handle] = _Quota()
        token = self.grant_role(role, handle)
        self._save_book()
        return {"ok": True, "handle": handle, "role": role, "token": token, "card": card, "key_exported": False}

    def unlock(self, actor: Actor, handle: str, passphrase: str) -> dict[str, Any]:
        if actor.handle != handle:
            raise QNMRefuse("FED-TENANT", "only that identity can open its key")
        if handle == self.owner.handle:
            return {"ok": True, "handle": handle, "unlocked": True}
        row = self.tenants.get(handle)
        if not row:
            raise QNMRefuse("FED-TENANT", "unknown tenant")
        ident = open_keystore(Path(row["dir"]), passphrase.encode("utf-8"))
        if ident.handle != handle:
            raise QNMRefuse("FED-WRONG-KEY", "tenant key handle mismatch")
        self.unlocked[handle] = ident
        return {"ok": True, "handle": handle, "unlocked": True, "key_exported": False}

    def set_quota(self, handle: str, payload: dict[str, Any]) -> dict[str, Any]:
        if handle not in self.quotas:
            raise QNMRefuse("FED-TENANT", "unknown identity")
        current = self.quotas[handle]
        self.quotas[handle] = _Quota(
            cpu_seconds=float(payload.get("cpu_seconds") or current.cpu_seconds),
            wall_seconds=float(payload.get("wall_seconds") or current.wall_seconds),
            memory_bytes=int(payload.get("memory_bytes") or current.memory_bytes),
            storage_bytes=int(payload.get("storage_bytes") or current.storage_bytes),
            tasks_per_minute=int(payload.get("tasks_per_minute") or current.tasks_per_minute),
        )
        return {"ok": True, "handle": handle}

    def _charge(self, handle: str, size: int) -> None:
        quota = self.quotas.get(handle) or _Quota()
        used = self.storage.get(handle, 0)
        if used + size > quota.storage_bytes:
            raise QNMRefuse("FED-QUOTA", "storage quota")
        self.storage[handle] = used + size

    def _rate_ok(self, handle: str) -> None:
        quota = self.quotas.get(handle) or _Quota()
        now = time.monotonic()
        window = [stamp for stamp in self.rate.get(handle, []) if now - stamp < 60]
        if len(window) >= quota.tasks_per_minute:
            self.rate[handle] = window
            raise QNMRefuse("FED-RATE", "task rate limit")
        window.append(now)
        self.rate[handle] = window

    def run_task(self, actor: Actor, job: dict[str, Any]) -> dict[str, Any]:
        if actor.role not in ("developer", "admin"):
            raise QNMRefuse("FED-ROLE", "tasks need a developer")
        ident = self._signer(actor)
        target = str(job.get("tenant") or ident.handle)
        if target != ident.handle:
            raise QNMRefuse("FED-TENANT", "cannot run as another identity")
        self._rate_ok(ident.handle)
        quota = self.quotas.get(ident.handle) or _Quota()
        self.sandbox_runs += 1
        result = run_job(
            job,
            cpu_seconds=quota.cpu_seconds,
            wall_seconds=quota.wall_seconds,
            memory_bytes=quota.memory_bytes,
        )
        public = {
            "op": str(job.get("op") or ""),
            "ok": bool(result.get("ok")),
            "code": str(result.get("code") or ""),
            "result_hash": sha256_hex(canonical({"result": result.get("result")})),
        }
        if self._writer is not None:
            self._writer("fedmesh_task", public, signer=ident)
            self._writer("fedmesh_task_host", {"for": ident.handle, "ok": public["ok"], "code": public["code"]})
        result = dict(result)
        result["handle"] = ident.handle
        return result

    def send_message(self, actor: Actor, to_handle: str, text: str, *, share: bool) -> dict[str, Any]:
        self.policy.hold(text)
        if not share:
            raise QNMRefuse("FED-POLICY", "raw data leaves only as an explicit encrypted share")
        return self._send_inner(actor, to_handle, {"kind": "note", "text": text}, purpose="msg")

    def send_edge(self, actor: Actor, to_handle: str, job: dict[str, Any], *, share: bool) -> dict[str, Any]:
        if actor.role not in ("developer", "admin"):
            raise QNMRefuse("FED-ROLE", "tasks need a developer")
        self.policy.hold(json.dumps(job, sort_keys=True, separators=(",", ":")))
        if not share:
            raise QNMRefuse("FED-POLICY", "raw data leaves only as an explicit encrypted share")
        return self._send_inner(actor, to_handle, {"kind": "task", "job": job}, purpose="task")

    def send_file(self, actor: Actor, to_handle: str, name: str, text: str, *, share: bool) -> dict[str, Any]:
        self.policy.hold(text)
        if not share:
            raise QNMRefuse("FED-POLICY", "raw data leaves only as an explicit encrypted share")
        plain = {"kind": "file", "name": name, "content_b64": b64e(text.encode("utf-8"))}
        return self._send_inner(actor, to_handle, plain, purpose="msg")

    def _send_inner(self, actor: Actor, to_handle: str, plaintext: dict[str, Any], *, purpose: str) -> dict[str, Any]:
        if self.island:
            raise QNMRefuse("FED-ISLAND", "island mode is on; mesh sends are stopped")
        ident = self._signer(actor)
        self.peers.check(to_handle, len(canonical(plaintext)))
        card = self._card(to_handle)
        ph = payload_hash(plaintext)
        if self._writer is None:
            raise QNMRefuse("FED-BOOTSTRAP", "receipt writer is not bound")
        receipt = self._writer(
            "fedmesh_msg",
            {"to": to_handle, "purpose": purpose, "payload_hash": ph},
            signer=ident,
        )
        inner = {
            "plaintext": plaintext,
            "projection": projection_of(receipt),
            "anchor": receipt["mesh"],
            "prefix": self.ledger.prefix(ident.handle)[-PREFIX_CAP:],
        }
        env = seal_envelope(
            private_key=ident.sign_private,
            box_private=ident.box_private,
            sender=ident.card,
            recipient_card=card,
            seq=int(receipt["mesh"]["seq"]),
            prev=str(receipt["mesh"]["prev"]),
            purpose=purpose,
            plaintext=inner,
        )
        if self.vault["enabled"]:
            return self._queue_multisig(ident, env)
        if self.two_hop["enabled"] and purpose == "msg":
            return self._route_two_hop(ident, env)
        return self._route(env, share=True)

    def _card(self, handle: str) -> dict[str, Any]:
        card = self.directory.cards.get(handle)
        if card:
            return card
        if not self.upstream_enabled:
            raise QNMRefuse("FED-NO-ROUTE", "no local card for that handle")
        for url in self._ordered_relays():
            try:
                got = self._get(url + "/v1/fedmesh/card?handle=" + quote(handle, safe=""))
            except QNMRefuse as exc:
                _reraise_transport(exc)
                self.down.add(url)
                continue
            if isinstance(got.get("card"), dict):
                verify_box_binding(got["card"])
                self.directory.remember_card(got["card"])
                return got["card"]
        raise QNMRefuse("FED-NO-ROUTE", "handle is not known")

    def _split_urls(self, handle: str) -> tuple[list[str], list[str]]:
        urls = [url.rstrip("/") for url in self.directory.addrs.get(handle, [])]
        if handle in self.cluster:
            return urls, []
        return [], urls

    def _ordered_relays(self) -> list[str]:
        healthy = [url for url in self.relay_urls if url not in self.down]
        sick = [url for url in self.relay_urls if url in self.down]
        return healthy + sick

    def _route(self, env: dict[str, Any], *, share: bool) -> dict[str, Any]:
        to_handle = str(env.get("to") or "")
        if self.direct_on:
            cluster, rest = self._split_urls(to_handle)
            refused: list[str] = []
            for url in cluster + rest:
                try:
                    response = self._post(url + "/v1/fedmesh/direct", env, share=share)
                    return {
                        "ok": True,
                        "path": "cluster" if url in cluster or to_handle in self.cluster else "direct",
                        "e2e": True,
                        "relays": [],
                        "response": response,
                    }
                except QNMRefuse as exc:
                    _reraise_transport(exc)
                    refused.append(exc.code)
                    continue
            if refused and all(code == "FED-EDGE-OFF" for code in refused):
                raise QNMRefuse("FED-EDGE-OFF", "peer refused edge compute")
        if not self.upstream_enabled:
            raise QNMRefuse("FED-NO-ROUTE", "upstream is off and no cluster peer accepted")
        if not self.relay_urls and not self.directory.addrs.get(to_handle):
            raise QNMRefuse("FED-BOOTSTRAP", "a new node needs a relay, a peer, or LAN discovery")
        stored: list[str] = []
        for url in self._ordered_relays():
            try:
                self._post(url + "/v1/fedmesh/send", env, share=share)
            except QNMRefuse as exc:
                _reraise_transport(exc)
                self.down.add(url)
                continue
            self.down.discard(url)
            stored.append(url)
            if len(stored) >= REPLICA_COPIES:
                break
        if not stored:
            raise QNMRefuse("FED-NO-ROUTE", "no relay accepted the envelope")
        return {"ok": True, "path": "relay", "e2e": True, "relays": stored}

    def _post(self, url: str, payload: dict[str, Any], *, share: bool = False) -> dict[str, Any]:
        self.policy.guard(payload, share=share)
        if self.transport is not None:
            result = self.transport("POST", url, payload)
            if not isinstance(result, dict):
                raise QNMRefuse("FED-NO-ROUTE", "transport refused")
            return result
        if self.tor.enabled:
            return self.tor.request("POST", url, payload)
        return http_json("POST", url, payload)

    def _get(self, url: str) -> dict[str, Any]:
        if self.transport is not None:
            result = self.transport("GET", url, None)
            if not isinstance(result, dict):
                raise QNMRefuse("FED-NO-ROUTE", "transport refused")
            return result
        if self.tor.enabled:
            return self.tor.request("GET", url, None)
        return http_json("GET", url)

    def poll(self) -> list[dict[str, Any]]:
        if not self.upstream_enabled:
            return []
        got: list[dict[str, Any]] = []
        for url in self._ordered_relays():
            try:
                res = self._get(url + "/v1/fedmesh/inbox?handle=" + quote(self.owner.handle, safe=""))
            except QNMRefuse as exc:
                _reraise_transport(exc)
                self.down.add(url)
                continue
            self.down.discard(url)
            ids: list[str] = []
            for env in res.get("envelopes") or []:
                ident = envelope_id(env)
                try:
                    got.append(self.ingest(env))
                except QNMRefuse as exc:
                    if exc.code in ("FED-REPLAY", "FED-EDGE-OFF"):
                        ids.append(ident)
                        continue
                    raise
                ids.append(ident)
            if ids:
                try:
                    self._post(
                        url + "/v1/fedmesh/ack",
                        {"v": VERSION, "kind": "ack", "author": AUTHOR, "handle": self.owner.handle, "ids": ids},
                        share=False,
                    )
                except QNMRefuse:
                    pass
        return got

    def ingest(self, env: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            verify_envelope(env)
            sender = str(env.get("from") or "")
            if sender in self.peers.quarantine:
                raise QNMRefuse("FED-QUARANTINE", "this node has quarantined that handle")
            self.peers.check(sender, len(str(env.get("ct") or "")))
            ident_env = envelope_id(env)
            if ident_env in self.seen_envelopes:
                raise QNMRefuse("FED-REPLAY", "envelope already ingested")
            if env.get("purpose") == "task" and not self.edge_on:
                raise QNMRefuse("FED-EDGE-OFF", "edge compute is off")
            if env.get("to") != self.owner.handle:
                raise QNMRefuse("FED-TAMPER", "envelope is not for this node")
            inner = open_envelope(self.owner.box_private, self.owner.card, env)
            if env.get("purpose") == "task":
                self.seen_envelopes.add(ident_env)
                return self._run_edge(env, inner)
            verify_committed_inner(inner)
            anchors = list(inner.get("prefix") or [])
            anchor = inner.get("anchor")
            if isinstance(anchor, dict) and all(row.get("hash") != anchor.get("hash") for row in anchors):
                anchors.append(anchor)
            for row in anchors:
                try:
                    self.ledger.submit(row)
                except QNMRefuse as exc:
                    if exc.code != "FED-REPLAY":
                        raise
            plain = inner.get("plaintext") if isinstance(inner.get("plaintext"), dict) else {}
            text = ""
            kind = str(plain.get("kind") or "")
            if kind == "note":
                text = str(plain.get("text") or "")
            elif kind == "file":
                text = b64d(str(plain.get("content_b64") or "")).decode("utf-8", "replace")
                self.airlock.land(text.encode("utf-8"))
            elif kind == "object":
                raw = b64d(str(plain.get("content_b64") or ""))
                if sha256_hex(raw) != plain.get("object"):
                    raise QNMRefuse("FG-GATE-REFUSE", "object bytes do not match the hash")
                self.airlock.land(raw, claimed=str(plain.get("object") or ""))
            self.seen_envelopes.add(ident_env)
            self.peers.heartbeats[sender] = self.peers.heartbeats.get(sender, 0) + 1
            self.inbox.append({"from": env.get("from"), "kind": kind, "text": text, "id": ident_env})
            self._write_inbox()
            if self._writer is not None:
                self._writer("fedmesh_delivery", {"msg_id": envelope_id(env), "from": env.get("from")})
            return {"ok": True, "from": env.get("from"), "kind": kind, "text": text, "id": envelope_id(env)}

    def _run_edge(self, env: dict[str, Any], inner: dict[str, Any]) -> dict[str, Any]:
        plain = inner.get("plaintext") if isinstance(inner.get("plaintext"), dict) else {}
        job = plain.get("job") if isinstance(plain.get("job"), dict) else {}
        quota = _Quota(cpu_seconds=1, wall_seconds=2, memory_bytes=16 * 1024 * 1024, tasks_per_minute=10)
        self.sandbox_runs += 1
        result = run_job(job, cpu_seconds=quota.cpu_seconds, wall_seconds=quota.wall_seconds, memory_bytes=quota.memory_bytes)
        public = {
            "for": env.get("from"),
            "ok": bool(result.get("ok")),
            "code": str(result.get("code") or ""),
            "result_hash": sha256_hex(canonical({"result": result.get("result")})),
            "msg_id": envelope_id(env),
        }
        host_receipt = None
        if self._writer is not None:
            host_receipt = self._writer("fedmesh_edge_host", public)
        return {"ok": True, "edge": True, "result": result, "host_receipt": host_receipt, "guest_anchor_for": env.get("from")}

    def http_relay(self, method: str, path: str, query: str, body: bytes) -> dict[str, Any]:
        route = path.rstrip("/") or "/"
        qs = parse_qs(query or "")
        payload: dict[str, Any] = {}
        if body:
            try:
                loaded = json.loads(body.decode("utf-8") or "{}")
            except Exception as exc:  # noqa: BLE001
                raise QNMRefuse("FED-TAMPER", "relay body is not JSON") from exc
            if not isinstance(loaded, dict):
                raise QNMRefuse("FED-TAMPER", "relay body is not an object")
            payload = loaded
        if route.endswith("/health") and method == "GET":
            return {
                "ok": True,
                "v": VERSION,
                "author": AUTHOR,
                "relay": self.relay_on,
                "direct": self.direct_on,
                "isolated": bool(self.isolated_local),
                "enabled_by_get": False,
            }
        if self.isolated_local:
            raise QNMRefuse("FED-ISOLATED", "this node is isolated and is not relaying")
        subject = str(payload.get("handle") or payload.get("from") or (qs.get("handle") or [""])[0])
        if subject and subject in self.isolated_seen:
            raise QNMRefuse("FED-ISOLATED", "relay refuses an isolated handle")
        if route.endswith("/register") and method == "POST":
            self._need_relay()
            verify_box_binding(payload)
            self.directory.remember_card(payload)
            return {"ok": True, "kind": "register", "author": AUTHOR, "handle": payload.get("handle")}
        if route.endswith("/send") and method == "POST":
            self._need_relay()
            return self._accept_relay(payload)
        if route.endswith("/inbox") and method == "GET":
            self._need_relay()
            handle = (qs.get("handle") or [""])[0]
            return {"ok": True, "envelopes": self.spool.poll(handle)}
        if route.endswith("/ack") and method == "POST":
            self._need_relay()
            return self.spool.ack(str(payload.get("handle") or ""), list(payload.get("ids") or []))
        if route.endswith("/card") and method == "GET":
            self._need_relay()
            handle = (qs.get("handle") or [""])[0]
            card = self.directory.cards.get(handle)
            if not card:
                raise QNMRefuse("FED-NO-ROUTE", "unknown handle")
            return {"ok": True, "card": card}
        if route.endswith("/direct") and method == "POST":
            if not self.direct_on:
                raise QNMRefuse("FED-DIRECT-OFF", "direct inbox is off")
            return self.ingest(payload)
        if route.endswith("/peers") and method == "POST":
            if not (self.lan_on or self.direct_on or self.relay_on):
                raise QNMRefuse("FED-DISCOVERY-OFF", "discovery is off")
            return self.directory.merge_peer_list(payload)
        if route.endswith("/object") and method == "POST":
            if not (self.direct_on or self.relay_on):
                raise QNMRefuse("FED-DIRECT-OFF", "object fetch is off")
            return self._serve_object(payload)
        if route.endswith("/refs") and method == "POST":
            if not (self.direct_on or self.relay_on):
                raise QNMRefuse("FED-DIRECT-OFF", "ref sync is off")
            self._apply_ref(payload)
            self.held_refs.append(payload)
            return {"ok": True, "kind": "ref", "author": AUTHOR, "object": payload.get("object")}
        if route.endswith("/rollup") and method == "POST":
            if not (self.direct_on or self.relay_on):
                raise QNMRefuse("FED-DIRECT-OFF", "rollup sync is off")
            verify_rollup(payload)
            self.held_rollups.append(payload)
            return {
                "ok": True,
                "kind": "rollup",
                "author": AUTHOR,
                "stored": True,
                "temporal_lock": False,
                "chainlock_upstream": False,
            }
        if route.endswith("/rollup-sign") and method == "POST":
            if not self.direct_on:
                raise QNMRefuse("FED-DIRECT-OFF", "cluster rollup sign is off")
            requester = str(payload.get("from") or "")
            if requester not in self.cluster:
                raise QNMRefuse("FED-ROLE", "rollup co-sign stays inside the cluster")
            return self.sign_rollup(Actor("admin", self.owner.handle, via="cluster"), list(payload.get("changes") or []))
        if route.endswith("/hop") and method == "POST":
            self._need_relay()
            return self.accept_hop(payload)
        if route.endswith("/hop") and method == "GET":
            self._need_relay()
            handle = (qs.get("handle") or [""])[0]
            return {"ok": True, "opened": False, "hops": self.take_hops(handle)}
        if route.endswith("/blind") and method == "GET":
            self._need_relay()
            handle = (qs.get("handle") or [""])[0]
            return {"ok": True, "blinds": self.take_blinds(handle)}
        if route.endswith("/isolation") and method == "POST":
            self._need_relay()
            return self.accept_isolation(payload)
        if route.endswith("/delivery") and method == "POST":
            self._need_relay()
            self.policy.guard(payload, share=False)
            return {"ok": True, "kind": "delivery", "author": AUTHOR, "stored": True}
        raise QNMRefuse("FED-NO-ROUTE", f"unknown relay path {route}")

    def _need_relay(self) -> None:
        if not self.relay_on:
            raise QNMRefuse("FED-RELAY-OFF", "this node is not a relay")

    def _accept_relay(self, env: dict[str, Any]) -> dict[str, Any]:
        verify_envelope(env)
        key = (str(env.get("from") or ""), int(env.get("seq") or 0))
        ident = envelope_id(env)
        previous = self.relay_seen.get(key)
        if previous is not None:
            if previous == ident:
                raise QNMRefuse("FED-REPLAY", "relay already accepted this sequence")
            raise QNMRefuse("FED-FORK", "relay saw a different envelope at this sequence")
        stored = self.spool.put(env)
        self.relay_seen[key] = ident
        return {"ok": True, "stored": True, "id": stored["id"], "kind": "msg"}

    def put_object(self, actor: Actor, data: bytes) -> str:
        ident = self._signer(actor)
        self._charge(ident.handle, len(data))
        try:
            self.policy.hold(data.decode("utf-8"))
        except UnicodeDecodeError:
            pass
        digest = self.store.put(data)
        self.objects_owner[digest] = ident.handle
        self._save_book()
        return digest

    def share_object(self, actor: Actor, digest: str, to_handle: str) -> dict[str, Any]:
        ident = self._signer(actor)
        if self.objects_owner.get(digest) != ident.handle:
            raise QNMRefuse("FED-SHARE", "only the owner can share an object")
        if not self.store.has(digest):
            raise QNMRefuse("FED-FETCH", "object missing")
        current = self.shares.setdefault(digest, [])
        if to_handle not in current:
            current.append(to_handle)
        self._save_book()
        return {"ok": True, "object": digest, "with": to_handle, "encrypted_on_fetch": True}

    def push_ref(self, actor: Actor, ref: str, digest: str) -> dict[str, Any]:
        ident = self._signer(actor)
        if self.objects_owner.get(digest) != ident.handle:
            raise QNMRefuse("FED-SHARE", "ref target is not this identity's object")
        seq, prev = self.refs.tip(ident.handle, ref)
        update = sign_ref(
            ident.sign_private,
            handle=ident.handle,
            key_id=ident.key_id,
            sign_pub=str(ident.card["sign_pub"]),
            ref=ref,
            object_hash=digest,
            prev=prev,
            seq=seq + 1,
            utc=utc_now(),
        )
        self._apply_ref(update)
        self.pending_refs.append(update)
        self._fan_cluster(update, "/v1/fedmesh/refs")
        if self.upstream_enabled:
            self.flush_refs()
        return update

    def flush_refs(self) -> list[dict[str, Any]]:
        if not self.upstream_enabled:
            return list(self.pending_refs)
        still: list[dict[str, Any]] = []
        for update in self.pending_refs:
            if not self._fan_relays(update, "/v1/fedmesh/refs"):
                still.append(update)
        self.pending_refs = still
        return still

    def fetch_object(self, actor: Actor, digest: str) -> bytes:
        if self.store.has(digest):
            owner = self.objects_owner.get(digest)
            shared_with = actor.handle in self.shares.get(digest, [])
            if owner == actor.handle or shared_with:
                return self.store.get(digest)
            raise QNMRefuse("FED-SHARE", "object is not shared with this identity")
        ident = self._signer(actor)
        request = sign_fetch(
            ident.sign_private,
            handle=ident.handle,
            key_id=ident.key_id,
            sign_pub=str(ident.card["sign_pub"]),
            object_hash=digest,
            utc=utc_now(),
        )
        urls = self._fetch_urls()
        for url in urls:
            try:
                res = self._post(url + "/v1/fedmesh/object", request, share=False)
            except QNMRefuse as exc:
                _reraise_transport(exc)
                continue
            if "ct" not in res:
                continue
            inner = open_envelope(ident.box_private, ident.card, res)
            plain = inner.get("plaintext") if isinstance(inner.get("plaintext"), dict) else {}
            raw = b64d(str(plain.get("content_b64") or ""))
            if sha256_hex(raw) != digest:
                raise QNMRefuse("FG-GATE-REFUSE", "object bytes do not match the hash")
            self.airlock.land(raw, claimed=digest)
            self.peers.hash_matches[ident.handle] = self.peers.hash_matches.get(ident.handle, 0) + 1
            return raw
        raise QNMRefuse("FED-FETCH", "object not found on cluster or relay peers")

    def _fetch_urls(self) -> list[str]:
        cluster: list[str] = []
        other: list[str] = []
        for handle, urls in self.directory.addrs.items():
            bucket = cluster if handle in self.cluster else other
            for url in urls:
                if url not in bucket:
                    bucket.append(url.rstrip("/"))
        relays = self._ordered_relays() if self.upstream_enabled else []
        return cluster + other + relays

    def _serve_object(self, request: dict[str, Any]) -> dict[str, Any]:
        verify_fetch(request)
        digest = str(request.get("object") or "")
        requester = str(request.get("from") or "")
        if requester not in self.shares.get(digest, []):
            raise QNMRefuse("FED-SHARE", "object is not shared with that handle")
        card = self.directory.cards.get(requester)
        if not card:
            raise QNMRefuse("FED-NO-ROUTE", "requester card unknown")
        data = self.store.get(digest)
        try:
            self.policy.hold(data.decode("utf-8"))
        except UnicodeDecodeError:
            pass
        plaintext = {"kind": "object", "object": digest, "content_b64": b64e(data)}
        ph = payload_hash(plaintext)
        if self._writer is None:
            raise QNMRefuse("FED-BOOTSTRAP", "receipt writer is not bound")
        receipt = self._writer("fedmesh_share", {"object": digest, "with": requester, "payload_hash": ph})
        inner = {
            "plaintext": plaintext,
            "projection": projection_of(receipt),
            "anchor": receipt["mesh"],
            "prefix": self.ledger.prefix(self.owner.handle)[-PREFIX_CAP:],
        }
        env = seal_envelope(
            private_key=self.owner.sign_private,
            box_private=self.owner.box_private,
            sender=self.owner.card,
            recipient_card=card,
            seq=int(receipt["mesh"]["seq"]),
            prev=str(receipt["mesh"]["prev"]),
            purpose="msg",
            plaintext=inner,
        )
        self.policy.guard(env, share=True)
        return env

    def sign_rollup(self, actor: Actor, changes: list[dict[str, Any]]) -> dict[str, Any]:
        self._hash_changes(changes)
        ident = self._signer(actor)
        batch = rollup_batch_hash(changes)
        if self._writer is None:
            raise QNMRefuse("FED-BOOTSTRAP", "receipt writer is not bound")
        receipt = self._writer("fedmesh_rollup", {"batch_hash": batch}, signer=ident)
        return {"ok": True, "anchor": receipt["mesh"], "projection": projection_of(receipt), "batch_hash": batch}

    def build_rollup(self, actor: Actor, changes: list[dict[str, Any]], signers: list[dict[str, Any]]) -> dict[str, Any]:
        self._signer(actor)
        self._hash_changes(changes)
        if not signers:
            signed = self.sign_rollup(actor, changes)
            signers = [{"anchor": signed["anchor"], "projection": signed["projection"]}]
        rollup = make_rollup(changes, signers)
        verify_rollup(rollup)
        return {"ok": True, "rollup": rollup}

    def stage_rollup(self, rollup: dict[str, Any]) -> dict[str, Any]:
        verify_rollup(rollup)
        self.pending_rollups.append(rollup)
        self._fan_cluster(rollup, "/v1/fedmesh/rollup")
        pushed = False
        if self.upstream_enabled and self._fan_relays(rollup, "/v1/fedmesh/rollup"):
            self.pending_rollups = [row for row in self.pending_rollups if row is not rollup]
            pushed = True
        return {"ok": True, "staged": True, "pushed": pushed, "temporal_lock": False, "chainlock_upstream": False}

    def sync(self) -> dict[str, Any]:
        refs_left = self.flush_refs()
        rollups_left = []
        for rollup in list(self.pending_rollups):
            if self.upstream_enabled and self._fan_relays(rollup, "/v1/fedmesh/rollup"):
                continue
            rollups_left.append(rollup)
        self.pending_rollups = rollups_left
        return {
            "ok": True,
            "refs_pending": len(refs_left),
            "rollups_pending": len(rollups_left),
            "digest": self.engine_digest(),
        }

    def engine_digest(self) -> dict[str, Any]:
        _seq, tip = self.ledger.tip(self.owner.handle)
        refs = [
            {"handle": handle, "ref": ref, "hash": row["hash"], "object": row["object"]}
            for (handle, ref), row in self.refs.tips.items()
            if handle == self.owner.handle
        ]
        return digest_status(handle=self.owner.handle, receipt_tip=tip, refs=refs)

    def _fan_cluster(self, payload: dict[str, Any], suffix: str) -> bool:
        sent = False
        for handle in self.cluster:
            for url in self.directory.addrs.get(handle, []):
                try:
                    self._post(url.rstrip("/") + suffix, payload, share=False)
                    sent = True
                except QNMRefuse as exc:
                    _reraise_transport(exc)
                    continue
        return sent

    def _fan_relays(self, payload: dict[str, Any], suffix: str) -> bool:
        for url in self._ordered_relays():
            try:
                self._post(url.rstrip("/") + suffix, payload, share=False)
            except QNMRefuse as exc:
                _reraise_transport(exc)
                self.down.add(url)
                continue
            self.down.discard(url)
            return True
        return False

    def _hash_changes(self, changes: list[dict[str, Any]]) -> None:
        for change in changes:
            if not isinstance(change, dict):
                raise QNMRefuse("FED-POLICY", "rollup change refused")
            if set(change) - {"kind", "object", "ref"}:
                raise QNMRefuse("FED-POLICY", "rollup changes are hashes only")
            obj = str(change.get("object") or "")
            if len(obj) != 64:
                raise QNMRefuse("FED-POLICY", "rollup object is not a digest")

    def configure_vault(self, m: int, n: int, members: list[str], *, enabled: bool) -> dict[str, Any]:
        if enabled and (m < 1 or n < m or len(members) < n):
            raise QNMRefuse("FED-MULTISIG", "threshold refused")
        self.vault = {"enabled": bool(enabled), "m": int(m), "n": int(n), "members": list(members)}
        self._save_book()
        return self.public_status()

    def _queue_multisig(self, ident: Identity, env: dict[str, Any]) -> dict[str, Any]:
        subject = envelope_id(env)
        if ident.handle not in self.vault["members"]:
            raise QNMRefuse("FED-MULTISIG", "signer is not a vault member")
        approval = sign_multisig(
            ident.sign_private,
            ident.handle,
            str(ident.card["sign_pub"]),
            subject,
            int(self.vault["m"]),
            int(self.vault["n"]),
        )
        prop = self.proposals.setdefault(subject, {"env": env, "approvals": []})
        if all(row.get("handle") != ident.handle for row in prop["approvals"]):
            prop["approvals"].append(approval)
        try:
            verify_multisig(prop["approvals"], subject, int(self.vault["m"]), int(self.vault["n"]))
        except QNMRefuse as exc:
            if exc.code != "FED-MULTISIG":
                raise
            return {
                "ok": True,
                "pending": True,
                "have": len(prop["approvals"]),
                "need": self.vault["m"],
                "subject": subject,
            }
        routed = self._route(env, share=True)
        routed["multisig"] = prop["approvals"]
        routed["pending"] = False
        return routed

    def approve(self, actor: Actor, subject: str) -> dict[str, Any]:
        ident = self._signer(actor)
        prop = self.proposals.get(subject)
        if not prop:
            raise QNMRefuse("FED-MULTISIG", "unknown proposal")
        if ident.handle not in self.vault["members"]:
            raise QNMRefuse("FED-MULTISIG", "signer is not a vault member")
        approval = sign_multisig(
            ident.sign_private,
            ident.handle,
            str(ident.card["sign_pub"]),
            subject,
            int(self.vault["m"]),
            int(self.vault["n"]),
        )
        if all(row.get("handle") != ident.handle for row in prop["approvals"]):
            prop["approvals"].append(approval)
        try:
            verify_multisig(prop["approvals"], subject, int(self.vault["m"]), int(self.vault["n"]))
        except QNMRefuse as exc:
            if exc.code != "FED-MULTISIG":
                raise
            return {"ok": True, "pending": True, "have": len(prop["approvals"]), "need": self.vault["m"]}
        routed = self._route(prop["env"], share=True)
        routed["pending"] = False
        routed["multisig"] = prop["approvals"]
        return routed

    def announce_peers(self, targets: list[tuple[str, int]]) -> dict[str, Any]:
        if not self.lan_on:
            raise QNMRefuse("FED-DISCOVERY-OFF", "LAN discovery is off")
        peers = []
        for handle, card in self.directory.cards.items():
            row = dict(card)
            row["addrs"] = list(self.directory.addrs.get(handle) or [])
            if self.base_url and handle == self.owner.handle and self.base_url not in row["addrs"]:
                row["addrs"].append(self.base_url)
            peers.append(row)
        card = sign_peer_list(
            self.owner.sign_private,
            sender_handle=self.owner.handle,
            sign_pub=str(self.owner.card["sign_pub"]),
            relays=list(self.relay_urls)[:8],
            peers=peers[:32],
        )
        raw = canonical(card)
        if self.lan is None:
            self.lan = LanSocket()
        sent = self.lan.announce(raw, targets)
        return {"ok": True, "sent": sent, "port": self.lan.port}

    def listen_lan(self) -> LanSocket:
        if not self.lan_on:
            raise QNMRefuse("FED-DISCOVERY-OFF", "LAN discovery is off")
        if self.lan is None:
            self.lan = LanSocket()
        return self.lan

    def ingest_lan(self, raw: bytes) -> dict[str, Any]:
        if len(raw) > 8192:
            raise QNMRefuse("FED-POISON", "announcement exceeds the byte cap")
        try:
            card = json.loads(raw.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            raise QNMRefuse("FED-POISON", "announcement is not a signed peer list") from exc
        if not isinstance(card, dict):
            raise QNMRefuse("FED-POISON", "announcement is not a signed peer list")
        result = self.directory.merge_peer_list(card)
        sender = str(card.get("from") or "")
        if sender:
            self.cluster.add(sender)
        return result

    def _apply_ref(self, update: dict[str, Any]) -> dict[str, Any]:
        try:
            return self.refs.apply(update)
        except QNMRefuse as exc:
            if exc.code == "FED-FORK":
                self.peers.equivocation.add(str(update.get("handle") or ""))
            raise

    def _append_private(self, path: Path, row: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

    def _local_act(self, kind: str, fields: dict[str, Any], ident: Identity | None = None) -> dict[str, Any]:
        signer = ident or self.owner
        self.guard_seq += 1
        statement = local_statement(
            signer.sign_private,
            handle=signer.handle,
            kind=kind,
            fields=fields,
            seq=self.guard_seq,
            prev=self.guard_prev,
        )
        verify_statement(statement)
        self.guard_prev = sha256_hex(canonical({key: value for key, value in statement.items() if key != "sig"}))
        self._append_private(self.root / "data" / "fedmesh" / "local-statements.jsonl", statement)
        if self._writer is not None:
            self._writer(
                "fedmesh_" + kind,
                {"kind": kind, "statement_hash": self.guard_prev, "executed": False},
            )
        return statement

    def quarantine_peer(self, peer: str, *, cut: bool) -> dict[str, Any]:
        if not str(peer).startswith("#"):
            raise QNMRefuse("FED-TAMPER", "quarantine peer handle refused")
        if cut:
            self.peers.quarantine.add(peer)
        else:
            self.peers.quarantine.discard(peer)
        self._local_act("quarantine", {"peer": peer, "action": "cut" if cut else "restore"})
        self._save_book()
        return {"ok": True, "peer": peer, "quarantined": cut, "network_wide": False}

    def enter_island(self) -> dict[str, Any]:
        if not self.island:
            self._island_saved = {
                "relays": list(self.relay_urls),
                "upstream": self.upstream_enabled,
                "direct": self.direct_on,
                "cluster": sorted(self.cluster),
                "addrs": {key: list(value) for key, value in self.directory.addrs.items()},
                "two_hop": dict(self.two_hop),
            }
            self.island = True
            self.relay_urls = []
            self.upstream_enabled = False
            self.direct_on = False
            self.two_hop = dict(self.two_hop)
            self.two_hop["enabled"] = False
            self.cluster.clear()
            self.directory.addrs = {}
            self._local_act("island", {"mode": "on"})
            self._save_book()
        status = self.public_status()
        status["local_runtime"] = True
        return status

    def leave_island(self) -> dict[str, Any]:
        if self.isolated_local:
            raise QNMRefuse("FED-ISOLATED", "isolation keeps this node off the mesh")
        saved = self._island_saved or {}
        self.relay_urls = [str(url) for url in list(saved.get("relays") or [])]
        self.upstream_enabled = bool(saved.get("upstream", True))
        self.direct_on = bool(saved.get("direct", False))
        self.cluster = set(saved.get("cluster") or [])
        self.directory.addrs = {key: list(value) for key, value in dict(saved.get("addrs") or {}).items()}
        if isinstance(saved.get("two_hop"), dict):
            self.two_hop = dict(saved["two_hop"])
        self.island = False
        self._local_act("island", {"mode": "off"})
        self._save_book()
        synced = self.sync()
        status = self.public_status()
        status["resync"] = synced
        return status

    def enable_two_hop(self, entry: str, exit_url: str, exit_handle: str) -> dict[str, Any]:
        if not entry or not exit_url or exit_handle not in self.directory.cards:
            raise QNMRefuse("FED-NO-ROUTE", "two-hop needs an entry URL, an exit URL, and the exit card")
        self.two_hop = {
            "enabled": True,
            "entry": entry.rstrip("/"),
            "exit": exit_url.rstrip("/"),
            "exit_handle": exit_handle,
        }
        self._save_book()
        return self.public_status()

    def _route_two_hop(self, ident: Identity, env: dict[str, Any]) -> dict[str, Any]:
        exit_handle = str(self.two_hop.get("exit_handle") or "")
        exit_card = self.directory.cards.get(exit_handle)
        recipient = str(env.get("to") or "")
        recipient_card = self.directory.cards.get(recipient)
        if not exit_card or not recipient_card:
            raise QNMRefuse("FED-NO-ROUTE", "two-hop is missing a card")
        hop = wrap_two_hop(
            ident.sign_private,
            origin=ident.handle,
            exit_handle=exit_handle,
            exit_box=b64d(str(exit_card.get("box_pub") or "")),
            recipient=recipient,
            recipient_box=b64d(str(recipient_card.get("box_pub") or "")),
            envelope=env,
            seq=int(env.get("seq") or 0),
            prev=str(env.get("prev") or ""),
        )
        self._post(str(self.two_hop["entry"]) + "/v1/fedmesh/hop", hop, share=True)
        return {
            "ok": True,
            "path": "two-hop",
            "e2e": True,
            "entry_sees_payload": False,
            "exit_sees_origin": False,
        }

    def accept_hop(self, hop: dict[str, Any]) -> dict[str, Any]:
        if hop.get("kind") != "hop" or "ciphertext" not in hop:
            raise QNMRefuse("FED-TAMPER", "hop envelope refused")
        verify_statement(hop)
        self._hop_queue.append(hop)
        self._append_private(self.root / "data" / "fedmesh" / "hops-outer.jsonl", hop)
        return {"ok": True, "stored": True, "opened": False, "kind": "hop"}

    def take_hops(self, handle: str) -> list[dict[str, Any]]:
        kept: list[dict[str, Any]] = []
        views: list[dict[str, Any]] = []
        for hop in self._hop_queue:
            if str(hop.get("to") or "") == handle:
                views.append(hop_exit_view(hop))
            else:
                kept.append(hop)
        self._hop_queue = kept
        return views

    def pull_hops(self) -> list[dict[str, Any]]:
        opened: list[dict[str, Any]] = []
        for url in self.hop_sources:
            res = self._get(url + "/v1/fedmesh/hop?handle=" + quote(self.owner.handle, safe=""))
            for view in list(res.get("hops") or []):
                if not isinstance(view, dict) or view.get("kind") != "hop-exit":
                    continue
                self.delivered_hop_views.append(view)
                raw = open_layer(
                    self.owner.box_private,
                    hop_info(self.owner.handle, int(view.get("seq") or 0)),
                    view,
                )
                blind = json.loads(raw.decode("utf-8"))
                if not isinstance(blind, dict) or blind.get("kind") != "blind":
                    raise QNMRefuse("FED-TAMPER", "hop layer was not a blind envelope")
                if "handle" in blind or "from" in blind:
                    raise QNMRefuse("FED-TAMPER", "exit hop layer carried an origin")
                recipient = str(blind.get("to") or "")
                self._blinds.setdefault(recipient, []).append(blind)
                self._append_private(self.root / "data" / "fedmesh" / "blinds.jsonl", blind)
                opened.append({"to": recipient, "seq": blind.get("seq")})
        return opened

    def take_blinds(self, handle: str) -> list[dict[str, Any]]:
        return list(self._blinds.pop(handle, []))

    def pull_blinds(self) -> list[dict[str, Any]]:
        got: list[dict[str, Any]] = []
        for url in self.hop_sources:
            res = self._get(url + "/v1/fedmesh/blind?handle=" + quote(self.owner.handle, safe=""))
            for blind in list(res.get("blinds") or []):
                if not isinstance(blind, dict):
                    continue
                raw = open_layer(
                    self.owner.box_private,
                    blind_info(self.owner.handle, int(blind.get("seq") or 0)),
                    blind,
                )
                env = json.loads(raw.decode("utf-8"))
                if isinstance(env, dict):
                    got.append(self.ingest(env))
        return got

    def trust_view(self, peer: str) -> dict[str, Any]:
        anchors = self.ledger.prefix(peer)
        age = None
        if anchors:
            try:
                from datetime import datetime, timezone

                stamp = datetime.strptime(str(anchors[0].get("utc") or ""), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                age = int((datetime.now(timezone.utc) - stamp).total_seconds())
            except ValueError:
                age = None
        view = {
            "ok": True,
            "peer": peer,
            "chain_length": len(anchors),
            "chain_age_s": age,
            "heartbeats": self.peers.heartbeats.get(peer, 0),
            "hash_matches": self.peers.hash_matches.get(peer, 0),
            "vouches": 1 if peer in self.peers.vouches else 0,
            "equivocation": peer in self.peers.equivocation,
            "advisory": peer in self.peers.advisory_flags,
            "quarantined": peer in self.peers.quarantine,
        }
        return view

    def subscribe_advisory(self, statement: dict[str, Any]) -> dict[str, Any]:
        verify_statement(statement)
        if statement.get("kind") != "advisory":
            raise QNMRefuse("FED-TAMPER", "advisory kind refused")
        entries = statement.get("entries")
        if not isinstance(entries, list) or len(entries) > 32:
            raise QNMRefuse("FED-POISON", "advisory list refused")
        flagged: list[str] = []
        for row in entries:
            if not isinstance(row, dict):
                raise QNMRefuse("FED-POISON", "advisory entry refused")
            if "score" in row:
                raise QNMRefuse("FED-POLICY", "advisories have no score")
            peer = str(row.get("peer") or "")
            if not peer.startswith("#") or len(str(row.get("note") or "")) > 200:
                raise QNMRefuse("FED-POISON", "advisory entry refused")
            flagged.append(peer)
        self.peers.advisories = [row for row in self.peers.advisories if row.get("handle") != statement.get("handle")]
        self.peers.advisories.append(statement)
        self.peers.advisory_flags = set()
        for row in self.peers.advisories:
            for entry in row.get("entries") or []:
                if isinstance(entry, dict):
                    self.peers.advisory_flags.add(str(entry.get("peer") or ""))
        self._save_book()
        return {"ok": True, "publisher": statement.get("handle"), "flagged": flagged, "affects": "subscriber"}

    def vouch_peer(self, peer: str) -> dict[str, Any]:
        if not peer.startswith("#"):
            raise QNMRefuse("FED-TAMPER", "vouch handle refused")
        statement = self._local_act("vouch", {"peer": peer})
        self.peers.vouches[peer] = {"handle": statement.get("handle"), "peer": peer}
        self._save_book()
        return {"ok": True, "peer": peer, "local_only": True}

    def promote_airlock(self, actor: Actor, digest: str, *, override: bool) -> dict[str, Any]:
        if override and actor.role != "admin":
            raise QNMRefuse("FED-ROLE", "scanner override is admin only")
        report = self.airlock.scan(digest)
        if report["infected"]:
            raise QNMRefuse("FED-AIRLOCK", "scanner reported a match")
        if report["scanner_absent"] and not override:
            raise QNMRefuse("FED-AIRLOCK", "scanner absent; promotion needs an explicit operator override")
        data = self.airlock.read(digest)
        self.store.put(data)
        ident = self._signer(actor)
        self.objects_owner[digest] = ident.handle
        if self._writer is not None:
            self._writer(
                "fedmesh_airlock",
                {
                    "object": digest,
                    "override": bool(override and report["scanner_absent"]),
                    "scanners": report["scanners"],
                    "executed": False,
                },
                signer=ident,
            )
        self._save_book()
        return {
            "ok": True,
            "promoted": True,
            "object": digest,
            "executed": False,
            "scanners": report["scanners"],
            "override": bool(override and report["scanner_absent"]),
        }

    def export_airgap(self, dest: str, digests: list[Any]) -> dict[str, Any]:
        folder = Path(dest)
        folder.mkdir(parents=True, exist_ok=True)
        files: list[tuple[str, bytes]] = []
        for digest in digests:
            key = str(digest)
            data = self.store.get(key) if self.store.has(key) else self.airlock.read(key)
            (folder / key).write_bytes(data)
            os.chmod(folder / key, stat.S_IRUSR | stat.S_IWUSR)
            files.append((key, data))
        manifest = sha256sums_text(files)
        (folder / "SHA256SUMS").write_text(manifest, encoding="utf-8")
        statement = self._local_act(
            "airgap",
            {
                "manifest_sha256": sha256_hex(manifest.encode("utf-8")),
                "files": [{"name": name, "sha256": sha256_hex(data)} for name, data in files],
            },
        )
        (folder / "airgap.json").write_text(json.dumps(statement, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        os.chmod(folder / "airgap.json", stat.S_IRUSR | stat.S_IWUSR)
        return {"ok": True, "dest": str(folder), "files": len(files), "sha256sum": True, "live": False}

    def import_airgap(self, src: str) -> dict[str, Any]:
        folder = Path(src)
        statement = json.loads((folder / "airgap.json").read_text(encoding="utf-8"))
        verify_statement(statement)
        if statement.get("kind") != "airgap":
            raise QNMRefuse("FED-TAMPER", "airgap statement refused")
        manifest = (folder / "SHA256SUMS").read_text(encoding="utf-8")
        if sha256_hex(manifest.encode("utf-8")) != statement.get("manifest_sha256"):
            raise QNMRefuse("FG-GATE-REFUSE", "airgap manifest hash mismatch")
        checked = check_sha256sums(manifest, folder)
        landed = []
        for row in checked:
            data = (folder / row["name"]).read_bytes()
            self.airlock.land(data, claimed=row["sha256"])
            landed.append(row["sha256"])
        return {"ok": True, "landed": landed, "promoted": False, "verified": True, "live": False}

    def design_page(self, peer: str) -> dict[str, Any]:
        self._require_local(peer)
        unlocked = self.owner.handle in self._design_open
        return {
            "ok": True,
            "html": page_html(handle=self.owner.handle, unlocked=unlocked),
            "unlocked": unlocked,
            "remote": False,
            "slots": self.design.public_slots(),
            "enabled_by_get": False,
        }

    def design_status(self, actor: Actor, peer: str) -> dict[str, Any]:
        self._require_local(peer)
        unlocked = actor.handle in self._design_open
        body: dict[str, Any] = {
            "ok": True,
            "handle": actor.handle,
            "self_name": self_name(actor.handle),
            "unlocked": unlocked,
            "remote": False,
            "slots": self.design.public_slots(),
            "ethics": self.ethics.status(),
            "isolated": actor.handle in self.isolated_local,
            "enabled_by_get": False,
        }
        if unlocked and actor.role != "guest":
            body["drafts"] = self.design.load(actor.handle)
        return body

    def design_challenge(self, actor: Actor, peer: str) -> dict[str, Any]:
        self._require_local(peer)
        if actor.role == "guest":
            raise QNMRefuse("FED-ROLE", "guest cannot unlock design mode")
        nonce = secrets.token_hex(16)
        self._design_nonces[actor.handle] = nonce
        return {"ok": True, "handle": actor.handle, "nonce": nonce, "unlocked": False}

    def design_unlock(self, actor: Actor, sig: str, public_key: str, peer: str) -> dict[str, Any]:
        self._require_local(peer)
        ident = self._signer(actor)
        nonce = self._design_nonces.get(ident.handle)
        if not nonce:
            raise QNMRefuse("FED-PASSPHRASE", "design mode needs a fresh challenge")
        statement = {
            "v": "FED-MESH-1.0",
            "kind": "design-unlock",
            "author": AUTHOR,
            "handle": ident.handle,
            "public_key": public_key,
            "nonce": nonce,
            "sig": sig,
        }
        verify_statement(statement)
        if signing_public_b64url(ident.sign_private) != public_key:
            raise QNMRefuse("FED-WRONG-KEY", "design unlock key does not match the handle")
        self._design_nonces.pop(ident.handle, None)
        self._design_open.add(ident.handle)
        return {"ok": True, "handle": ident.handle, "unlocked": True, "remote": False}

    def design_put(self, actor: Actor, payload: dict[str, Any], peer: str) -> dict[str, Any]:
        ident = self._require_design(actor, peer)
        blocks = payload.get("blocks")
        cleaned = None
        if isinstance(blocks, list):
            verdict, cleaned = _prepare_blocks(self, blocks)
            if verdict is not None:
                document = draft_document(
                    handle=ident.handle,
                    slot=int(payload.get("slot") or 0),
                    label=str(payload.get("label") or ""),
                    template=str(payload.get("template") or "blank"),
                    theme=str(payload.get("theme") or "night"),
                    blocks=[{"type": "text", "text": "removed"}],
                )
                document["blocks"] = [{"type": "image", "sha256": verdict.get("input_sha256"), "removed": True}]
                self._ethics_violation(ident, document, verdict)
        document = draft_document(
            handle=ident.handle,
            slot=int(payload.get("slot") or 0),
            label=str(payload.get("label") or ""),
            template=str(payload.get("template") or "blank"),
            theme=str(payload.get("theme") or "night"),
            blocks=cleaned,
        )
        self.design.save(ident.handle, document)
        return {"ok": True, "slot": document["slot"], "label": document["label"], "published": False}

    def design_move(self, actor: Actor, payload: dict[str, Any], peer: str) -> dict[str, Any]:
        ident = self._require_design(actor, peer)
        document = move_block(
            self.design.get(ident.handle, int(payload.get("slot") or 0)),
            int(payload.get("from") if payload.get("from") is not None else 0),
            int(payload.get("to") if payload.get("to") is not None else 0),
        )
        self.design.save(ident.handle, document)
        return {"ok": True, "slot": document["slot"], "blocks": len(document["blocks"])}

    def design_preview(self, actor: Actor, slot: int, peer: str) -> dict[str, Any]:
        ident = self._require_design(actor, peer)
        document = self.design.get(ident.handle, slot)
        page = preview_html(document)
        return {"ok": True, "html": page, "published": False, "label": document["label"], "theme": document["theme"]}

    def design_publish(self, actor: Actor, slot: int, peer: str, *, override: bool) -> dict[str, Any]:
        ident = self._require_design(actor, peer)
        document = self.design.get(ident.handle, slot)
        texts = collect_texts(document)
        images = []
        for digest in image_hashes(document):
            if not self.airlock.has(digest):
                raise QNMRefuse("FG-GATE-REFUSE", "design image is not in the airlock")
            images.append(self.airlock.read(digest))
        try:
            verdict = self.ethics.check(texts=texts, images=images)
        except QNMRefuse:
            raise
        if not verdict.get("ok"):
            self._ethics_violation(ident, document, verdict)
        if self._writer is not None:
            self._writer(
                "fedmesh_ethics",
                {
                    "verdict": "clear",
                    "models": verdict.get("models"),
                    "content_stored": False,
                    "catches_everything": False,
                },
                signer=ident,
            )
        for digest in image_hashes(document):
            self.promote_airlock(actor, digest, override=override)
        raw = site_bytes(document)
        landed = self.airlock.land(raw)
        self.promote_airlock(actor, landed["sha256"], override=override)
        update = self.push_ref(actor, str(document["label"]), landed["sha256"])
        document["published"] = True
        self.design.save(ident.handle, document)
        return {
            "ok": True,
            "published": True,
            "object": landed["sha256"],
            "ref": document["label"],
            "ref_seq": update.get("seq"),
            "ethics": "clear",
            "content_in_receipt": False,
        }

    def appeal(self, actor: Actor, peer: str) -> dict[str, Any]:
        ident = self._require_design(actor, peer)
        row = self.isolated_local.get(ident.handle)
        if not row:
            raise QNMRefuse("FED-ISOLATED", "this handle is not isolated")
        statement = self._local_act(
            "appeal",
            {
                "subject_hash": row.get("statement_hash"),
                "reason": row.get("reason"),
                "request": "recheck",
            },
            ident=ident,
        )
        recheck: dict[str, Any] = {"ran": False, "lifted": False}
        if row.get("reason") == "ETHICS-CHILD-IMAGE":
            recheck["reason"] = "hash-only"
        elif self.ethics.status()["absent"]:
            recheck["reason"] = "model-absent"
        else:
            recheck = {"ran": True, "lifted": False, "reason": "review-does-not-lift"}
        return {
            "ok": True,
            "appeal": statement.get("kind"),
            "recheck": recheck,
            "lifted": False,
            "isolated": True,
            "content_stored": False,
            "reports_filed": False,
        }

    def accept_isolation(self, statement: dict[str, Any]) -> dict[str, Any]:
        verify_statement(statement)
        if statement.get("kind") != "isolation":
            raise QNMRefuse("FED-TAMPER", "isolation statement kind refused")
        if statement.get("handle") != statement.get("subject"):
            raise QNMRefuse("FED-POLICY", "only the handle can sign its own isolation")
        if statement.get("content_stored") is not False:
            raise QNMRefuse("FED-POLICY", "isolation records do not carry content")
        if _has_content_key(statement):
            raise QNMRefuse("FED-POLICY", "isolation records do not carry content")
        evidence = str(statement.get("evidence") or "")
        if len(evidence) != 64:
            raise QNMRefuse("FED-TAMPER", "isolation evidence hash refused")
        self.isolated_seen[str(statement["subject"])] = {
            "reason": statement.get("reason"),
            "evidence": evidence,
            "content_stored": False,
        }
        self._save_book()
        return {"ok": True, "subject": statement.get("subject"), "network_wide": False, "stored_content": False}

    def _require_local(self, peer: str) -> None:
        host = str(peer or "").split("%", 1)[0].strip("[]")
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise QNMRefuse("FG-GATE-REFUSE", "design mode refuses remote access")

    def _require_design(self, actor: Actor, peer: str) -> Identity:
        self._require_local(peer)
        if actor.role == "guest":
            raise QNMRefuse("FED-ROLE", "guest cannot edit design mode")
        ident = self._signer(actor)
        if ident.handle not in self._design_open:
            raise QNMRefuse("FED-PASSPHRASE", "design mode requires the handle key unlock")
        return ident

    def _ethics_violation(self, ident: Identity, document: dict[str, Any], verdict: dict[str, Any]) -> None:
        reason = str(verdict.get("reason") or "")
        if reason == "ETHICS-CHILD-IMAGE":
            for digest in image_hashes(document):
                self.airlock.drop(digest)
            kept = []
            for block in document.get("blocks") or []:
                if block.get("type") == "image":
                    kept.append({"type": "image", "sha256": block.get("sha256"), "removed": True})
                elif block.get("type") == "gallery":
                    kept.append({"type": "gallery", "images": list(block.get("images") or []), "removed": True})
                else:
                    kept.append(block)
            document["blocks"] = kept
            self.design.save(ident.handle, document)
        statement = self._local_act(
            "isolation",
            {
                "subject": ident.handle,
                "reason": reason,
                "evidence": verdict.get("evidence"),
                "content_stored": False,
                "chainlock": False,
                "temporal_lock": False,
            },
            ident=ident,
        )
        digest = sha256_hex(canonical({key: value for key, value in statement.items() if key != "sig"}))
        self.isolated_local[ident.handle] = {
            "reason": reason,
            "evidence": verdict.get("evidence"),
            "statement_hash": digest,
            "content_stored": False,
            "chainlock": False,
            "temporal_lock": False,
        }
        self.enter_island()
        self.relay_on = False
        if self._writer is not None:
            self._writer(
                "fedmesh_ethics",
                {
                    "verdict": "refuse",
                    "reason": reason,
                    "evidence": verdict.get("evidence"),
                    "model": verdict.get("model"),
                    "version": verdict.get("version"),
                    "content_stored": False,
                    "catches_everything": False,
                },
                signer=ident,
            )
        self._save_book()
        raise QNMRefuse("FED-ETHICS", reason)

    def _inbox_for(self, actor: Actor) -> dict[str, Any]:
        if actor.role == "guest":
            rows = [{"from": row["from"], "kind": row["kind"], "id": row["id"]} for row in self.inbox]
            return {"ok": True, "inbox": rows, "redacted": True}
        if actor.handle != self.owner.handle and actor.role != "admin":
            raise QNMRefuse("FED-TENANT", "inbox is the host identity's")
        if actor.role == "admin" and actor.handle != self.owner.handle:
            raise QNMRefuse("FED-TENANT", "admin cannot read another inbox")
        return {"ok": True, "inbox": list(self.inbox)}

    def _write_inbox(self) -> None:
        path = self.root / "data" / "fedmesh" / "inbox.jsonl"
        lines = [json.dumps(row, sort_keys=True, separators=(",", ":")) for row in self.inbox]
        path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

    def _book_path(self) -> Path:
        return self.root / "data" / "fedmesh" / "book.json"

    def _save_book(self) -> None:
        payload = {
            "tenants": self.tenants,
            "tokens": self.tokens,
            "shares": self.shares,
            "objects_owner": self.objects_owner,
            "vault": self.vault,
            "quarantine": sorted(self.peers.quarantine),
            "island": self.island,
            "isolated_local": self.isolated_local,
            "isolated_seen": self.isolated_seen,
            "island_saved": self._island_saved,
            "guard_seq": self.guard_seq,
            "guard_prev": self.guard_prev,
            "two_hop": self.two_hop,
            "advisories": self.peers.advisories,
            "vouches": self.peers.vouches,
            "equivocation": sorted(self.peers.equivocation),
        }
        path = self._book_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

    def _load_book(self) -> None:
        path = self._book_path()
        if not path.is_file():
            return
        data = json.loads(path.read_text(encoding="utf-8"))
        self.tenants = dict(data.get("tenants") or {})
        self.tokens = dict(data.get("tokens") or {})
        self.shares = {key: list(value) for key, value in dict(data.get("shares") or {}).items()}
        self.objects_owner = dict(data.get("objects_owner") or {})
        vault = data.get("vault") or {}
        if isinstance(vault, dict):
            self.vault = {
                "enabled": bool(vault.get("enabled")),
                "m": int(vault.get("m") or 0),
                "n": int(vault.get("n") or 0),
                "members": list(vault.get("members") or []),
            }
        for handle, row in self.tenants.items():
            if isinstance(row, dict) and isinstance(row.get("card"), dict):
                self.directory.remember_card(row["card"])
            self.quotas.setdefault(handle, _Quota())
        self.peers.quarantine = set(data.get("quarantine") or [])
        self.island = bool(data.get("island"))
        local_rows = data.get("isolated_local") or {}
        seen_rows = data.get("isolated_seen") or {}
        self.isolated_local = dict(local_rows) if isinstance(local_rows, dict) else {}
        self.isolated_seen = dict(seen_rows) if isinstance(seen_rows, dict) else {}
        if self.isolated_local:
            self.island = True
        saved = data.get("island_saved")
        self._island_saved = saved if isinstance(saved, dict) else None
        self.guard_seq = int(data.get("guard_seq") or 0)
        self.guard_prev = str(data.get("guard_prev") or ("0" * 64))
        if isinstance(data.get("two_hop"), dict):
            self.two_hop = dict(data["two_hop"])
        self.peers.advisories = list(data.get("advisories") or [])
        self.peers.advisory_flags = set()
        for row in self.peers.advisories:
            for entry in row.get("entries") or []:
                if isinstance(entry, dict):
                    self.peers.advisory_flags.add(str(entry.get("peer") or ""))
        vouches = data.get("vouches") or {}
        if isinstance(vouches, dict):
            self.peers.vouches = dict(vouches)
        self.peers.equivocation = set(data.get("equivocation") or [])
        if self.island:
            self.cluster.clear()
            self.directory.addrs = {}
