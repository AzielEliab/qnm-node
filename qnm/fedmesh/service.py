"""Local-first edge mesh on one qnm daemon.

Inner core (keys, objects, tasks) stays on this process. Outbound
posts pass through the policy filter. Cluster peers are preferred.
Relays are a fallback, and any daemon can opt in to be one. The
Worker URL is just a configurable relay, off unless the operator
points at it.

Author: Aziel Eliab only.
"""

from __future__ import annotations

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
from qnm.fedmesh.chain import Ledger
from qnm.fedmesh.discover import Directory, LanSocket
from qnm.fedmesh.identity import Identity, create_keystore, load_or_create_owner, open_keystore
from qnm.fedmesh.objects import ObjectStore, RefLog, digest_status
from qnm.fedmesh.policy import Outbound
from qnm.fedmesh.relay import Spool, http_json
from qnm.fedmesh.sandbox import run_job
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

    def local_op(self, actor: Actor, payload: dict[str, Any]) -> dict[str, Any]:
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
        ident = self._signer(actor)
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
            except QNMRefuse:
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
            except QNMRefuse:
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
        return http_json("POST", url, payload)

    def _get(self, url: str) -> dict[str, Any]:
        if self.transport is not None:
            result = self.transport("GET", url, None)
            if not isinstance(result, dict):
                raise QNMRefuse("FED-NO-ROUTE", "transport refused")
            return result
        return http_json("GET", url)

    def poll(self) -> list[dict[str, Any]]:
        if not self.upstream_enabled:
            return []
        got: list[dict[str, Any]] = []
        for url in self._ordered_relays():
            try:
                res = self._get(url + "/v1/fedmesh/inbox?handle=" + quote(self.owner.handle, safe=""))
            except QNMRefuse:
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
            elif kind == "object":
                raw = b64d(str(plain.get("content_b64") or ""))
                if sha256_hex(raw) != plain.get("object"):
                    raise QNMRefuse("FED-TAMPER", "fetched object hash mismatch")
                self.store.put(raw)
                self.objects_owner[sha256_hex(raw)] = self.owner.handle
            self.seen_envelopes.add(ident_env)
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
                "enabled_by_get": False,
            }
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
            self.refs.apply(payload)
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
        self.refs.apply(update)
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
            except QNMRefuse:
                continue
            if "ct" not in res:
                continue
            inner = open_envelope(ident.box_private, ident.card, res)
            plain = inner.get("plaintext") if isinstance(inner.get("plaintext"), dict) else {}
            raw = b64d(str(plain.get("content_b64") or ""))
            if sha256_hex(raw) != digest:
                raise QNMRefuse("FED-TAMPER", "peer object hash mismatch")
            self.store.put(raw)
            self.objects_owner[digest] = ident.handle
            self._save_book()
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
                except QNMRefuse:
                    continue
        return sent

    def _fan_relays(self, payload: dict[str, Any], suffix: str) -> bool:
        for url in self._ordered_relays():
            try:
                self._post(url.rstrip("/") + suffix, payload, share=False)
            except QNMRefuse:
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
