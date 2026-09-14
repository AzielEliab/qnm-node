"""COLD-COPY SURVIVAL — mesh law (Aziel Eliab only).

Make a tip expensive to erase by multiplying cold copies and refusing
live sync of bodies across the network.

  • N cold replicas: MESH-VAULT on transfer, reader local vaults,
    optional pin of already-public tip / receipt hashes.
  • Pulling origin / Worker / DNS does not erase cold copies.
  • Public rollup may die with the pull; records remain on cold copies
    plus local verify / append.
  • Hash-absolute fail-closed ingest. No live body sync that could
    spray poison. Majority cannot outvote a broken hash.
  • Tips / receipts / vault tips are content-addressed. Local node
    keeps verifying / appending without the creator online.
  • Named hosts only. No unmarked hydra. No VPN concealment.

Companion: SPLIT-WIRES-1.0 (pull-only payload plane).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from qnm.boot import AUTHOR, SPEC, QNMRefuse, _utc_now, sha256_hex
from qnm.nolie import is_tunnel_host
from qnm.wires import HASH_LEN, WIRES_SPEC, canonical_hash

COLD_SPEC = "COLD-COPY-1.0"
DEFAULT_N = 3
NAMED_HOST_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")
DEVICE_CLASSES = (
    "laptop",
    "phone",
    "apple-watch",
    "phone-watch",
    "radio",
    "bluetooth",
)
FORBIDDEN_HOSTS = frozenset(
    {
        "*",
        "+",
        "any",
        "hydra",
        "unmarked",
        "vpn",
        "tor",
        "mixnet",
        "onion",
        "conceal",
    }
)


class ColdCopy:
    """Content-addressed local vault. Cold replicas. No live body sync."""

    def __init__(self, root: Path, *, replica_n: int = DEFAULT_N) -> None:
        self.root = Path(root)
        self.replica_n = max(int(replica_n), 1)
        self.objects = self.root / "data" / "vault" / "objects"
        self.replica_path = self.root / "data" / "vault" / "replicas.jsonl"
        self.pin_path = self.root / "data" / "vault" / "pins.jsonl"
        self.objects.mkdir(parents=True, exist_ok=True)
        self.replica_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.replica_path.is_file():
            self.replica_path.write_text("", encoding="utf-8")
        if not self.pin_path.is_file():
            self.pin_path.write_text("", encoding="utf-8")
        self.origin_alive = True
        self.worker_alive = True
        self.dns_alive = True
        self.named_hosts: set[str] = {"local", "mesh-vault", "reader", *DEVICE_CLASSES}

    def status(self) -> dict[str, Any]:
        replicas = self.replicas()
        return {
            "ok": True,
            "spec": COLD_SPEC,
            "companion": WIRES_SPEC,
            "build": SPEC,
            "author": AUTHOR,
            "replica_n": self.replica_n,
            "objects": len(list(self.objects.glob("*"))),
            "replicas": len(replicas),
            "pins": len(self.pins()),
            "origin_alive": self.origin_alive,
            "worker_alive": self.worker_alive,
            "dns_alive": self.dns_alive,
            "die_with_pull": not (self.origin_alive or self.worker_alive or self.dns_alive),
            "live_body_sync": False,
            "named_hosts_only": True,
            "unmarked_hydra": False,
            "vpn_concealment": False,
            "creator_session_required": False,
            "copies_one_tunnel": False,
            "device_classes": list(DEVICE_CLASSES),
            "persist_across_devices": True,
        }

    def _append(self, path: Path, row: dict[str, Any]) -> dict[str, Any]:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
            fh.flush()
        return row

    def _read_jsonl(self, path: Path) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        if not path.is_file():
            return items
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                items.append(json.loads(line))
        return items

    def replicas(self) -> list[dict[str, Any]]:
        return self._read_jsonl(self.replica_path)

    def pins(self) -> list[dict[str, Any]]:
        return self._read_jsonl(self.pin_path)

    def declare_host(self, name: str) -> str:
        host = self._named_host(name)
        self.named_hosts.add(host)
        return host

    def _named_host(self, name: str) -> str:
        host = str(name or "").strip()
        lowered = host.lower()
        if not host or lowered in FORBIDDEN_HOSTS:
            raise QNMRefuse("QNM-COLD-NAMED-HOSTS", "named hosts only; no unmarked hydra")
        if "vpn" in lowered or "conceal" in lowered or lowered.startswith("vpn"):
            raise QNMRefuse("QNM-COLD-NO-VPN", "no VPN concealment")
        if "hydra" in lowered:
            raise QNMRefuse("QNM-COLD-NAMED-HOSTS", "named hosts only; no unmarked hydra")
        if not NAMED_HOST_RE.match(host):
            raise QNMRefuse("QNM-COLD-NAMED-HOSTS", "named hosts only; no unmarked hydra")
        return host

    def store(self, body: bytes | str, *, host: str = "local") -> dict[str, Any]:
        raw = body.encode("utf-8") if isinstance(body, str) else bytes(body)
        digest = sha256_hex(raw)
        leaf = self.objects / digest
        if not leaf.is_file():
            leaf.write_bytes(raw)
        host_name = self._named_host(host)
        rec = self._place(digest, host_name, kind="local-vault")
        return {
            "ok": True,
            "tip": digest,
            "host": host_name,
            "bytes": len(raw),
            "content_addressed": True,
            "replica": rec,
            "spec": COLD_SPEC,
            "author": AUTHOR,
        }

    def transfer(self, digest: str, host: str = "mesh-vault") -> dict[str, Any]:
        """MESH-VAULT on transfer — a named cold replica, not live sync."""
        tip = self._require_object(digest)
        host_name = self._named_host(host)
        kind = "device-vault" if host_name in DEVICE_CLASSES else "mesh-vault"
        rec = self._place(tip, host_name, kind=kind)
        return {
            "ok": True,
            "tip": tip,
            "host": host_name,
            "kind": kind,
            "live_sync": False,
            "erased": False,
            "spec": COLD_SPEC,
            "author": AUTHOR,
            "replica": rec,
        }

    def persist_across_devices(
        self,
        digest: str,
        devices: tuple[str, ...] | list[str] | None = None,
    ) -> dict[str, Any]:
        """Cold-copy / vault-on-transfer / outbox class for all devices.

        A pull or offline hop does not erase the tip. Named device
        classes only (laptop, phone, watches, radio, bluetooth).
        """
        tip = self._require_object(digest)
        wanted = tuple(devices) if devices else DEVICE_CLASSES
        placed: list[dict[str, Any]] = []
        for host in wanted:
            placed.append(self.transfer(tip, host=host))
        vault = self.transfer(tip, host="mesh-vault")
        reader = self.transfer(tip, host="reader")
        return {
            "ok": True,
            "tip": tip,
            "devices": [row["host"] for row in placed],
            "replicas": self.replica_count(tip),
            "mesh_vault": vault,
            "reader": reader,
            "erased": False,
            "live_sync": False,
            "pull_erases_tip": False,
            "offline_hop_erases_tip": False,
            "spec": COLD_SPEC,
            "author": AUTHOR,
        }

    def pin_public(self, digest: str, *, kind: str = "tip") -> dict[str, Any]:
        """Optional pin of an already-public tip or receipt hash. Hash only."""
        tip = canonical_hash(digest)
        if kind not in ("tip", "receipt"):
            raise QNMRefuse("QNM-COLD-PIN", "pin already-public tip or receipt hashes only")
        rec = {
            "kind": kind,
            "tip": tip,
            "public": True,
            "body": False,
            "utc": _utc_now(),
            "spec": COLD_SPEC,
            "author": AUTHOR,
        }
        self._append(self.pin_path, rec)
        return rec

    def live_sync(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-COLD-NO-LIVE-SYNC",
            "refuse live sync of bodies across the network",
        )

    def unmarked_hydra(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse("QNM-COLD-NAMED-HOSTS", "no unmarked hydra")

    def vpn_conceal(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse("QNM-COLD-NO-VPN", "no VPN concealment")

    def one_tunnel(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-NO-ONE-TUNNEL",
            "copies are not all on one tunnel",
        )

    def hosts_for(self, digest: str) -> set[str]:
        tip = canonical_hash(digest)
        hosts = {str(row["host"]) for row in self.replicas() if row.get("tip") == tip}
        if (self.objects / tip).is_file():
            hosts.add("local")
        return hosts

    def pull_origin(self) -> dict[str, Any]:
        """Public origin / Worker / DNS die with the pull. Cold copies remain."""
        self.origin_alive = False
        self.worker_alive = False
        self.dns_alive = False
        return {
            "ok": True,
            "origin_alive": False,
            "worker_alive": False,
            "dns_alive": False,
            "die_with_pull": True,
            "cold_copies_remain": True,
            "objects": len(list(self.objects.glob("*"))),
            "replicas": len(self.replicas()),
            "pins": len(self.pins()),
            "public_restore": False,
            "spec": COLD_SPEC,
            "author": AUTHOR,
        }

    def verify(
        self,
        digest: str,
        *,
        creator_online: bool = False,
        require_creator: bool = False,
    ) -> dict[str, Any]:
        _ = creator_online
        if require_creator:
            raise QNMRefuse(
                "QNM-COLD-NO-CREATOR",
                "cold verify does not depend on a living operator session",
            )
        tip = self._require_object(digest)
        raw = (self.objects / tip).read_bytes()
        if sha256_hex(raw) != tip:
            raise QNMRefuse("QNM-WIRES-FAIL-CLOSED", "vault tip hash mismatch")
        return {
            "ok": True,
            "tip": tip,
            "verified": True,
            "creator_online": False,
            "creator_required": False,
            "spec": COLD_SPEC,
            "author": AUTHOR,
        }

    def replica_count(self, digest: str) -> int:
        tip = canonical_hash(digest)
        hosts = {row["host"] for row in self.replicas() if row.get("tip") == tip}
        if (self.objects / tip).is_file():
            hosts.add("local")
        return len(hosts)

    def expensive_to_erase(self, digest: str) -> dict[str, Any]:
        n = self.replica_count(digest)
        return {
            "ok": n >= self.replica_n,
            "tip": canonical_hash(digest),
            "replicas": n,
            "required": self.replica_n,
            "single_server_unkillable": n >= 2,
            "spec": COLD_SPEC,
            "author": AUTHOR,
        }

    def _place(self, digest: str, host: str, *, kind: str) -> dict[str, Any]:
        existing = {str(row["host"]) for row in self.replicas() if row.get("tip") == digest}
        after = existing | {host}
        if is_tunnel_host(host) and after.issubset({host}):
            self.one_tunnel()
        if after and all(is_tunnel_host(item) for item in after) and len(after) == 1:
            self.one_tunnel()
        rec = {
            "tip": digest,
            "host": host,
            "kind": kind,
            "live_sync": False,
            "utc": _utc_now(),
            "spec": COLD_SPEC,
            "author": AUTHOR,
        }
        return self._append(self.replica_path, rec)

    def _require_object(self, digest: str) -> str:
        tip = canonical_hash(digest)
        if not (self.objects / tip).is_file():
            raise QNMRefuse("QNM-COLD-MISSING", "no cold object for tip")
        return tip


def assert_hash_len(digest: str) -> str:
    if len(digest) != HASH_LEN:
        raise QNMRefuse("QNM-WIRES-FAIL-CLOSED", "content address is 64 hex")
    return digest
