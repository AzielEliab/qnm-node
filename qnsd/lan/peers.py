"""Operator-pinned peer directory. Discovery does not write this."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from qnm.fedmesh.wire import verify_box_binding
from qnsd.boot import AUTHOR, _utc_now
from qnsd.lan.bind import parse_ip_port
from qnsd.lan.contract import ADAPTER_ID, PACKET_V, LanRefuse
from qnsd.lan.tlsutil import cert_common_name, cert_sha256


class PeerDirectory:
    def __init__(self, root: Path) -> None:
        self.path = Path(root) / "data" / "lan" / "peers.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, stat.S_IRWXU)
        self.peers: dict[str, dict[str, Any]] = {}
        if self.path.is_file():
            self.peers = json.loads(self.path.read_text(encoding="utf-8"))

    def list_public(self) -> list[dict[str, Any]]:
        rows = []
        for row in self.peers.values():
            rows.append(
                {
                    "handle": row["handle"],
                    "key_status": row["key_status"],
                    "addresses": list(row["addresses"]),
                    "adapters": list(row["adapters"]),
                    "cert_sha256": row["cert_sha256"],
                    "last_success_utc": row.get("last_success_utc") or "",
                    "revocation": row.get("revocation"),
                    "route_state": row.get("route_state") or "DISCOVERED",
                }
            )
        return rows

    def get(self, handle: str) -> dict[str, Any]:
        row = self.peers.get(handle)
        if row is None:
            raise LanRefuse("QNS-LAN-IDENTITY", "peer is not pinned", outcome="refused", security=True)
        return row

    def active(self) -> list[dict[str, Any]]:
        return [row for row in self.peers.values() if row.get("key_status") == "active"]

    def add(self, card: dict[str, Any], cert_pem: str, address: str) -> dict[str, Any]:
        verify_box_binding(card)
        handle = str(card["handle"])
        pem = str(cert_pem or "")
        if cert_common_name(pem) != handle:
            raise LanRefuse("QNS-LAN-IDENTITY", "certificate name is not the handle", outcome="refused", security=True)
        host, port = parse_ip_port(address)
        row = {
            "v": PACKET_V,
            "author": AUTHOR,
            "handle": handle,
            "card": {
                "v": card.get("v"),
                "purpose": card.get("purpose"),
                "author": card.get("author"),
                "handle": handle,
                "key_id": card.get("key_id"),
                "sign_pub": card.get("sign_pub"),
                "box_pub": card.get("box_pub"),
                "box_sig": card.get("box_sig"),
            },
            "cert_pem": pem,
            "cert_sha256": cert_sha256(pem),
            "addresses": [f"{host}:{port}"],
            "adapters": [ADAPTER_ID],
            "key_status": "active",
            "last_success_utc": "",
            "revocation": None,
            "route_state": "DISCOVERED",
        }
        self.peers[handle] = row
        self._save()
        return {"ok": True, "handle": handle, "cert_sha256": row["cert_sha256"], "live": False}

    def revoke(self, handle: str, reason: str) -> dict[str, Any]:
        row = self.get(handle)
        row["key_status"] = "revoked"
        row["revocation"] = {"utc": _utc_now(), "reason": str(reason or "operator")[:80]}
        row["route_state"] = "DISCOVERED"
        self._save()
        return {"ok": True, "handle": handle, "key_status": "revoked", "live": False}

    def set_state(self, handle: str, state: str) -> None:
        row = self.peers.get(handle)
        if row is None:
            return
        row["route_state"] = state
        self._save()

    def mark_success(self, handle: str, utc: str) -> None:
        row = self.peers.get(handle)
        if row is None:
            return
        row["last_success_utc"] = utc
        row["route_state"] = "ACKNOWLEDGED"
        self._save()

    def approved_hosts(self, handle: str) -> set[str]:
        row = self.get(handle)
        hosts = set()
        for address in row.get("addresses") or []:
            host, _port = parse_ip_port(str(address))
            hosts.add(host)
        return hosts

    def _save(self) -> None:
        text = json.dumps(self.peers, sort_keys=True, indent=2) + "\n"
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(text, encoding="utf-8")
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        tmp.replace(self.path)
