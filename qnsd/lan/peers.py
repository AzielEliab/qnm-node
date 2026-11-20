"""Operator-pinned peer directory. Discovery does not write this.

The pin is the SHA-256 of the peer signing public key. The 11-character
handle is an alias. A second key does not replace that pin unless the
previous key signs the new card.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from qnm.fedmesh.wire import check_rotation_freshness, verify_box_binding, verify_card_rotation
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
        self.seen_rotations: set[str] = set()
        self._seen_path = self.path.with_name("rotation-seen.json")
        if self.path.is_file():
            self.peers = json.loads(self.path.read_text(encoding="utf-8"))
            self._migrate()
        if self._seen_path.is_file():
            seen = json.loads(self._seen_path.read_text(encoding="utf-8"))
            if isinstance(seen, list):
                self.seen_rotations = {str(item) for item in seen}

    def list_public(self) -> list[dict[str, Any]]:
        rows = []
        for row in self.peers.values():
            rows.append(
                {
                    "handle": row["handle"],
                    "key_id": row["card"]["key_id"],
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

    def _migrate(self) -> None:
        """Re-key a handle-indexed file by the full public-key pin."""
        migrated: dict[str, dict[str, Any]] = {}
        for key, row in list(self.peers.items()):
            if not isinstance(row, dict):
                continue
            card = row.get("card") if isinstance(row.get("card"), dict) else {}
            key_id = str(card.get("key_id") or "")
            if len(key_id) != 64:
                continue
            migrated[key_id] = row
            if key != key_id:
                row["legacy_handle_key"] = str(key)
        if migrated.keys() != self.peers.keys():
            self.peers = migrated
            self._save()

    def get(self, handle: str) -> dict[str, Any]:
        """Return the pin for ``handle``.

        An active pin wins. A single revoked or rotated row is still
        returned so the caller can report that status. Two active pins
        for one handle are a collision and are refused.
        """
        rows = [row for row in self.peers.values() if row.get("handle") == handle]
        active = [row for row in rows if row.get("key_status") == "active"]
        if len(active) > 1:
            raise LanRefuse("QNS-LAN-IDENTITY", "peer handle is not a unique pin", outcome="refused", security=True)
        if len(active) == 1:
            return active[0]
        if len(rows) == 1:
            return rows[0]
        raise LanRefuse("QNS-LAN-IDENTITY", "peer is not pinned", outcome="refused", security=True)

    def get_key(self, key_id: str) -> dict[str, Any]:
        row = self.peers.get(str(key_id or ""))
        if row is None or row.get("key_status") != "active":
            raise LanRefuse("QNS-LAN-IDENTITY", "peer key is not pinned", outcome="refused", security=True)
        return row

    def active(self) -> list[dict[str, Any]]:
        return [row for row in self.peers.values() if row.get("key_status") == "active"]

    def add(self, card: dict[str, Any], cert_pem: str, address: str) -> dict[str, Any]:
        verify_box_binding(card)
        handle = str(card["handle"])
        key_id = str(card.get("key_id") or "")
        if len(key_id) != 64:
            raise LanRefuse("QNS-LAN-IDENTITY", "peer pin must be the full public key", outcome="refused", security=True)
        prior = self.peers.get(key_id)
        if prior and str(prior.get("key_status") or "") in ("rotated", "revoked"):
            raise LanRefuse(
                "QNS-LAN-IDENTITY",
                "rotated or revoked key cannot be re-pinned",
                outcome="refused",
                security=True,
            )
        for row in self.peers.values():
            if row.get("handle") == handle and row.get("key_status") == "active" and str(row["card"].get("key_id")) != key_id:
                raise LanRefuse(
                    "QNS-LAN-IDENTITY",
                    "peer allowlist is pinned to a different public key",
                    outcome="refused",
                    security=True,
                )
        return self._pin(card, cert_pem, address)

    def rotate(self, card: dict[str, Any], cert_pem: str, address: str, rotation: dict[str, Any]) -> dict[str, Any]:
        """Replace a pin only when the previous key signed the new card."""
        verify_box_binding(card)
        prev_id = str((rotation or {}).get("prev_key_id") or "")
        prev = self.peers.get(prev_id)
        if prev is None or prev.get("key_status") != "active":
            raise LanRefuse("QNS-LAN-IDENTITY", "previous key is not an active pin", outcome="refused", security=True)
        verify_card_rotation(str(prev["card"]["sign_pub"]), card, rotation)
        try:
            check_rotation_freshness(
                rotation,
                prev_rot_seq=int(prev.get("rot_seq") or 0),
                seen_sigs=self.seen_rotations,
            )
        except Exception as exc:
            from qnm.boot import QNMRefuse

            if isinstance(exc, QNMRefuse):
                raise LanRefuse(exc.code, exc.detail, outcome="refused", security=True) from exc
            raise
        pem = str(cert_pem or "")
        if cert_common_name(pem) != str(card["handle"]):
            raise LanRefuse("QNS-LAN-IDENTITY", "certificate name is not the handle", outcome="refused", security=True)
        parse_ip_port(address)
        prev["key_status"] = "rotated"
        prev["rotated_to"] = str(card["key_id"])
        prev["rot_seq"] = int(rotation["rot_seq"])
        self.seen_rotations.add(str(rotation.get("sig") or ""))
        pinned = self._pin(card, cert_pem, address, prev_key_id=prev_id)
        row = self.peers[str(card["key_id"])]
        row["rot_seq"] = int(rotation["rot_seq"])
        self._save()
        self._save_seen()
        return pinned

    def _pin(self, card: dict[str, Any], cert_pem: str, address: str, prev_key_id: str = "") -> dict[str, Any]:
        handle = str(card["handle"])
        key_id = str(card["key_id"])
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
                "key_id": key_id,
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
            "prev_key_id": prev_key_id,
        }
        self.peers[key_id] = row
        self._save()
        return {"ok": True, "handle": handle, "key_id": key_id, "cert_sha256": row["cert_sha256"], "live": False}

    def revoke(self, handle: str, reason: str) -> dict[str, Any]:
        row = self.get(handle)
        row["key_status"] = "revoked"
        row["revocation"] = {"utc": _utc_now(), "reason": str(reason or "operator")[:80]}
        row["route_state"] = "DISCOVERED"
        self._save()
        return {"ok": True, "handle": handle, "key_status": "revoked", "live": False}

    def set_state(self, handle: str, state: str) -> None:
        try:
            row = self.get(handle)
        except LanRefuse:
            return
        row["route_state"] = state
        self._save()

    def mark_success(self, handle: str, utc: str) -> None:
        try:
            row = self.get(handle)
        except LanRefuse:
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

    def approved_host_set(self) -> set[str]:
        """Source addresses allowed to start TLS. Active pins only."""
        hosts: set[str] = set()
        for row in self.peers.values():
            if row.get("key_status") != "active":
                continue
            for address in row.get("addresses") or []:
                try:
                    host, _port = parse_ip_port(str(address))
                except LanRefuse:
                    continue
                hosts.add(host)
        return hosts

    def _save(self) -> None:
        text = json.dumps(self.peers, sort_keys=True, indent=2) + "\n"
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(text, encoding="utf-8")
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        tmp.replace(self.path)

    def _save_seen(self) -> None:
        text = json.dumps(sorted(self.seen_rotations), indent=2) + "\n"
        tmp = self._seen_path.with_suffix(".json.tmp")
        tmp.write_text(text, encoding="utf-8")
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        tmp.replace(self._seen_path)
