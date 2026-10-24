"""Signed hop receipts. No payload, key, or location fields."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from qnm.fedmesh.wire import canonical, sha256_hex
from qnsd.boot import AUTHOR
from qnsd.lan.contract import ADAPTER_ID, FORBIDDEN_RECORD_KEYS, GENESIS, PACKET_V, LanRefuse
from qnsd.lan.sign import sign_document, verify_document

RECEIPT_KEYS = frozenset(
    {
        "v",
        "kind",
        "author",
        "handle",
        "public_key",
        "sig",
        "packet_id",
        "payload_hash",
        "prev",
        "from_handle",
        "to_handle",
        "adapter",
        "hop",
        "sent_utc",
        "received_utc",
        "outcome",
        "hash",
    }
)


def receipt_core(body: dict[str, Any]) -> dict[str, Any]:
    return {key: body[key] for key in body if key not in ("sig", "hash")}


def receipt_hash(body: dict[str, Any]) -> str:
    return sha256_hex(canonical(receipt_core(body)))


class HopReceipts:
    def __init__(self, root: Path) -> None:
        self.path = Path(root) / "data" / "lan" / "receipts.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, stat.S_IRWXU)
        if not self.path.is_file():
            self.path.write_text("", encoding="utf-8")
            os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)

    def list(self) -> list[dict[str, Any]]:
        rows = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line))
        return rows

    def prev_for(self, packet_id: str) -> str:
        prev = GENESIS
        for row in self.list():
            if row.get("packet_id") == packet_id:
                prev = str(row.get("hash") or prev)
        return prev

    def has_stored(self, packet_id: str, payload_hash: str) -> bool:
        for row in self.list():
            if (
                row.get("packet_id") == packet_id
                and row.get("payload_hash") == payload_hash
                and row.get("outcome") == "ok"
            ):
                return True
        return False

    def append(
        self,
        private_key: Any,
        *,
        handle: str,
        public_key: str,
        packet_id: str,
        payload_hash: str,
        from_handle: str,
        to_handle: str,
        hop: int,
        sent_utc: str,
        received_utc: str,
        outcome: str,
    ) -> dict[str, Any]:
        if self.has_stored(packet_id, payload_hash) and outcome == "ok":
            for row in reversed(self.list()):
                if row.get("packet_id") == packet_id and row.get("outcome") == "ok":
                    return row
        core = {
            "v": PACKET_V,
            "kind": "hop-receipt",
            "author": AUTHOR,
            "handle": handle,
            "public_key": public_key,
            "packet_id": packet_id,
            "payload_hash": payload_hash,
            "prev": self.prev_for(packet_id),
            "from_handle": from_handle,
            "to_handle": to_handle,
            "adapter": ADAPTER_ID,
            "hop": int(hop),
            "sent_utc": sent_utc,
            "received_utc": received_utc,
            "outcome": outcome,
        }
        leaked = FORBIDDEN_RECORD_KEYS.intersection(core)
        if leaked:
            raise LanRefuse("QNS-LAN-REFUSED", "receipt field refused", outcome="refused", security=True)
        core["hash"] = receipt_hash(core)
        signed = sign_document(private_key, core)
        if set(signed) != RECEIPT_KEYS:
            raise LanRefuse("QNS-LAN-MALFORMED", "receipt keys refused", outcome="permanent", security=True)
        line = json.dumps(signed, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())
        return signed

    def verify(self) -> dict[str, Any]:
        errors: list[str] = []
        prev_by_packet: dict[str, str] = {}
        count = 0
        for index, row in enumerate(self.list()):
            count += 1
            if set(row) != RECEIPT_KEYS:
                errors.append(f"{index}: keys")
                continue
            if FORBIDDEN_RECORD_KEYS.intersection(row):
                errors.append(f"{index}: forbidden field")
                continue
            expect = receipt_hash(row)
            if row.get("hash") != expect:
                errors.append(f"{index}: hash")
                continue
            packet_id = str(row.get("packet_id") or "")
            prev = prev_by_packet.get(packet_id, GENESIS)
            if row.get("prev") != prev:
                errors.append(f"{index}: prev")
            prev_by_packet[packet_id] = str(row.get("hash"))
            try:
                verify_document(row, signer=str(row.get("handle") or ""))
            except LanRefuse as exc:
                errors.append(f"{index}: {exc.code}")
        return {
            "ok": not errors,
            "receipts": count,
            "errors": errors,
            "live": False,
            "author": AUTHOR,
            "adapter": ADAPTER_ID,
        }
