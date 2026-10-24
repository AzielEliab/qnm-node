"""Opt-in lan-tls node. The HTTP door is not this socket.

``live`` stays false. A loopback session is not cross-host proof.
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import stat
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from qnm.fedmesh.identity import load_or_create_owner
from qnm.fedmesh.secwire import signing_public_b64url
from qnm.fedmesh.wire import GENESIS_PREV, canonical, envelope_id, seal_envelope, sha256_hex
from qnsd.boot import AUTHOR, _utc_now
from qnsd.lan.bind import parse_ip_port, select_bind
from qnsd.lan.contract import (
    ADAPTER_ID,
    DEFAULT_FRAGMENT,
    DEFAULT_PORT,
    ENC_ALG,
    HANDSHAKE_TIMEOUT_S,
    MAX_FRAGMENT,
    MAX_NONCES,
    MIN_FRAGMENT,
    NONCE_BYTES,
    PACKET_V,
    SESSION_ALG,
    LanRefuse,
    SendResult,
)
from qnsd.lan.ledger import SeqLedger
from qnsd.lan.peers import PeerDirectory
from qnsd.lan.queue import QueueStore, new_item
from qnsd.lan.receipts import HopReceipts
from qnsd.lan.router import RoutePlanner
from qnsd.lan.session import client_handshake, result_from, send_envelope, serve_connection
from qnsd.lan.tlsutil import client_context, ensure_cert, server_context
from qnsd.photon import make_photon, photon_id

LOG_KEYS = (
    "event",
    "adapter",
    "packet_id",
    "payload_hash",
    "outcome",
    "code",
    "level",
    "handle",
    "peer_handle",
    "live",
    "loopback",
    "fragment_index",
    "fragment_count",
    "nbytes",
    "hop",
    "security",
)


class LanTLSAdapter:
    """TransportAdapter for one node. Production registers this adapter only."""

    def __init__(self, node: LanNode) -> None:
        self.node = node

    def capabilities(self) -> dict[str, Any]:
        return self.node.capabilities()

    def open(self) -> dict[str, Any]:
        return {"ok": False, "code": "QNS-LAN-ABSENT", "live": False, "detail": "pass an address to listen"}

    def send(self, packet: dict[str, Any]) -> SendResult:
        return self.node.deliver(packet)

    def receive(self) -> dict[str, Any]:
        rows = self.node.inbox_list()
        if not rows:
            return {"outcome": "absent", "code": "QNS-LAN-ABSENT", "live": False}
        return {"outcome": "ok", "live": False, "packet_id": rows[-1]["packet_id"], "payload_hash": rows[-1]["payload_hash"]}

    def close(self) -> None:
        self.node.close()

    def health(self) -> dict[str, Any]:
        return self.node.health()


class LanNode:
    def __init__(
        self,
        root: Path | str,
        *,
        enabled: bool = False,
        allow_loopback: bool = False,
        max_fragment_bytes: int = DEFAULT_FRAGMENT,
        passphrase: str | None = None,
    ) -> None:
        self.root = Path(root)
        self.enabled = bool(enabled)
        self.allow_loopback = bool(allow_loopback)
        if not MIN_FRAGMENT <= int(max_fragment_bytes) <= MAX_FRAGMENT:
            raise LanRefuse("QNS-LAN-QUOTA", "fragment size refused", outcome="permanent", security=True)
        self.max_fragment_bytes = int(max_fragment_bytes)
        self.root.mkdir(parents=True, exist_ok=True)
        secret = passphrase if passphrase is not None else (os.environ.get("QNM_NODE_PASSPHRASE") or None)
        self.ident = load_or_create_owner(self.root / "data" / "identity", secret)
        self.handle = self.ident.handle
        self.card = self.ident.card
        self.public_key = signing_public_b64url(self.ident.sign_private)
        self.sign_private = self.ident.sign_private
        self.box_private = self.ident.box_private
        cert = ensure_cert(self.root / "data" / "lan" / "tls", self.handle)
        self.cert_pem = cert["cert_pem"]
        self.cert_sha256 = cert["cert_sha256"]
        self.cert_path = cert["cert_path"]
        self.key_path = cert["key_path"]
        self.peers = PeerDirectory(self.root)
        self.queue = QueueStore(self.root)
        self.receipts = HopReceipts(self.root)
        self.ledger = SeqLedger(self.root)
        self.adapter = LanTLSAdapter(self)
        self.planner = RoutePlanner([self.adapter])
        self._listener: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sessions = 0
        self._reachable = False
        self._loopback = False
        self._conns: dict[str, int] = {}
        self._nonces: list[str] = []
        self._nonce_path = self.root / "data" / "lan" / "nonces.json"
        self._log_path = self.root / "data" / "lan" / "log.jsonl"
        self._load_nonces()
        self.relay_urls: tuple[str, ...] = ()
        self.relay_contacts = 0

    def capabilities(self) -> dict[str, Any]:
        present = self._listener is not None or self._sessions > 0
        return {
            "adapter": ADAPTER_ID,
            "v": PACKET_V,
            "presence": "PRESENT" if present else "ABSENT",
            "live": False,
            "fielding": "ABSENT",
            "hook_pending": False,
            "authenticated_peer": self._sessions > 0,
            "reachable": bool(self._reachable),
            "loopback": bool(self._loopback),
            "cross_host_proven": False,
            "mtu_bytes": self.max_fragment_bytes,
            "relay": False,
            "nat_traversal": False,
            "mock": False,
            "simulated_success": False,
            "enabled": self.enabled,
            "author": AUTHOR,
        }

    def health(self) -> dict[str, Any]:
        body = self.capabilities()
        body["peers"] = self.peers.list_public()
        body["queue"] = len([item for item in self.queue.items if item.get("state") in ("queued", "waiting")])
        body["receipts"] = self.receipts.verify()
        return body

    def public_material(self) -> dict[str, Any]:
        card = {
            key: self.card[key]
            for key in ("v", "purpose", "author", "handle", "key_id", "sign_pub", "box_pub", "box_sig")
        }
        return {
            "handle": self.handle,
            "card": card,
            "cert_pem": self.cert_pem,
            "cert_sha256": self.cert_sha256,
            "live": False,
            "author": AUTHOR,
        }

    def add_peer(self, material: dict[str, Any], address: str) -> dict[str, Any]:
        return self.peers.add(material["card"], material["cert_pem"], address)

    def revoke(self, handle: str, reason: str = "operator") -> dict[str, Any]:
        return self.peers.revoke(handle, reason)

    def listen(self, host: str, port: int = DEFAULT_PORT, *, allow_loopback: bool | None = None) -> dict[str, Any]:
        if not self.enabled:
            raise LanRefuse("QNS-LAN-ABSENT", "listener is not enabled", outcome="absent", security=False)
        if self._listener is not None:
            raise LanRefuse("QNS-LAN-BIND", "listener already open", outcome="refused", security=True)
        flag = self.allow_loopback if allow_loopback is None else bool(allow_loopback)
        if flag:
            self.allow_loopback = True
        ip = select_bind(host, allow_loopback=flag)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((ip, int(port)))
        sock.listen(8)
        sock.settimeout(0.2)
        self._listener = sock
        self._loopback = ip.startswith("127.")
        self._stop.clear()
        self._thread = threading.Thread(target=self._accept_loop, name="qns-lan", daemon=True)
        self._thread.start()
        bound_port = int(sock.getsockname()[1])
        self.log(event="listen", outcome="ok", code="", loopback=self._loopback, handle=self.handle)
        return {"ok": True, "bind": ip, "port": bound_port, "live": False, "loopback": self._loopback, "adapter": ADAPTER_ID}

    def close(self) -> None:
        self._stop.set()
        sock = self._listener
        self._listener = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    def send_payload(self, to_handle: str, payload: dict[str, Any], *, expiry_s: int = 3600) -> SendResult:
        return self.planner.dispatch(
            {"dst_handle": to_handle, "payload": dict(payload), "expiry_s": int(expiry_s)}
        )

    def flush(self, *, now: datetime | None = None) -> list[SendResult]:
        results = []
        for item in self.queue.ready(now):
            results.append(
                self.planner.dispatch(
                    {
                        "dst_handle": item.get("dst_handle"),
                        "envelope": item.get("envelope"),
                        "packet_id": item.get("packet_id"),
                        "payload_hash": item.get("payload_hash"),
                    }
                )
            )
        return results

    def deliver(self, packet: dict[str, Any]) -> SendResult:
        if not self.enabled:
            return SendResult(outcome="absent", code="QNS-LAN-ABSENT", security=False, detail="disabled")
        dst = str(packet.get("dst_handle") or "")
        try:
            peer = self.peers.get(dst)
        except LanRefuse as exc:
            return result_from(exc)
        if peer.get("key_status") != "active":
            return SendResult(outcome="refused", code="QNS-LAN-REVOKED", security=True, detail="revoked")
        envelope = packet.get("envelope")
        if isinstance(envelope, dict):
            packet_id = str(envelope.get("packet_id") or "")
            payload_hash = str(envelope.get("payload_hash") or "")
        else:
            payload = dict(packet.get("payload") or {})
            preview = make_photon(src=self.handle, dst=dst, payload=payload, pair_id="")
            payload_hash = sha256_hex(canonical(payload))
            if self.receipts.has_stored(preview.photon_id, payload_hash):
                return SendResult(
                    outcome="ok",
                    transport_accepted=False,
                    ack_level="stored",
                    packet_id=preview.photon_id,
                    payload_hash=payload_hash,
                    levels=["stored"],
                )
            try:
                envelope = self._seal(dst, payload, int(packet.get("expiry_s") or 3600))
            except LanRefuse as exc:
                return result_from(exc)
            packet_id = str(envelope["packet_id"])
            payload_hash = str(envelope["payload_hash"])
            if self.queue.get(packet_id) is None:
                try:
                    self.queue.append(
                        new_item(
                            envelope,
                            packet_id=packet_id,
                            payload_hash=payload_hash,
                            expiry_utc=str(envelope["expiry_utc"]),
                        )
                    )
                except LanRefuse as exc:
                    return result_from(exc, packet_id=packet_id, payload_hash=payload_hash)
        if self.receipts.has_stored(packet_id, payload_hash):
            self.queue.mark(packet_id, state="done", outcome="ok", code="")
            return SendResult(
                outcome="ok",
                code="",
                transport_accepted=False,
                ack_level="stored",
                packet_id=packet_id,
                payload_hash=payload_hash,
                levels=["stored"],
            )
        try:
            result = self._exchange(peer, envelope)
        except LanRefuse as exc:
            self._note_failure(packet_id, payload_hash, envelope, exc)
            return result_from(exc, packet_id=packet_id, payload_hash=payload_hash, transport_accepted=exc.outcome != "absent")
        if result.ack_level == "stored":
            self._note_stored(envelope)
            self.queue.mark(packet_id, state="done", outcome="ok", code="")
            self._reachable = True
        return result

    def verify(self) -> dict[str, Any]:
        report = self.receipts.verify()
        missing = []
        for row in self.receipts.list():
            if row.get("outcome") != "ok":
                continue
            packet_id = str(row.get("packet_id") or "")
            if row.get("to_handle") == self.handle and not self.inbox_path(packet_id).is_file():
                missing.append(packet_id)
        report["missing_inbox"] = missing
        report["ok"] = bool(report["ok"]) and not missing
        report["live"] = False
        return report

    def inbox_path(self, packet_id: str) -> Path:
        safe = "".join(ch for ch in packet_id if ch in "0123456789abcdef")
        return self.root / "data" / "lan" / "inbox" / f"{safe}.json"

    def inbox_list(self) -> list[dict[str, Any]]:
        folder = self.root / "data" / "lan" / "inbox"
        if not folder.is_dir():
            return []
        rows = []
        for path in sorted(folder.glob("*.json")):
            row = json.loads(path.read_text(encoding="utf-8"))
            rows.append({"packet_id": row.get("packet_id"), "payload_hash": row.get("payload_hash")})
        return rows

    def log(self, **fields: Any) -> None:
        row: dict[str, Any] = {"adapter": ADAPTER_ID, "live": False}
        for key in LOG_KEYS:
            if key not in fields:
                continue
            value = fields[key]
            if isinstance(value, (str, int, bool)) or value is None:
                row[key] = value
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        with self._log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def log_text(self) -> str:
        if not self._log_path.is_file():
            return ""
        return self._log_path.read_text(encoding="utf-8")

    def remember_nonce(self, nonce: str) -> None:
        token = str(nonce or "")
        if len(token) != NONCE_BYTES * 2 or any(ch not in "0123456789abcdef" for ch in token):
            raise LanRefuse("QNS-LAN-MALFORMED", "nonce refused", outcome="permanent", security=True)
        if token in self._nonces:
            raise LanRefuse("QNS-LAN-REPLAY", "nonce already seen", outcome="refused", security=True)
        self._nonces.append(token)
        if len(self._nonces) > MAX_NONCES:
            self._nonces = self._nonces[-MAX_NONCES:]
        self._nonce_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._nonce_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self._nonces) + "\n", encoding="utf-8")
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        tmp.replace(self._nonce_path)

    def mark_session(self, up: bool) -> None:
        if up:
            self._sessions += 1
            self._reachable = True
        else:
            self._sessions = max(0, self._sessions - 1)

    def _allocate_seq(self) -> tuple[int, str]:
        """Next sender seq.

        Outstanding queued envelopes count, so two packets sealed before
        either is stored do not reuse seq 1. The receiver still accepts
        them only in order.
        """
        seq, prev = self.ledger.tip(self.handle)
        for item in self.queue.items:
            if item.get("state") not in ("queued", "waiting"):
                continue
            body = (item.get("envelope") or {}).get("body") or {}
            try:
                item_seq = int(body.get("seq") or 0)
            except (TypeError, ValueError):
                continue
            if item_seq > seq:
                seq = item_seq
                prev = envelope_id(body)
        if seq < 1:
            return 1, GENESIS_PREV
        return seq + 1, prev

    def _seal(
        self,
        dst: str,
        payload: dict[str, Any],
        expiry_s: int,
        *,
        seq: int | None = None,
        prev: str | None = None,
    ) -> dict[str, Any]:
        peer = self.peers.get(dst)
        photon = make_photon(src=self.handle, dst=dst, payload=payload, pair_id="")
        if photon.photon_id != photon_id(photon):
            raise LanRefuse("QNS-LAN-FORK", "photon id drifted", outcome="refused", security=True)
        payload_hash = sha256_hex(canonical(payload))
        alloc_seq, alloc_prev = self._allocate_seq()
        seq = alloc_seq if seq is None else int(seq)
        prev = alloc_prev if prev is None else str(prev)
        sealed = seal_envelope(
            private_key=self.sign_private,
            box_private=self.box_private,
            sender=self.card,
            recipient_card=peer["card"],
            seq=seq,
            prev=prev,
            purpose="msg",
            plaintext={"kind": "qns-photon", "photon": photon.to_dict()},
        )
        created = _utc_now()
        expiry = (datetime.now(timezone.utc) + timedelta(seconds=max(1, expiry_s))).strftime("%Y-%m-%dT%H:%M:%SZ")
        from qnsd.lan.sign import sign_document

        return sign_document(
            self.sign_private,
            {
                "v": PACKET_V,
                "kind": "packet",
                "author": AUTHOR,
                "packet_id": photon.photon_id,
                "src_handle": self.handle,
                "dst_handle": dst,
                "created_utc": created,
                "expiry_utc": expiry,
                "payload_hash": payload_hash,
                "enc": {"alg": ENC_ALG, "session": SESSION_ALG},
                "body": sealed,
                "public_key": self.public_key,
            },
        )

    def _exchange(self, peer: dict[str, Any], envelope: dict[str, Any]) -> SendResult:
        address = str((peer.get("addresses") or [""])[0])
        host, port = parse_ip_port(address)
        import ipaddress

        loopback = ipaddress.ip_address(host).is_loopback
        if loopback and not self.allow_loopback:
            raise LanRefuse("QNS-LAN-BIND", "loopback peer needs an explicit opt-in", outcome="refused", security=True)
        self._loopback = loopback or self._loopback
        try:
            raw = socket.create_connection((host, port), timeout=HANDSHAKE_TIMEOUT_S)
        except OSError as exc:
            raise LanRefuse("QNS-LAN-UNAVAILABLE", "peer unavailable", outcome="temporary", security=False) from exc
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            tls = client_context(self.cert_path, self.key_path, str(peer["cert_pem"])).wrap_socket(
                raw, server_hostname=host
            )
        except ssl.SSLError as exc:
            raw.close()
            raise LanRefuse("QNS-LAN-IDENTITY", "tls peer authentication failed", outcome="refused", security=True) from exc
        tls.settimeout(HANDSHAKE_TIMEOUT_S)
        try:
            client_handshake(tls, self, peer)
            self.mark_session(True)
            try:
                return send_envelope(tls, self, peer, envelope)
            finally:
                self.mark_session(False)
        finally:
            try:
                tls.close()
            except OSError:
                pass

    def _note_stored(self, envelope: dict[str, Any]) -> None:
        packet_id = str(envelope["packet_id"])
        payload_hash = str(envelope["payload_hash"])
        if not self.receipts.has_stored(packet_id, payload_hash):
            body = envelope["body"]
            try:
                self.ledger.accept(self.handle, int(body["seq"]), str(body["prev"]), envelope_id(body))
            except LanRefuse as exc:
                if exc.code != "FED-REPLAY":
                    raise
            self.receipts.append(
                self.sign_private,
                handle=self.handle,
                public_key=self.public_key,
                packet_id=packet_id,
                payload_hash=payload_hash,
                from_handle=self.handle,
                to_handle=str(envelope["dst_handle"]),
                hop=1,
                sent_utc=str(envelope.get("created_utc") or ""),
                received_utc=_utc_now(),
                outcome="ok",
            )
        self.peers.mark_success(str(envelope["dst_handle"]), _utc_now())
        self.log(event="stored", packet_id=packet_id, payload_hash=payload_hash, peer_handle=str(envelope["dst_handle"]), outcome="ok", code="")

    def _note_failure(self, packet_id: str, payload_hash: str, envelope: dict[str, Any], exc: LanRefuse) -> None:
        if exc.outcome == "temporary" and exc.code != "QNS-LAN-QUOTA":
            state = self.queue.schedule_retry(packet_id)
            if state == "spent":
                exc.outcome = "permanent"
                exc.code = "QNS-LAN-RETRY"
                exc.security = True
        elif exc.security or exc.outcome in ("refused", "permanent"):
            self.queue.mark(packet_id, state="refused", outcome=exc.outcome, code=exc.code)
        if packet_id and not self.receipts.has_stored(packet_id, payload_hash):
            self.receipts.append(
                self.sign_private,
                handle=self.handle,
                public_key=self.public_key,
                packet_id=packet_id,
                payload_hash=payload_hash,
                from_handle=self.handle,
                to_handle=str(envelope.get("dst_handle") or ""),
                hop=1,
                sent_utc=str(envelope.get("created_utc") or _utc_now()),
                received_utc="",
                outcome="ok" if exc.outcome == "ok" else exc.outcome if exc.outcome in ("temporary", "refused", "permanent", "absent") else "refused",
            )
        self.log(event="send-result", packet_id=packet_id, payload_hash=payload_hash, outcome=exc.outcome, code=exc.code, security=exc.security)

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            sock = self._listener
            if sock is None:
                return
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            source = str(addr[0])
            count = self._conns.get(source, 0)
            if count >= 4:
                conn.close()
                self.log(event="refuse", code="QNS-LAN-QUOTA", outcome="refused", security=True)
                continue
            self._conns[source] = count + 1
            threading.Thread(target=self._serve, args=(conn, source), daemon=True).start()

    def _serve(self, conn: socket.socket, source: str) -> None:
        try:
            pems = [str(row["cert_pem"]) for row in self.peers.active()]
            try:
                ctx = server_context(self.cert_path, self.key_path, pems)
                tls = ctx.wrap_socket(conn, server_side=True)
            except (LanRefuse, ssl.SSLError, OSError):
                self.log(event="refuse", code="QNS-LAN-IDENTITY", outcome="refused", security=True)
                conn.close()
                return
            serve_connection(tls, self, source)
        finally:
            self._conns[source] = max(0, self._conns.get(source, 1) - 1)

    def _load_nonces(self) -> None:
        if self._nonce_path.is_file():
            loaded = json.loads(self._nonce_path.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                self._nonces = [str(item) for item in loaded][-MAX_NONCES:]

