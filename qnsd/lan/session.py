"""TLS session, handshake, fragments, and delivery acks.

The TLS library is the session cipher. Signatures reuse Ed25519.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import ssl
import stat
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from qnm.fedmesh.wire import (
    b64e,
    canonical,
    envelope_id,
    open_envelope,
    sha256_hex,
    verify_envelope,
)
from qnsd.boot import AUTHOR, _utc_now
from qnsd.lan.contract import (
    ACK_LEVELS,
    CLOCK_SKEW_S,
    ENC_ALG,
    FORBIDDEN_RECORD_KEYS,
    GENESIS,
    HANDSHAKE_TIMEOUT_S,
    LAN_V,
    MAX_FRAGMENTS,
    MAX_INFLIGHT,
    MAX_MESSAGES,
    MAX_REASSEMBLY,
    MESSAGE_WINDOW_S,
    NONCE_BYTES,
    PACKET_V,
    READ_TIMEOUT_S,
    REASSEMBLY_TIMEOUT_S,
    SESSION_ALG,
    LanRefuse,
    SendResult,
)
from qnsd.lan.frame import read_frame, write_frame
from qnsd.lan.sign import sign_bytes, sign_document, verify_bytes, verify_document
from qnsd.photon import loads, photon_id

PACKET_KEYS = frozenset(
    {
        "v",
        "kind",
        "author",
        "packet_id",
        "src_handle",
        "dst_handle",
        "created_utc",
        "expiry_utc",
        "payload_hash",
        "enc",
        "body",
        "public_key",
        "sig",
    }
)
FRAGMENT_KEYS = frozenset(
    {
        "v",
        "kind",
        "author",
        "handle",
        "public_key",
        "packet_id",
        "payload_hash",
        "index",
        "count",
        "total",
        "sha256",
        "body_b64",
        "sig",
    }
)


def _utc_parse(text: str) -> datetime:
    try:
        return datetime.strptime(str(text), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise LanRefuse("QNS-LAN-MALFORMED", "utc refused", outcome="permanent", security=True) from exc


def check_clock(created_utc: str, expiry_utc: str, *, now: datetime | None = None) -> None:
    moment = now or datetime.now(timezone.utc)
    created = _utc_parse(created_utc)
    expiry = _utc_parse(expiry_utc)
    skew = timedelta(seconds=CLOCK_SKEW_S)
    if expiry < created:
        raise LanRefuse("QNS-LAN-EXPIRED", "expiry precedes creation", outcome="permanent", security=True)
    if created > moment + skew:
        raise LanRefuse("QNS-LAN-CLOCK", "created time is outside the skew window", outcome="permanent", security=True)
    if moment > expiry + skew:
        raise LanRefuse("QNS-LAN-EXPIRED", "packet expired", outcome="permanent", security=True)


def transcript(
    *,
    initiator_handle: str,
    responder_handle: str,
    initiator_nonce: str,
    responder_nonce: str,
    initiator_cert_sha256: str,
    responder_cert_sha256: str,
) -> dict[str, Any]:
    return {
        "v": LAN_V,
        "kind": "handshake-transcript",
        "protocol": LAN_V,
        "author": AUTHOR,
        "initiator_handle": initiator_handle,
        "responder_handle": responder_handle,
        "initiator_nonce": initiator_nonce,
        "responder_nonce": responder_nonce,
        "initiator_cert_sha256": initiator_cert_sha256,
        "responder_cert_sha256": responder_cert_sha256,
    }


def peer_cert_sha256(sock: socket.socket) -> str:
    der = sock.getpeercert(binary_form=True)
    if not der:
        raise LanRefuse("QNS-LAN-IDENTITY", "peer certificate missing", outcome="refused", security=True)
    return hashlib.sha256(der).hexdigest()


def _require_keys(obj: dict[str, Any], keys: frozenset[str], *, version: str) -> None:
    if obj.get("v") != version:
        raise LanRefuse("QNS-LAN-VERSION", "unknown critical version", outcome="permanent", security=True)
    if set(obj) != keys:
        raise LanRefuse("QNS-LAN-MALFORMED", "message fields refused", outcome="permanent", security=True)


def _ack_hash(ack: dict[str, Any]) -> str:
    statement = {key: value for key, value in ack.items() if key != "sig"}
    return sha256_hex(canonical(statement))


def _split(raw: bytes, size: int) -> list[bytes]:
    if len(raw) > MAX_FRAGMENTS * size or len(raw) > MAX_REASSEMBLY:
        raise LanRefuse("QNS-LAN-QUOTA", "packet exceeds the reassembly cap", outcome="refused", security=True)
    return [raw[index : index + size] for index in range(0, len(raw), size)] or [b""]


class _Rate:
    def __init__(self) -> None:
        self.times: list[float] = []
        self.inflight = 0

    def bump(self) -> None:
        now = time.monotonic()
        self.times = [stamp for stamp in self.times if now - stamp < MESSAGE_WINDOW_S]
        if len(self.times) >= MAX_MESSAGES or self.inflight >= MAX_INFLIGHT:
            raise LanRefuse("QNS-LAN-QUOTA", "peer quota", outcome="refused", security=True)
        self.times.append(now)


def handshake_drop(exc: BaseException) -> LanRefuse | None:
    """A dropped handshake is temporary. A bad certificate is not.

    ``SSLEOFError`` and ``ConnectionResetError`` are peer drops.
    ``security`` stays false so the queue can retry. Certificate and
    pin failures return ``None`` and the caller keeps them as refusals.
    """
    if isinstance(exc, TimeoutError):
        return LanRefuse(
            "QNS-LAN-TIMEOUT",
            "handshake timed out",
            outcome="temporary",
            security=False,
        )
    if isinstance(exc, (ssl.SSLEOFError, ConnectionResetError, BrokenPipeError)):
        return LanRefuse(
            "QNS-LAN-UNAVAILABLE",
            "peer dropped the handshake",
            outcome="temporary",
            security=False,
        )
    if isinstance(exc, ssl.SSLError) and "timed out" in str(exc).lower():
        return LanRefuse(
            "QNS-LAN-TIMEOUT",
            "handshake timed out",
            outcome="temporary",
            security=False,
        )
    return None


def require_ack_level(seen: list[str], level: str) -> None:
    """Acks arrive received, then verified, then stored."""
    if len(seen) >= len(ACK_LEVELS) or ACK_LEVELS[len(seen)] != level:
        raise LanRefuse(
            "QNS-LAN-MALFORMED",
            "ack level out of order",
            outcome="permanent",
            security=True,
        )


def _arm(sock: socket.socket, deadline: float, cap: float) -> None:
    left = deadline - time.monotonic()
    if left <= 0:
        raise LanRefuse(
            "QNS-LAN-TIMEOUT",
            "session deadline",
            outcome="temporary",
            security=False,
        )
    sock.settimeout(min(cap, left))


def _refusal_from(msg: dict[str, Any], *, expect_handle: str) -> LanRefuse:
    verify_document(msg, signer=str(msg.get("handle") or ""))
    if msg.get("handle") != expect_handle:
        raise LanRefuse("QNS-LAN-IDENTITY", "outcome signer mismatch", outcome="refused", security=True)
    code = str(msg.get("code") or "QNS-LAN-REFUSED")
    security = bool(msg.get("security"))
    outcome = str(msg.get("outcome") or "refused")
    if code == "FED-GAP":
        outcome, security = "temporary", False
    return LanRefuse(code, "peer refused the packet", outcome=outcome, security=security)


def client_handshake(sock: socket.socket, node: Any, peer: dict[str, Any], deadline: float) -> None:
    _arm(sock, deadline, HANDSHAKE_TIMEOUT_S)
    presented = peer_cert_sha256(sock)
    if presented != peer["cert_sha256"]:
        raise LanRefuse("QNS-LAN-IDENTITY", "certificate pin mismatch", outcome="refused", security=True)
    nonce = os.urandom(NONCE_BYTES).hex()
    hello = sign_document(
        node.sign_private,
        {
            "v": LAN_V,
            "kind": "hello",
            "author": AUTHOR,
            "handle": node.handle,
            "public_key": node.public_key,
            "initiator_handle": node.handle,
            "responder_handle": peer["handle"],
            "initiator_nonce": nonce,
            "initiator_cert_sha256": node.cert_sha256,
        },
    )
    write_frame(sock, hello)
    reply = read_frame(sock)
    if reply.get("kind") == "outcome":
        raise _refusal_from(reply, expect_handle=str(peer["handle"]))
    _check_responder_hello(node, peer, reply, nonce, presented)
    node.remember_nonce(str(reply["responder_nonce"]))
    body = transcript(
        initiator_handle=node.handle,
        responder_handle=peer["handle"],
        initiator_nonce=nonce,
        responder_nonce=str(reply["responder_nonce"]),
        initiator_cert_sha256=node.cert_sha256,
        responder_cert_sha256=presented,
    )
    confirm = {
        "v": LAN_V,
        "kind": "confirm",
        "author": AUTHOR,
        "handle": node.handle,
        "public_key": node.public_key,
        **{key: body[key] for key in (
            "initiator_handle",
            "responder_handle",
            "initiator_nonce",
            "responder_nonce",
            "initiator_cert_sha256",
            "responder_cert_sha256",
        )},
    }
    confirm["sig"] = sign_bytes(node.sign_private, canonical(body))
    write_frame(sock, confirm)
    node.peers.set_state(peer["handle"], "AUTHENTICATED")
    node.log(event="handshake", peer_handle=peer["handle"], outcome="ok", code="")


def _check_responder_hello(
    node: Any,
    peer: dict[str, Any],
    reply: dict[str, Any],
    nonce: str,
    presented: str,
) -> None:
    if reply.get("v") != LAN_V or reply.get("kind") != "hello":
        raise LanRefuse("QNS-LAN-VERSION", "handshake version refused", outcome="permanent", security=True)
    if reply.get("handle") != peer["handle"] or reply.get("responder_handle") != peer["handle"]:
        raise LanRefuse("QNS-LAN-IDENTITY", "responder handle mismatch", outcome="refused", security=True)
    if reply.get("initiator_handle") != node.handle or reply.get("initiator_nonce") != nonce:
        raise LanRefuse("QNS-LAN-IDENTITY", "handshake did not bind this initiator", outcome="refused", security=True)
    if reply.get("responder_cert_sha256") != presented or reply.get("initiator_cert_sha256") != node.cert_sha256:
        raise LanRefuse("QNS-LAN-IDENTITY", "handshake certificate mismatch", outcome="refused", security=True)
    body = transcript(
        initiator_handle=node.handle,
        responder_handle=peer["handle"],
        initiator_nonce=nonce,
        responder_nonce=str(reply.get("responder_nonce") or ""),
        initiator_cert_sha256=node.cert_sha256,
        responder_cert_sha256=presented,
    )
    from qnm.fedmesh.wire import b64d, b64url_d

    if b64url_d(str(reply.get("public_key") or "")) != b64d(str(peer["card"]["sign_pub"])):
        raise LanRefuse("QNS-LAN-IDENTITY", "signing key is not the pin", outcome="refused", security=True)
    verify_bytes(str(reply.get("public_key") or ""), str(reply.get("sig") or ""), canonical(body), signer=peer["handle"])
    if not reply.get("responder_nonce") or len(str(reply["responder_nonce"])) != NONCE_BYTES * 2:
        raise LanRefuse("QNS-LAN-MALFORMED", "responder nonce refused", outcome="permanent", security=True)


def server_handshake(sock: socket.socket, node: Any, source_ip: str, deadline: float) -> dict[str, Any]:
    _arm(sock, deadline, HANDSHAKE_TIMEOUT_S)
    presented = peer_cert_sha256(sock)
    hello = read_frame(sock)
    if hello.get("v") != LAN_V or hello.get("kind") != "hello":
        raise LanRefuse("QNS-LAN-VERSION", "handshake version refused", outcome="permanent", security=True)
    verify_document(hello, signer=str(hello.get("handle") or ""))
    handle = str(hello.get("initiator_handle") or "")
    if handle != hello.get("handle"):
        raise LanRefuse("QNS-LAN-IDENTITY", "hello handle mismatch", outcome="refused", security=True)
    peer = node.peers.get(handle)
    if peer.get("key_status") != "active":
        raise LanRefuse("QNS-LAN-REVOKED", "peer key is revoked", outcome="refused", security=True)
    if presented != peer["cert_sha256"] or hello.get("initiator_cert_sha256") != presented:
        raise LanRefuse("QNS-LAN-IDENTITY", "certificate pin mismatch", outcome="refused", security=True)
    from qnm.fedmesh.wire import b64d, b64url_d

    if b64url_d(str(hello.get("public_key") or "")) != b64d(str(peer["card"]["sign_pub"])):
        raise LanRefuse("QNS-LAN-IDENTITY", "signing key is not the pin", outcome="refused", security=True)
    if source_ip not in node.peers.approved_hosts(handle):
        raise LanRefuse("QNS-LAN-REFUSED", "source address is not approved", outcome="refused", security=True)
    if hello.get("responder_handle") != node.handle:
        raise LanRefuse("QNS-LAN-IDENTITY", "hello is for a different node", outcome="refused", security=True)
    node.remember_nonce(str(hello.get("initiator_nonce") or ""))
    responder_nonce = os.urandom(NONCE_BYTES).hex()
    body = transcript(
        initiator_handle=handle,
        responder_handle=node.handle,
        initiator_nonce=str(hello["initiator_nonce"]),
        responder_nonce=responder_nonce,
        initiator_cert_sha256=presented,
        responder_cert_sha256=node.cert_sha256,
    )
    reply = {
        "v": LAN_V,
        "kind": "hello",
        "author": AUTHOR,
        "handle": node.handle,
        "public_key": node.public_key,
        "initiator_handle": handle,
        "responder_handle": node.handle,
        "initiator_nonce": str(hello["initiator_nonce"]),
        "responder_nonce": responder_nonce,
        "initiator_cert_sha256": presented,
        "responder_cert_sha256": node.cert_sha256,
        "sig": sign_bytes(node.sign_private, canonical(body)),
    }
    write_frame(sock, reply)
    confirm = read_frame(sock)
    if confirm.get("kind") != "confirm" or confirm.get("v") != LAN_V or confirm.get("author") != AUTHOR:
        raise LanRefuse("QNS-LAN-VERSION", "confirm version refused", outcome="permanent", security=True)
    for key, value in body.items():
        if key in ("v", "kind", "protocol", "author"):
            continue
        if confirm.get(key) != value:
            raise LanRefuse("QNS-LAN-IDENTITY", "confirm did not bind the transcript", outcome="refused", security=True)
    verify_bytes(
        str(confirm.get("public_key") or ""),
        str(confirm.get("sig") or ""),
        canonical(body),
        signer=handle,
    )
    node.peers.set_state(handle, "AUTHENTICATED")
    node.log(event="handshake", peer_handle=handle, outcome="ok", code="")
    return peer


def send_envelope(
    sock: socket.socket,
    node: Any,
    peer: dict[str, Any],
    envelope: dict[str, Any],
    deadline: float,
) -> SendResult:
    packet_id = str(envelope.get("packet_id") or "")
    payload_hash = str(envelope.get("payload_hash") or "")
    raw = canonical(envelope)
    pieces = _split(raw, int(node.max_fragment_bytes))
    node.peers.set_state(peer["handle"], "ELIGIBLE")
    frames_out = False
    try:
        for index, piece in enumerate(pieces):
            frag = sign_document(
                node.sign_private,
                {
                    "v": LAN_V,
                    "kind": "fragment",
                    "author": AUTHOR,
                    "handle": node.handle,
                    "public_key": node.public_key,
                    "packet_id": packet_id,
                    "payload_hash": payload_hash,
                    "index": index,
                    "count": len(pieces),
                    "total": len(raw),
                    "sha256": sha256_hex(piece),
                    "body_b64": b64e(piece),
                },
            )
            write_frame(sock, frag)
        frames_out = True
        node.peers.set_state(peer["handle"], "ATTEMPTED")
        node.log(
            event="send",
            packet_id=packet_id,
            payload_hash=payload_hash,
            peer_handle=peer["handle"],
            fragment_count=len(pieces),
            nbytes=len(raw),
            outcome="temporary",
            code="",
        )
        levels: list[str] = []
        read_deadline = min(time.monotonic() + READ_TIMEOUT_S, deadline)
        while time.monotonic() < read_deadline:
            _arm(sock, read_deadline, READ_TIMEOUT_S)
            msg = read_frame(sock)
            kind = str(msg.get("kind") or "")
            if kind == "outcome":
                raise _refusal_from(msg, expect_handle=str(peer["handle"]))
            if kind != "delivery-ack":
                raise LanRefuse("QNS-LAN-MALFORMED", "expected an ack", outcome="permanent", security=True)
            verify_document(msg, signer=str(msg.get("from_handle") or ""))
            if msg.get("from_handle") != peer["handle"] or msg.get("to_handle") != node.handle:
                raise LanRefuse("QNS-LAN-IDENTITY", "ack identity mismatch", outcome="refused", security=True)
            if msg.get("packet_id") != packet_id or msg.get("payload_hash") != payload_hash:
                raise LanRefuse("QNS-LAN-FORK", "ack does not bind this packet", outcome="refused", security=True)
            level = str(msg.get("level") or "")
            require_ack_level(levels, level)
            levels.append(level)
            node.log(event="ack", packet_id=packet_id, payload_hash=payload_hash, level=level, peer_handle=peer["handle"], outcome="ok", code="")
            if level == "stored":
                node.peers.set_state(peer["handle"], "ACKNOWLEDGED")
                return SendResult(
                    outcome="ok",
                    code="",
                    security=False,
                    transport_accepted=True,
                    ack_level="stored",
                    packet_id=packet_id,
                    payload_hash=payload_hash,
                    levels=levels,
                )
        raise LanRefuse("QNS-LAN-TIMEOUT", "stored ack timed out", outcome="temporary", security=False)
    except LanRefuse as exc:
        if frames_out:
            exc.transport_accepted = True
        raise
    except (ssl.SSLEOFError, ConnectionResetError, BrokenPipeError, TimeoutError) as exc:
        code = "QNS-LAN-TIMEOUT" if isinstance(exc, TimeoutError) else "QNS-LAN-UNAVAILABLE"
        raise LanRefuse(
            code,
            "peer dropped the session",
            outcome="temporary",
            security=False,
            transport_accepted=frames_out,
        ) from exc


def serve_connection(sock: socket.socket, node: Any, source_ip: str, deadline: float) -> None:
    rate = _Rate()
    handed = False
    try:
        peer = server_handshake(sock, node, source_ip, deadline)
        handed = True
        node.mark_session(True)
        while True:
            _arm(sock, deadline, REASSEMBLY_TIMEOUT_S)
            rate.bump()
            rate.inflight += 1
            try:
                _serve_one(sock, node, peer)
            finally:
                rate.inflight = max(0, rate.inflight - 1)
    except LanRefuse as exc:
        if not handed and exc.security and exc.code != "QNS-LAN-UNAVAILABLE":
            _write_outcome(sock, node, "", "", exc)
        if exc.code != "QNS-LAN-UNAVAILABLE":
            node.log(event="refuse", code=exc.code, outcome=exc.outcome, security=exc.security)
    except (TimeoutError, ssl.SSLEOFError, ConnectionResetError, BrokenPipeError) as exc:
        dropped = handshake_drop(exc)
        node.log(
            event="refuse",
            code=dropped.code if dropped is not None else "QNS-LAN-UNAVAILABLE",
            outcome="temporary",
            security=False,
        )
    finally:
        node.mark_session(False)
        try:
            sock.close()
        except OSError:
            pass


def _serve_one(sock: socket.socket, node: Any, peer: dict[str, Any]) -> None:
    sock.settimeout(REASSEMBLY_TIMEOUT_S)
    first = read_frame(sock)
    if first.get("kind") != "fragment":
        raise LanRefuse("QNS-LAN-MALFORMED", "expected a fragment", outcome="permanent", security=True)
    count = int(first.get("count") or 0)
    if count < 1 or count > MAX_FRAGMENTS:
        raise LanRefuse("QNS-LAN-QUOTA", "fragment count refused", outcome="refused", security=True)
    frames = [first]
    while len(frames) < count:
        frames.append(read_frame(sock))
    raw = _reassemble(frames, peer_handle=str(peer["handle"]))
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LanRefuse("QNS-LAN-MALFORMED", "reassembly is not JSON", outcome="permanent", security=True) from exc
    if not isinstance(envelope, dict):
        raise LanRefuse("QNS-LAN-MALFORMED", "reassembly must be an object", outcome="permanent", security=True)
    packet_id = str(envelope.get("packet_id") or "")
    payload_hash = str(envelope.get("payload_hash") or "")
    prev = GENESIS
    try:
        _require_keys(envelope, PACKET_KEYS, version=PACKET_V)
        if envelope.get("kind") != "packet":
            raise LanRefuse("QNS-LAN-MALFORMED", "kind refused", outcome="permanent", security=True)
        received = _ack(node, packet_id=packet_id, payload_hash=payload_hash, level="received", to_handle=str(peer["handle"]), prev=prev)
        write_frame(sock, received)
        prev = _ack_hash(received)
        _verify_packet(node, peer, envelope)
        verified = _ack(node, packet_id=packet_id, payload_hash=payload_hash, level="verified", to_handle=str(peer["handle"]), prev=prev)
        write_frame(sock, verified)
        prev = _ack_hash(verified)
        _store_packet(node, peer, envelope, prev)
        stored = _ack(node, packet_id=packet_id, payload_hash=payload_hash, level="stored", to_handle=str(peer["handle"]), prev=prev)
        write_frame(sock, stored)
    except LanRefuse as exc:
        _write_outcome(sock, node, packet_id, payload_hash, exc)
        raise


def _reassemble(frames: list[dict[str, Any]], *, peer_handle: str) -> bytes:
    count = int(frames[0].get("count") or 0)
    total = int(frames[0].get("total") or 0)
    packet_id = frames[0].get("packet_id")
    payload_hash = frames[0].get("payload_hash")
    if total < 1 or total > MAX_REASSEMBLY:
        raise LanRefuse("QNS-LAN-QUOTA", "reassembly cap", outcome="refused", security=True)
    slots: dict[int, bytes] = {}
    for frame in frames:
        _require_keys(frame, FRAGMENT_KEYS, version=LAN_V)
        verify_document(frame, signer=peer_handle)
        if frame.get("handle") != peer_handle:
            raise LanRefuse("QNS-LAN-IDENTITY", "fragment signer mismatch", outcome="refused", security=True)
        if int(frame.get("count") or 0) != count or int(frame.get("total") or 0) != total:
            raise LanRefuse("QNS-LAN-FORK", "fragment set mismatch", outcome="refused", security=True)
        if frame.get("packet_id") != packet_id or frame.get("payload_hash") != payload_hash:
            raise LanRefuse("QNS-LAN-FORK", "fragment packet mismatch", outcome="refused", security=True)
        index = int(frame.get("index") or 0)
        if index < 0 or index >= count:
            raise LanRefuse("QNS-LAN-MALFORMED", "fragment index refused", outcome="permanent", security=True)
        from qnm.fedmesh.wire import b64d

        try:
            piece = b64d(str(frame.get("body_b64") or ""))
        except Exception as exc:  # noqa: BLE001
            raise LanRefuse("QNS-LAN-MALFORMED", "fragment body refused", outcome="permanent", security=True) from exc
        digest = sha256_hex(piece)
        if digest != frame.get("sha256"):
            raise LanRefuse("QNS-LAN-REFUSED", "fragment hash mismatch", outcome="refused", security=True)
        prior = slots.get(index)
        if prior is not None and prior != piece:
            raise LanRefuse("QNS-LAN-FORK", "fragment fork", outcome="refused", security=True)
        slots[index] = piece
    if len(slots) != count:
        raise LanRefuse("QNS-LAN-MALFORMED", "incomplete fragment set", outcome="permanent", security=True)
    raw = b"".join(slots[index] for index in range(count))
    if len(raw) != total:
        raise LanRefuse("QNS-LAN-MALFORMED", "fragment length mismatch", outcome="permanent", security=True)
    return raw


def _verify_packet(node: Any, peer: dict[str, Any], envelope: dict[str, Any]) -> None:
    if envelope.get("src_handle") != peer["handle"] or envelope.get("dst_handle") != node.handle:
        raise LanRefuse("QNS-LAN-IDENTITY", "packet is not between these peers", outcome="refused", security=True)
    enc = envelope.get("enc")
    if not isinstance(enc, dict) or enc.get("alg") != ENC_ALG or enc.get("session") != SESSION_ALG:
        raise LanRefuse("QNS-LAN-VERSION", "encryption metadata refused", outcome="permanent", security=True)
    if set(enc) != {"alg", "session"}:
        raise LanRefuse("QNS-LAN-MALFORMED", "encryption fields refused", outcome="permanent", security=True)
    verify_document(envelope, signer=str(envelope["src_handle"]))
    check_clock(str(envelope.get("created_utc") or ""), str(envelope.get("expiry_utc") or ""))
    body = envelope.get("body")
    if not isinstance(body, dict):
        raise LanRefuse("QNS-LAN-MALFORMED", "body refused", outcome="permanent", security=True)
    try:
        verify_envelope(body)
        inner = open_envelope(node.box_private, node.card, body)
    except LanRefuse:
        raise
    except Exception as exc:
        code = getattr(exc, "code", "QNS-LAN-REFUSED")
        raise LanRefuse(str(code), "envelope refused", outcome="refused", security=True) from exc
    if not isinstance(inner, dict) or inner.get("kind") != "qns-photon":
        raise LanRefuse("QNS-LAN-MALFORMED", "inner kind refused", outcome="permanent", security=True)
    photon = loads(inner.get("photon") or {})
    if photon.photon_id != envelope.get("packet_id") or photon_id(photon) != envelope.get("packet_id"):
        raise LanRefuse("QNS-LAN-FORK", "photon_id mismatch", outcome="refused", security=True)
    expect = sha256_hex(canonical(photon.payload))
    if expect != envelope.get("payload_hash"):
        raise LanRefuse("QNS-LAN-FORK", "payload hash mismatch", outcome="refused", security=True)
    if photon.src != peer["handle"] or photon.dst != node.handle:
        raise LanRefuse("QNS-LAN-IDENTITY", "photon endpoints mismatch", outcome="refused", security=True)


def _store_packet(node: Any, peer: dict[str, Any], envelope: dict[str, Any], prev_ack: str) -> None:
    packet_id = str(envelope["packet_id"])
    payload_hash = str(envelope["payload_hash"])
    path = node.inbox_path(packet_id)
    if path.is_file():
        existing = json.loads(path.read_text(encoding="utf-8"))
        if existing.get("payload_hash") != payload_hash:
            raise LanRefuse("QNS-LAN-FORK", "packet id already stored", outcome="refused", security=True)
        return
    body = envelope["body"]
    node.ledger.preview(str(peer["handle"]), int(body["seq"]), str(body["prev"]), envelope_id(body))
    inner = open_envelope(node.box_private, node.card, body)
    photon = loads(inner["photon"]).to_dict()
    record = {
        "packet_id": packet_id,
        "payload_hash": payload_hash,
        "envelope_id": envelope_id(body),
        "photon": photon,
        "stored_utc": _utc_now(),
        "prev_ack": prev_ack,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True, indent=2) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
    tmp.replace(path)
    node.ledger.accept(str(peer["handle"]), int(body["seq"]), str(body["prev"]), envelope_id(body))
    node.receipts.append(
        node.sign_private,
        handle=node.handle,
        public_key=node.public_key,
        packet_id=packet_id,
        payload_hash=payload_hash,
        from_handle=str(peer["handle"]),
        to_handle=node.handle,
        hop=int(photon.get("hop") or 0) + 1,
        sent_utc=str(envelope.get("created_utc") or ""),
        received_utc=_utc_now(),
        outcome="ok",
    )


def _ack(node: Any, *, packet_id: str, payload_hash: str, level: str, to_handle: str, prev: str) -> dict[str, Any]:
    return sign_document(
        node.sign_private,
        {
            "v": PACKET_V,
            "kind": "delivery-ack",
            "author": AUTHOR,
            "packet_id": packet_id,
            "payload_hash": payload_hash,
            "level": level,
            "from_handle": node.handle,
            "to_handle": to_handle,
            "prev": prev,
            "public_key": node.public_key,
        },
    )


def _write_outcome(sock: socket.socket, node: Any, packet_id: str, payload_hash: str, exc: LanRefuse) -> None:
    try:
        msg = sign_document(
            node.sign_private,
            {
                "v": LAN_V,
                "kind": "outcome",
                "author": AUTHOR,
                "handle": node.handle,
                "public_key": node.public_key,
                "packet_id": packet_id,
                "payload_hash": payload_hash,
                "outcome": exc.outcome,
                "code": exc.code,
                "security": bool(exc.security),
            },
        )
        write_frame(sock, msg)
    except OSError:
        return


def result_from(exc: LanRefuse, *, packet_id: str = "", payload_hash: str = "", transport_accepted: bool = False) -> SendResult:
    return SendResult(
        outcome=exc.outcome if exc.outcome in ("absent", "temporary", "refused", "permanent", "ok") else "refused",
        code=exc.code,
        security=bool(exc.security),
        transport_accepted=transport_accepted,
        packet_id=packet_id,
        payload_hash=payload_hash,
        detail=exc.code,
    )
