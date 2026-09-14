"""SPLIT THE WIRES — QNM-BUILD-1.0 §15.

Fast 0.5–1s tick: presence + tip hash only. Fixed-size. No body /
diff / file on that socket.

Payload lives on a second plane the receiver PULLS — never sender
fan-out push.

Update is a proof, not a timer: cite prev + lockset, fail-closed
verify. 777s is dwell after a valid cite (not wait-then-accept).
Clock desync ≠ yes. Ambiguous tip = isolate, not merge.

Equivocation: same prev, two tips from one node → lock / isolate that
peer. No vote-to-reconcile. Quorum cannot outvote a broken hash.

Emit last locally: announce a tip only after own verify. Phoenix is
local reboot / WAIT for the failed node only — neighbors do not
phoenix because a neighbor did. No unsend of unverified body.

Partition: split brain keeps separate chains, no auto-splice. Rejoin =
cite + operator / lockset. Heartbeat loss ≠ poison and ≠ apply last
packet.

The 1s loop and the 777s gate never share a socket.

Author: Aziel Eliab only. Public tunnels still die with the pull.
Phoenix is not public hostname restore.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Callable

from qnm.boot import AUTHOR, SPEC, QNMRefuse, _atomic_write, sha256_hex

TICK_SOCKET = "tick"
CITE_SOCKET = "cite"
TICK_BYTES = 96
TICK_MS_MIN = 500
TICK_MS_MAX = 1000
DWELL_S = 777
CLOCK_SKEW_MAX_S = 30
HEARTBEAT_SUSPECT = 3
TIP_HEX = 64

_TICK_FORBIDDEN = ("body", "diff", "file", "payload", "blob", "data")


def _peer_bytes(peer: str) -> bytes:
    text = str(peer).strip().lower()
    if len(text) == TIP_HEX:
        try:
            return bytes.fromhex(text)
        except ValueError:
            pass
    return hashlib.sha256(text.encode("utf-8")).digest()


def _tip_bytes(tip: str) -> bytes:
    text = str(tip).strip().lower()
    if len(text) != TIP_HEX:
        raise QNMRefuse("QNM-WIRES-TICK", "tip hash must be 64 hex")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise QNMRefuse("QNM-WIRES-TICK", "tip hash must be 64 hex") from exc


def encode_tick(presence: bool, peer: str, tip: str) -> bytes:
    raw = bytes([1 if presence else 0]) + _peer_bytes(peer) + _tip_bytes(tip)
    if len(raw) > TICK_BYTES:
        raise QNMRefuse("QNM-WIRES-TICK", "tick overflow")
    padded = raw + bytes(TICK_BYTES - len(raw))
    if len(padded) != TICK_BYTES:
        raise QNMRefuse("QNM-WIRES-TICK", "tick must be fixed-size")
    return padded


def decode_tick(frame: bytes) -> dict[str, Any]:
    if not isinstance(frame, (bytes, bytearray)) or len(frame) != TICK_BYTES:
        raise QNMRefuse("QNM-WIRES-TICK", "tick must be fixed-size")
    reserved = bytes(frame[65:])
    if reserved != bytes(TICK_BYTES - 65):
        raise QNMRefuse("QNM-WIRES-TICK", "no body/diff/file on the tick socket")
    return {
        "presence": bool(frame[0]),
        "peer": bytes(frame[1:33]).hex(),
        "tip": bytes(frame[33:65]).hex(),
        "socket": TICK_SOCKET,
        "bytes": TICK_BYTES,
    }


class Wires:
    """Two sockets. Tick is presence+tip. Cite/payload is the other plane."""

    def __init__(
        self,
        root: Path | None = None,
        *,
        now: Callable[[], float] | None = None,
    ) -> None:
        self.root = Path(root) if root is not None else Path.cwd()
        self._now = now or time.time
        self.tick_socket = TICK_SOCKET
        self.cite_socket = CITE_SOCKET
        self.locked_peers: set[str] = set()
        self.suspect: dict[str, int] = {}
        self._by_peer_prev: dict[tuple[str, str], str] = {}
        self._cites: dict[str, dict[str, Any]] = {}
        self._payload_dir = self.root / "data" / "payload"
        self._payload_dir.mkdir(parents=True, exist_ok=True)
        self._state_path = self.root / "data" / "witness" / "wires.json"
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        self._load()

    def _load(self) -> None:
        if not self._state_path.is_file():
            return
        row = json.loads(self._state_path.read_text(encoding="utf-8"))
        self.locked_peers = set(row.get("locked_peers") or [])
        self.suspect = {str(k): int(v) for k, v in dict(row.get("suspect") or {}).items()}
        for item in row.get("observed") or []:
            peer, prev, tip = item[0], item[1], item[2]
            self._by_peer_prev[(str(peer), str(prev))] = str(tip)
        for cid, rec in dict(row.get("cites") or {}).items():
            self._cites[str(cid)] = dict(rec)

    def _flush(self) -> None:
        row = {
            "tick_socket": self.tick_socket,
            "cite_socket": self.cite_socket,
            "locked_peers": sorted(self.locked_peers),
            "suspect": dict(self.suspect),
            "observed": [[p, prev, tip] for (p, prev), tip in sorted(self._by_peer_prev.items())],
            "cites": self._cites,
            "spec": SPEC,
            "author": AUTHOR,
        }
        _atomic_write(
            self._state_path,
            json.dumps(row, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        )

    def snapshot(self) -> dict[str, Any]:
        return {
            "ok": True,
            "tick_socket": self.tick_socket,
            "cite_socket": self.cite_socket,
            "split": self.tick_socket != self.cite_socket,
            "tick_bytes": TICK_BYTES,
            "tick_ms": [TICK_MS_MIN, TICK_MS_MAX],
            "dwell_s": DWELL_S,
            "locked_peers": sorted(self.locked_peers),
            "cites": len(self._cites),
            "spec": SPEC,
            "author": AUTHOR,
        }

    def bind_sockets(self, tick: str, cite: str) -> dict[str, Any]:
        if not tick or not cite or tick == cite:
            raise QNMRefuse(
                "QNM-WIRES-SPLIT",
                "1s loop and 777s gate never share a socket",
            )
        self.tick_socket = tick
        self.cite_socket = cite
        self._flush()
        return self.snapshot()

    def send(self, socket: str, kind: str, **payload: Any) -> dict[str, Any]:
        if socket == self.tick_socket and kind != "tick":
            raise QNMRefuse(
                "QNM-WIRES-SPLIT",
                "1s loop and 777s gate never share a socket",
            )
        if socket == self.cite_socket and kind == "tick":
            raise QNMRefuse(
                "QNM-WIRES-SPLIT",
                "1s loop and 777s gate never share a socket",
            )
        if socket == self.tick_socket and any(k in payload for k in _TICK_FORBIDDEN):
            raise QNMRefuse("QNM-WIRES-TICK", "no body/diff/file on the tick socket")
        if kind == "tick":
            return self.tick(
                peer=str(payload.get("peer") or ""),
                tip=str(payload.get("tip") or ""),
                presence=bool(payload.get("presence", True)),
                socket=socket,
            )
        raise QNMRefuse("QNM-WIRES-SPLIT", f"unknown wire kind:{kind}")

    def tick(
        self,
        *,
        peer: str,
        tip: str,
        presence: bool = True,
        socket: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        sock = socket or self.tick_socket
        if sock == self.cite_socket:
            raise QNMRefuse(
                "QNM-WIRES-SPLIT",
                "1s loop and 777s gate never share a socket",
            )
        if sock != self.tick_socket:
            raise QNMRefuse("QNM-WIRES-SPLIT", "tick uses the tick socket only")
        if extra:
            if any(k in extra for k in _TICK_FORBIDDEN):
                raise QNMRefuse("QNM-WIRES-TICK", "no body/diff/file on the tick socket")
        frame = encode_tick(presence, peer, tip)
        decoded = decode_tick(frame)
        return {
            "ok": True,
            "kind": "tick",
            "socket": self.tick_socket,
            "presence": presence,
            "peer": peer,
            "tip": str(tip).strip().lower(),
            "bytes": len(frame),
            "fixed": True,
            "body": False,
            "decoded": decoded,
            "spec": SPEC,
            "author": AUTHOR,
        }

    def stash_payload(self, body: dict[str, Any] | str | bytes) -> dict[str, Any]:
        """Local store only. The receiver later PULLS. Not a push."""
        if isinstance(body, bytes):
            raw = body
            parsed: Any = None
        elif isinstance(body, str):
            raw = body.encode("utf-8")
            parsed = body
        else:
            raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
            parsed = dict(body)
        payload_id = sha256_hex(raw)
        leaf = self._payload_dir / f"{payload_id}.bin"
        leaf.write_bytes(raw)
        return {
            "ok": True,
            "id": payload_id,
            "stored": True,
            "pushed": False,
            "spec": SPEC,
            "author": AUTHOR,
            "kind": type(parsed).__name__ if parsed is not None else "bytes",
        }

    def pull_payload(self, payload_id: str) -> dict[str, Any]:
        leaf = self._payload_dir / f"{str(payload_id)}.bin"
        if not leaf.is_file():
            raise QNMRefuse("QNM-WIRES-NO-PUSH", "payload plane is receiver-pull; nothing stored")
        raw = leaf.read_bytes()
        try:
            body: Any = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            body = raw.hex()
        return {
            "ok": True,
            "id": payload_id,
            "body": body,
            "pulled": True,
            "pushed": False,
            "socket": self.cite_socket,
            "spec": SPEC,
            "author": AUTHOR,
        }

    def fanout_push(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-WIRES-NO-PUSH",
            "payload on a second plane the receiver PULLS — never sender fan-out push",
        )

    def _verify_lockset(self, lockset: Any, prev: str, tip: str) -> None:
        if not isinstance(lockset, dict) or not lockset:
            raise QNMRefuse("QNM-WIRES-PROOF", "fail-closed: cite prev + lockset")
        if lockset.get("hash_ok") is False or lockset.get("broken") is True:
            raise QNMRefuse("QNM-WIRES-PROOF", "fail-closed verify")
        if not (lockset.get("id") or lockset.get("seal") or lockset.get("lock") or lockset.get("prev")):
            raise QNMRefuse("QNM-WIRES-PROOF", "fail-closed: cite prev + lockset")
        if lockset.get("prev") is not None and str(lockset["prev"]) != prev:
            raise QNMRefuse("QNM-WIRES-PROOF", "fail-closed verify")
        if lockset.get("tip") is not None and str(lockset["tip"]).lower() != tip:
            raise QNMRefuse("QNM-WIRES-PROOF", "fail-closed verify")

    def observe_tip(self, peer: str, prev: str, tip: str) -> None:
        key = (str(peer), str(prev))
        existing = self._by_peer_prev.get(key)
        if existing is not None and existing != tip:
            self.lock_peer(peer)
            raise QNMRefuse(
                "QNM-WIRES-EQUIVOCATION",
                "same prev, two tips from one node → lock/isolate that peer",
            )
        self._by_peer_prev[key] = tip
        self._flush()

    def lock_peer(self, peer: str) -> None:
        self.locked_peers.add(str(peer))
        self._flush()

    def cite(
        self,
        *,
        prev: str,
        tip: str,
        lockset: dict[str, Any],
        peer: str,
        now: float | None = None,
        clock_skew_s: float = 0,
        socket: str | None = None,
    ) -> dict[str, Any]:
        sock = socket or self.cite_socket
        if sock == self.tick_socket:
            raise QNMRefuse(
                "QNM-WIRES-SPLIT",
                "1s loop and 777s gate never share a socket",
            )
        if sock != self.cite_socket:
            raise QNMRefuse("QNM-WIRES-SPLIT", "cite uses the cite socket only")
        if abs(float(clock_skew_s)) > CLOCK_SKEW_MAX_S:
            raise QNMRefuse("QNM-WIRES-CLOCK", "clock desync ≠ yes")
        if not prev or not tip:
            raise QNMRefuse("QNM-WIRES-PROOF", "fail-closed: cite prev + lockset")
        tip_n = str(tip).strip().lower()
        _tip_bytes(tip_n)
        self._verify_lockset(lockset, str(prev), tip_n)
        if str(peer) in self.locked_peers:
            raise QNMRefuse(
                "QNM-WIRES-EQUIVOCATION",
                "same prev, two tips from one node → lock/isolate that peer",
            )
        self.observe_tip(str(peer), str(prev), tip_n)
        t0 = float(self._now() if now is None else now)
        rec = {
            "prev": str(prev),
            "tip": tip_n,
            "peer": str(peer),
            "lockset": dict(lockset),
            "verified": True,
            "accepted": True,
            "cited_at": t0,
            "dwell_until": t0 + DWELL_S,
            "dwell_s": DWELL_S,
            "wait_then_accept": False,
            "socket": self.cite_socket,
        }
        cid = sha256_hex(f"{peer}:{prev}:{tip_n}:{t0}".encode())
        rec["id"] = cid
        self._cites[cid] = rec
        self._flush()
        return {
            "ok": True,
            "id": cid,
            "verified": True,
            "accepted": True,
            "dwell_s": DWELL_S,
            "dwell_until": rec["dwell_until"],
            "cited_at": t0,
            "wait_then_accept": False,
            "socket": self.cite_socket,
            "spec": SPEC,
            "author": AUTHOR,
        }

    def apply_cited(self, cite_id: str, *, now: float | None = None) -> dict[str, Any]:
        rec = self._cites.get(str(cite_id))
        if rec is None or not rec.get("verified"):
            raise QNMRefuse("QNM-WIRES-PROOF", "update is a proof not a timer")
        t1 = float(self._now() if now is None else now)
        remain = rec["dwell_until"] - t1
        if remain > 0:
            return {
                "ok": True,
                "applied": False,
                "dwelling": True,
                "remain_s": remain,
                "wait_then_accept": False,
                "spec": SPEC,
                "author": AUTHOR,
            }
        return {
            "ok": True,
            "applied": True,
            "dwelling": False,
            "remain_s": 0,
            "id": cite_id,
            "spec": SPEC,
            "author": AUTHOR,
        }

    def wait_then_accept(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-WIRES-PROOF",
            "777s = dwell after valid cite (not wait-then-accept)",
        )

    def vote_reconcile(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse("QNM-WIRES-EQUIVOCATION", "no vote-to-reconcile")

    def quorum_override(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse("QNM-WIRES-QUORUM", "quorum cannot outvote a broken hash")

    def announce(
        self,
        *,
        peer: str,
        tip: str,
        verified: bool,
        presence: bool = True,
    ) -> dict[str, Any]:
        if not verified:
            raise QNMRefuse(
                "QNM-WIRES-EMIT-LAST",
                "announce tip only after own verify",
            )
        return self.tick(peer=peer, tip=tip, presence=presence)

    def unsend(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse("QNM-WIRES-NO-UNSEND", "no unsend of unverified body")

    def neighbor_phoenix(self, peer: str = "") -> None:
        _ = peer
        raise QNMRefuse(
            "QNM-PHOENIX-LOCAL-WAIT",
            "Phoenix is local reboot/WAIT for the failed node only — "
            "neighbors do not phoenix because a neighbor did",
        )

    def splice(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-WIRES-NO-SPLICE",
            "split brain keeps separate chains, no auto-splice",
        )

    def merge_tips(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse("QNM-WIRES-AMBIGUOUS", "ambiguous tip = isolate not merge")

    def rejoin(
        self,
        *,
        prev: str,
        tip: str,
        lockset: dict[str, Any],
        peer: str,
        operator: bool = False,
        now: float | None = None,
        clock_skew_s: float = 0,
    ) -> dict[str, Any]:
        if not operator and not (isinstance(lockset, dict) and lockset.get("operator")):
            raise QNMRefuse("QNM-WIRES-REJOIN", "rejoin = cite + operator/lockset")
        rec = self.cite(
            prev=prev,
            tip=tip,
            lockset=lockset,
            peer=peer,
            now=now,
            clock_skew_s=clock_skew_s,
        )
        rec["rejoin"] = True
        rec["operator"] = True
        return rec

    def heartbeat_miss(self, peer: str, misses: int | None = None) -> dict[str, Any]:
        name = str(peer)
        count = int(misses) if misses is not None else self.suspect.get(name, 0) + 1
        self.suspect[name] = count
        self._flush()
        return {
            "ok": True,
            "peer": name,
            "misses": count,
            "suspect": count >= HEARTBEAT_SUSPECT,
            "poison": False,
            "applied": False,
            "isolate": False,
            "phoenix": False,
            "spec": SPEC,
            "author": AUTHOR,
        }

    def apply_last_on_heartbeat_loss(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-WIRES-HEARTBEAT",
            "heartbeat loss ≠ poison and ≠ apply last packet",
        )

    def poison_on_heartbeat_loss(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-WIRES-HEARTBEAT",
            "heartbeat loss ≠ poison and ≠ apply last packet",
        )
