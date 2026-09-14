"""SPLIT THE WIRES — mesh law (Aziel Eliab only).

Two planes that never share a socket:
  tick plane   — 0.5–1s presence + tip hash only. Fixed-size.
  payload plane — receiver PULLS. Never a sender fan-out.

Update is a proof, not a timer. 777s is dwell after a valid cite.
Clock desync is not a yes. Ambiguous tip isolates, it does not merge.
Equivocation ends that peer, not the chain. Majority is not truth.
Emit last, locally. Phoenix is local wait / re-seal. No unsend.
Partition: no auto-splice. Heartbeat loss is not poison and not apply.
Public tunnels and sites die with the pull.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from qnm.boot import AUTHOR, SPEC, QNMRefuse, _utc_now, sha256_hex

WIRES_SPEC = "SPLIT-WIRES-1.0"
TICK_MIN_S = 0.5
TICK_MAX_S = 1.0
DWELL_S = 777
TICK_MAGIC = b"QNT1"
PRESENCE_BYTES = 32
TIP_BYTES = 32
TICK_SIZE = len(TICK_MAGIC) + PRESENCE_BYTES + TIP_BYTES  # 68
TICK_PLANE = "tick"
PAYLOAD_PLANE = "payload"
TICK_SOCKET = "tick_socket"
DWELL_SOCKET = "dwell_socket"
TICK_CLOCK = "tick_0.5_1s"
DWELL_CLOCK = "dwell_777s"
HASH_LEN = 64

_TICK_FORBIDDEN = frozenset(
    {
        "body",
        "diff",
        "file",
        "payload",
        "bytes",
        "blob",
        "content",
        "data",
    }
)


def _parse_utc(stamp: str) -> datetime:
    text = stamp.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text).astimezone(timezone.utc)


def _as_utc(now: datetime | str | None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if isinstance(now, str):
        return _parse_utc(now)
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


def canonical_hash(value: str) -> str:
    digest = str(value or "").strip().lower()
    if len(digest) != HASH_LEN or any(c not in "0123456789abcdef" for c in digest):
        raise QNMRefuse("QNM-WIRES-FAIL-CLOSED", "tip hash must be 64 hex")
    return digest


def pack_tick(presence: str, tip_hash: str) -> bytes:
    """Fixed-size tick: magic + presence digest + tip digest. No body."""
    tip = bytes.fromhex(canonical_hash(tip_hash))
    pres = bytes.fromhex(sha256_hex(str(presence).encode("utf-8")))
    frame = TICK_MAGIC + pres + tip
    if len(frame) != TICK_SIZE:
        raise QNMRefuse("QNM-WIRES-TICK-SIZE", "tick must be fixed-size")
    return frame


def unpack_tick(frame: bytes) -> dict[str, str]:
    if not isinstance(frame, (bytes, bytearray)) or len(frame) != TICK_SIZE:
        raise QNMRefuse("QNM-WIRES-TICK-SIZE", "tick must be fixed-size")
    if bytes(frame[:4]) != TICK_MAGIC:
        raise QNMRefuse("QNM-WIRES-FAIL-CLOSED", "bad tick magic")
    return {
        "plane": TICK_PLANE,
        "presence": bytes(frame[4:36]).hex(),
        "tip_hash": bytes(frame[36:68]).hex(),
    }


@dataclass
class Lockset:
    hashes: frozenset[str]

    @classmethod
    def from_iterable(cls, items: Any) -> "Lockset":
        out: set[str] = set()
        for item in items or ():
            out.add(canonical_hash(str(item)))
        return cls(frozenset(out))

    def holds(self, digest: str) -> bool:
        return canonical_hash(digest) in self.hashes

    def with_hash(self, digest: str) -> "Lockset":
        return Lockset(self.hashes | {canonical_hash(digest)})


@dataclass
class Cite:
    prev: str
    tip: str
    peer: str
    utc: str
    applied: bool = False


@dataclass
class PeerView:
    peer: str
    prev: str | None = None
    tips: set[str] = field(default_factory=set)
    status: str = "live"
    misses: int = 0
    suspect: bool = False
    last_packet: dict[str, Any] | None = None


@dataclass
class Island:
    island_id: str
    tip: str
    spliced: bool = False


class Wires:
    """Local split-the-wires engine. Radios stay off. Planes stay strangers."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = Path(root) if root is not None else Path.cwd()
        self.held_prev = "0" * HASH_LEN
        self.lockset = Lockset(frozenset({self.held_prev}))
        self.pending: Cite | None = None
        self.peers: dict[str, PeerView] = {}
        self.islands: dict[str, Island] = {}
        self.payloads: dict[str, bytes] = {}
        self.emitted: list[dict[str, Any]] = []
        self.verified_local = False
        self.chain_ok = True

    def status(self) -> dict[str, Any]:
        return {
            "ok": True,
            "spec": WIRES_SPEC,
            "companion": SPEC,
            "author": AUTHOR,
            "tick_min_s": TICK_MIN_S,
            "tick_max_s": TICK_MAX_S,
            "dwell_s": DWELL_S,
            "tick_size": TICK_SIZE,
            "planes": {TICK_PLANE: "presence+tip", PAYLOAD_PLANE: "pull-only"},
            "sockets": {TICK_CLOCK: TICK_SOCKET, DWELL_CLOCK: DWELL_SOCKET},
            "shared_socket": False,
            "held_prev": self.held_prev,
            "lockset": sorted(self.lockset.hashes),
            "pending": None
            if self.pending is None
            else {
                "prev": self.pending.prev,
                "tip": self.pending.tip,
                "peer": self.pending.peer,
                "utc": self.pending.utc,
                "applied": self.pending.applied,
            },
            "peers": {
                name: {
                    "status": view.status,
                    "suspect": view.suspect,
                    "misses": view.misses,
                    "tips": sorted(view.tips),
                }
                for name, view in self.peers.items()
            },
            "islands": {
                name: {"tip": isle.tip, "spliced": isle.spliced}
                for name, isle in self.islands.items()
            },
            "live_body_sync": False,
            "auto_splice": False,
            "majority_is_truth": False,
        }

    def refuse_shared_socket(self, clock: str, socket: str) -> None:
        tick_on_dwell = clock == TICK_CLOCK and socket == DWELL_SOCKET
        dwell_on_tick = clock == DWELL_CLOCK and socket == TICK_SOCKET
        if tick_on_dwell or dwell_on_tick or socket in (TICK_SOCKET, DWELL_SOCKET) and clock not in (
            TICK_CLOCK,
            DWELL_CLOCK,
        ):
            raise QNMRefuse(
                "QNM-WIRES-TWO-CLOCKS",
                "1s loop and 777s gate stay strangers",
            )
        if clock == TICK_CLOCK and socket != TICK_SOCKET:
            raise QNMRefuse("QNM-WIRES-TWO-CLOCKS", "tick clock uses tick socket only")
        if clock == DWELL_CLOCK and socket != DWELL_SOCKET:
            raise QNMRefuse("QNM-WIRES-TWO-CLOCKS", "dwell clock uses dwell socket only")

    def admit_tick(self, raw: bytes | dict[str, Any]) -> dict[str, Any]:
        if isinstance(raw, dict):
            extra = set(raw) - {"presence", "tip_hash", "plane"}
            if extra & _TICK_FORBIDDEN:
                raise QNMRefuse("QNM-WIRES-TICK-PLANE", "no body, diff, or file on the tick plane")
            if extra:
                raise QNMRefuse("QNM-WIRES-TICK-PLANE", "tick carries presence + tip hash only")
            if raw.get("plane") not in (None, TICK_PLANE):
                raise QNMRefuse("QNM-WIRES-TICK-PLANE", "tick plane only")
            frame = pack_tick(str(raw.get("presence") or ""), str(raw.get("tip_hash") or ""))
            parsed = unpack_tick(frame)
            parsed["presence_in"] = str(raw.get("presence") or "")
            return parsed
        if isinstance(raw, (bytes, bytearray)) and raw[:4] == TICK_MAGIC:
            return unpack_tick(bytes(raw))
        raise QNMRefuse("QNM-WIRES-TICK-PLANE", "tick is fixed-size presence + tip hash")

    def push_payload(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse("QNM-WIRES-PULL-ONLY", "payload is pulled, never pushed")

    def store_for_pull(self, body: bytes | str, digest: str | None = None) -> str:
        raw = body.encode("utf-8") if isinstance(body, str) else bytes(body)
        tip = digest or sha256_hex(raw)
        tip = canonical_hash(tip)
        if digest is not None and sha256_hex(raw) != tip:
            raise QNMRefuse("QNM-WIRES-FAIL-CLOSED", "payload hash mismatch")
        self.payloads[tip] = raw
        return tip

    def pull_payload(self, digest: str) -> dict[str, Any]:
        tip = canonical_hash(digest)
        if tip not in self.payloads:
            raise QNMRefuse("QNM-WIRES-PULL-ONLY", "no local replica to pull")
        raw = self.payloads[tip]
        if sha256_hex(raw) != tip:
            raise QNMRefuse("QNM-WIRES-FAIL-CLOSED", "pulled body does not match tip")
        return {
            "ok": True,
            "plane": PAYLOAD_PLANE,
            "tip_hash": tip,
            "bytes": len(raw),
            "verified": True,
            "pushed": False,
            "spec": WIRES_SPEC,
            "author": AUTHOR,
        }

    def time_is_not_authorization(self, *, authorize_by_clock: bool = False) -> None:
        if authorize_by_clock:
            raise QNMRefuse("QNM-WIRES-CLOCK-DESYNC", "clock desync is not a yes")

    def cite(
        self,
        *,
        prev: str,
        tip: str,
        peer: str = "local",
        lockset: Lockset | None = None,
        now: datetime | str | None = None,
        authorize_by_clock: bool = False,
    ) -> dict[str, Any]:
        self.time_is_not_authorization(authorize_by_clock=authorize_by_clock)
        cited_prev = canonical_hash(prev)
        new_tip = canonical_hash(tip)
        held = Lockset(self.lockset.hashes if lockset is None else lockset.hashes)
        if cited_prev != self.held_prev:
            raise QNMRefuse("QNM-WIRES-FAIL-CLOSED", "new tip must cite held prev")
        if not held.holds(cited_prev):
            raise QNMRefuse("QNM-WIRES-FAIL-CLOSED", "prev is not in the lockset")
        if new_tip == cited_prev:
            raise QNMRefuse("QNM-WIRES-FAIL-CLOSED", "tip must advance from prev")
        utc = _as_utc(now).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.lockset = held
        self.pending = Cite(prev=cited_prev, tip=new_tip, peer=peer, utc=utc)
        return {
            "ok": True,
            "cited": True,
            "applied": False,
            "prev": cited_prev,
            "tip": new_tip,
            "peer": peer,
            "utc": utc,
            "dwell_s": DWELL_S,
            "dwell_is_timer_to_take_whatever": False,
            "spec": WIRES_SPEC,
            "author": AUTHOR,
        }

    def apply_cited(
        self,
        *,
        now: datetime | str | None = None,
        arrived_tip: str | None = None,
    ) -> dict[str, Any]:
        if self.pending is None:
            raise QNMRefuse("QNM-WIRES-FAIL-CLOSED", "no valid cite to dwell")
        if arrived_tip is not None and canonical_hash(arrived_tip) != self.pending.tip:
            raise QNMRefuse(
                "QNM-WIRES-DWELL-CITE",
                "777s is dwell after a valid cite, not take whatever arrived",
            )
        elapsed = _as_utc(now) - _parse_utc(self.pending.utc)
        if elapsed < timedelta(seconds=DWELL_S):
            return {
                "ok": True,
                "applied": False,
                "dwell_complete": False,
                "dwell_s": DWELL_S,
                "tip": self.pending.tip,
                "spec": WIRES_SPEC,
                "author": AUTHOR,
            }
        self.held_prev = self.pending.tip
        self.lockset = self.lockset.with_hash(self.pending.tip)
        self.pending.applied = True
        applied = self.pending
        return {
            "ok": True,
            "applied": True,
            "dwell_complete": True,
            "prev": applied.prev,
            "tip": applied.tip,
            "peer": applied.peer,
            "spec": WIRES_SPEC,
            "author": AUTHOR,
        }

    def isolate_ambiguous(self, peer: str, tips: list[str]) -> dict[str, Any]:
        unique = {canonical_hash(t) for t in tips}
        if len(unique) < 2:
            raise QNMRefuse("QNM-WIRES-FAIL-CLOSED", "ambiguous tip needs two candidates")
        view = self._peer(peer)
        view.status = "isolated"
        return {
            "ok": False,
            "isolated": True,
            "merged": False,
            "peer": peer,
            "code": "QNM-WIRES-AMBIGUOUS",
            "tips": sorted(unique),
            "spec": WIRES_SPEC,
            "author": AUTHOR,
        }

    def note_peer_tip(self, peer: str, prev: str, tip: str) -> dict[str, Any]:
        cited_prev = canonical_hash(prev)
        new_tip = canonical_hash(tip)
        view = self._peer(peer)
        if view.status in ("isolated", "locked"):
            raise QNMRefuse("QNM-WIRES-EQUIVOCATION", f"peer {peer} already locked")
        if view.prev == cited_prev and view.tips and new_tip not in view.tips:
            view.status = "locked"
            view.tips.add(new_tip)
            return {
                "ok": False,
                "peer": peer,
                "status": "locked",
                "chain_ends": False,
                "vote_to_reconcile": False,
                "code": "QNM-WIRES-EQUIVOCATION",
                "prev": cited_prev,
                "tips": sorted(view.tips),
                "spec": WIRES_SPEC,
                "author": AUTHOR,
            }
        view.prev = cited_prev
        view.tips.add(new_tip)
        return {
            "ok": True,
            "peer": peer,
            "status": view.status,
            "prev": cited_prev,
            "tip": new_tip,
            "spec": WIRES_SPEC,
            "author": AUTHOR,
        }

    def quorum_cannot_outvote(self, digest: str, votes: int, *, broken: bool = True) -> None:
        _ = votes
        if broken:
            raise QNMRefuse(
                "QNM-WIRES-HASH-ABSOLUTE",
                "quorum cannot outvote a broken hash; majority is not truth",
            )
        canonical_hash(digest)

    def mark_verified(self, chain_ok: bool) -> None:
        self.chain_ok = bool(chain_ok)
        self.verified_local = bool(chain_ok)

    def emit_tick(self, presence: str, tip_hash: str) -> dict[str, Any]:
        if not self.chain_ok or not self.verified_local:
            raise QNMRefuse("QNM-WIRES-EMIT-LAST", "announce tip only after own verify passes")
        tip = canonical_hash(tip_hash)
        frame = pack_tick(presence, tip)
        rec = {
            "ok": True,
            "plane": TICK_PLANE,
            "presence": presence,
            "tip_hash": tip,
            "tick": frame.hex(),
            "size": len(frame),
            "body": False,
            "verified": True,
            "spec": WIRES_SPEC,
            "author": AUTHOR,
        }
        self.emitted.append(rec)
        return rec

    def leave_box(self, item: dict[str, Any]) -> dict[str, Any]:
        if item.get("body") and not item.get("verified"):
            raise QNMRefuse("QNM-WIRES-NO-UNSEND", "nothing leaving the box is an unverified body")
        if item.get("plane") == PAYLOAD_PLANE and item.get("push"):
            raise QNMRefuse("QNM-WIRES-PULL-ONLY", "payload is pulled, never pushed")
        return {"ok": True, "left": True, "verified": True, "unsend": False}

    def unsend(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse("QNM-WIRES-NO-UNSEND", "no unsend")

    def neighbor_phoenix(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-PHOENIX-LOCAL-WAIT",
            "Phoenix is local wait / re-seal; neighbors do not phoenix because a neighbor phoenix'd",
        )

    def keep_island(self, island_id: str, tip: str) -> dict[str, Any]:
        isle = Island(island_id=island_id, tip=canonical_hash(tip))
        self.islands[island_id] = isle
        return {"ok": True, "island": island_id, "tip": isle.tip, "spliced": False}

    def splice(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse("QNM-WIRES-NO-SPLICE", "split brain: no auto-splice on reconnect")

    def rejoin(
        self,
        *,
        prev: str,
        tip: str,
        operator: bool = False,
        lockset: Lockset | None = None,
        now: datetime | str | None = None,
        peer: str = "rejoin",
    ) -> dict[str, Any]:
        if not operator and lockset is None:
            raise QNMRefuse(
                "QNM-WIRES-REJOIN-CITE",
                "rejoin is cite + human/operator or lockset gate, same as first ingest",
            )
        return self.cite(
            prev=prev,
            tip=tip,
            peer=peer,
            lockset=lockset,
            now=now,
        )

    def heartbeat_miss(self, peer: str) -> dict[str, Any]:
        view = self._peer(peer)
        view.misses += 1
        if view.misses >= 3:
            view.suspect = True
        return {
            "ok": True,
            "peer": peer,
            "misses": view.misses,
            "suspect": view.suspect,
            "poison": False,
            "applied_last_packet": False,
            "isolated": view.status == "isolated",
            "spec": WIRES_SPEC,
            "author": AUTHOR,
        }

    def apply_last_on_heartbeat_loss(self, peer: str) -> None:
        view = self._peer(peer)
        _ = view.last_packet
        raise QNMRefuse(
            "QNM-WIRES-HEARTBEAT",
            "heartbeat loss is not poison and is not apply last packet",
        )

    def _peer(self, peer: str) -> PeerView:
        name = str(peer or "").strip() or "peer"
        if name not in self.peers:
            self.peers[name] = PeerView(peer=name)
        return self.peers[name]


def wires_from_disk(root: Path) -> Wires:
    engine = Wires(root)
    path = Path(root) / "data" / "witness" / "wires.json"
    if not path.is_file():
        return engine
    row = json.loads(path.read_text(encoding="utf-8"))
    engine.held_prev = str(row.get("held_prev") or engine.held_prev)
    engine.lockset = Lockset.from_iterable(row.get("lockset") or [engine.held_prev])
    return engine
