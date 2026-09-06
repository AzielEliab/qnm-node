"""Spiderweb forward — AIH-WP-1.3.

Many pair-ids per live node. Forward A→B→C only along existing pair
edges, after APG pass, while the hop node is not isolated/locked and
the hop bearer is enabled.

hop_max default 8. Seen-hash list; loops drop.

Wi-Fi / hop bearer dies → path gone, bind remains. Outbox keeps the
frame. Waiting is not death.

Poison and tamper do not ride the spiderweb.

THIS IS NOT Bell-pair physics. No qubit claims.

Author: Aziel Eliab only. Node law: QNM-BUILD-1.0.
"""

from __future__ import annotations

import json
from collections import deque
from typing import TYPE_CHECKING, Any

from qnm.boot import AUTHOR, QNMRefuse, sha256_hex
from qnm.pairs import HOP_MAX_DEFAULT, NODE_SPEC, PAIR_SPEC

if TYPE_CHECKING:
    from qnm.node import Node

_NO_EDGES = ("COLD", "ISOLATED", "PHOENIX_LOCK", "SCORCHED")


def frame_id(src: str, dest: str, payload: dict[str, Any], salt: str = "") -> str:
    core = {
        "dest": dest,
        "payload": payload,
        "salt": salt,
        "src": src,
    }
    return sha256_hex(
        json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
    )


def _canonical_frame(frame: dict[str, Any]) -> bytes:
    return json.dumps(frame, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


class Spiderweb:
    """In-process pair graph. Not a radio mesh. Not a login mesh."""

    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}

    def attach(self, node: Node) -> None:
        if not node.install_root:
            raise QNMRefuse("AIH-HANDSHAKE", "boot before spiderweb attach")
        self.nodes[str(node.install_root).lower()] = node
        node.spiderweb = self

    def _alive(self, node: Node) -> bool:
        return node.state not in _NO_EDGES

    def path_roots(self, src: str, dest: str) -> list[str] | None:
        src_k, dest_k = src.lower(), dest.lower()
        if src_k == dest_k:
            return [src_k]
        start = self.nodes.get(src_k)
        if start is None or not self._alive(start):
            return None
        q: deque[list[str]] = deque([[src_k]])
        seen = {src_k}
        while q:
            path = q.popleft()
            cur = self.nodes.get(path[-1])
            if cur is None or not self._alive(cur):
                continue
            for peer in cur.pairs.peers():
                pk = peer.lower()
                if pk in seen:
                    continue
                nxt = path + [pk]
                if pk == dest_k:
                    return nxt
                seen.add(pk)
                q.append(nxt)
        return None

    def forward(
        self,
        src: Node,
        dest: str,
        payload: dict[str, Any] | bytes | str,
        *,
        via: str | None = None,
        hop_max: int = HOP_MAX_DEFAULT,
        seen: list[str] | None = None,
        salt: str = "",
    ) -> dict[str, Any]:
        if src.install_root is None:
            raise QNMRefuse("AIH-NO-EDGES", "source has no install_root")
        if isinstance(payload, (bytes, str)):
            admitted = src.apg.admit(payload)
        else:
            admitted = src.apg.admit(
                json.dumps(payload, sort_keys=True, separators=(",", ":"))
            )
        self._refuse_physics(admitted)
        dest_k = str(dest).lower()
        src_k = str(src.install_root).lower()
        fid = frame_id(src_k, dest_k, admitted, salt)
        seen_list = list(seen or [])
        if fid in seen_list:
            return self._drop("AIH-LOOP-DROP", "frame hash already seen", hops=0)
        seen_list.append(fid)
        if src_k in seen_list and seen_list.count(src_k) > 1:
            return self._drop("AIH-LOOP-DROP", "source already on seen list", hops=0)
        if src_k not in seen_list:
            seen_list.append(src_k)

        frame = {
            "kind": "spiderweb-frame",
            "src": src_k,
            "dest": dest_k,
            "via": via or "",
            "hops": 0,
            "hop_max": int(hop_max),
            "seen": seen_list,
            "payload": admitted,
            "frame_id": fid,
            "pair_path": [],
            "bell_pair": False,
            "qubit": False,
            "spec": PAIR_SPEC,
            "companion": NODE_SPEC,
            "author": AUTHOR,
        }
        return self._walk(src, frame)

    def _walk(self, current: Node, frame: dict[str, Any]) -> dict[str, Any]:
        if current.state in _NO_EDGES:
            raise QNMRefuse("AIH-NO-EDGES", f"no spiderweb edges in {current.state}")
        # APG on every hop — poison never rides.
        admitted = current.apg.admit(_canonical_frame(frame))
        self._refuse_physics(admitted.get("payload") if isinstance(admitted.get("payload"), dict) else admitted)
        dest = str(frame["dest"]).lower()
        me = str(current.install_root or "").lower()
        if me == dest:
            current._write_receipt(
                "spiderweb_deliver",
                {"frame_id": frame["frame_id"], "hops": frame["hops"]},
            )
            return {
                "ok": True,
                "delivered": True,
                "waiting": False,
                "death": False,
                "at": me,
                "hops": frame["hops"],
                "seen": list(frame["seen"]),
                "pair_path": list(frame["pair_path"]),
                "spec": PAIR_SPEC,
                "companion": NODE_SPEC,
                "author": AUTHOR,
            }

        hops = int(frame["hops"])
        hop_max = int(frame.get("hop_max") or HOP_MAX_DEFAULT)
        if hops >= hop_max:
            return self._drop("AIH-HOP-MAX", f"hops {hops} >= hop_max {hop_max}", hops=hops)

        via = str(frame.get("via") or "") or self._any_enabled_bearer(current)
        if not via or not current.bearers.is_on(via):
            return current._queue_path_wait(frame, via or "none")

        path = self.path_roots(me, dest)
        if path is None or len(path) < 2:
            return current._queue_path_wait(frame, via)

        nxt = path[1]
        seen = list(frame.get("seen") or [])
        if nxt in seen:
            return self._drop("AIH-LOOP-DROP", "next hop already seen", hops=hops)
        peer = self.nodes.get(nxt)
        if peer is None:
            return current._queue_path_wait(frame, via)
        if not current.pairs.has_edge(nxt):
            raise QNMRefuse("AIH-NO-EDGES", "forward only along existing pair edges")
        if not self._alive(peer):
            raise QNMRefuse("AIH-NO-EDGES", f"peer {peer.state} has no edges")
        if not peer.bearers.is_on(via) and via != "local":
            # Next hop cannot carry this via today — path gone, bind remains.
            return current._queue_path_wait(frame, via)

        pair = next(
            (p for p in current.pairs.list() if str(p.get("peer") or "").lower() == nxt),
            None,
        )
        pair_id = str((pair or {}).get("pair_id") or "")
        next_frame = dict(frame)
        next_frame["hops"] = hops + 1
        next_frame["via"] = via
        next_frame["seen"] = seen + [nxt]
        next_frame["pair_path"] = list(frame.get("pair_path") or []) + [pair_id]
        current._write_receipt(
            "spiderweb_hop",
            {"to": nxt, "via": via, "hops": next_frame["hops"], "pair_id": pair_id},
        )
        return self._walk(peer, next_frame)

    def _any_enabled_bearer(self, node: Node) -> str:
        snap = node.bearers.snapshot()
        for name in ("lan", "operator", "local"):
            if snap.get(name):
                return name
        return "local"

    def _refuse_physics(self, payload: dict[str, Any]) -> None:
        if not isinstance(payload, dict):
            return
        if payload.get("bell_pair") is True or payload.get("qubit") is True:
            raise QNMRefuse("AIH-NOT-BELL", "not Bell-pair physics; no qubit claims")
        op = str(payload.get("op") or "")
        if op in ("bell_pair", "qubit", "entangle"):
            raise QNMRefuse("AIH-NOT-BELL", "not Bell-pair physics; no qubit claims")

    def _drop(self, code: str, detail: str, *, hops: int) -> dict[str, Any]:
        return {
            "ok": False,
            "dropped": True,
            "waiting": False,
            "death": False,
            "code": code,
            "detail": detail,
            "hops": hops,
            "spec": PAIR_SPEC,
            "companion": NODE_SPEC,
            "author": AUTHOR,
        }
