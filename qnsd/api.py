"""Local HTTP API — QNS-CD-1.0.

Binds 127.0.0.1 ONLY. Port from cfg (default 8891). Not a Node Gate.
GET mesh is not a route and never enables.
"""

from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from qnsd.boot import AUTHOR, SPEC, QNSRefuse, load_lock
from qnsd.node import DEFAULT_BIND, DEFAULT_PORT, Node
from qnsd.photon import HOP_MAX_DEFAULT

LOCAL_PATHS = {
    "/local/boot",
    "/local/state",
    "/local/policy",
    "/local/declare",
    "/local/pair",
    "/local/ingress",
    "/local/forward",
    "/local/outbox",
    "/local/outbox/cut",
    "/local/receipts",
    "/local/phoenix/arm",
}


class _Handler(BaseHTTPRequestHandler):
    node: Node

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def _client_ok(self) -> bool:
        host = self.client_address[0]
        return host in ("127.0.0.1", "::1")

    def _send(self, code: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        if not self._client_ok():
            self._send(403, QNSRefuse("QNM-LOOPBACK-ONLY", "127.0.0.1 only").as_dict())
            return
        code, payload = self.node.handle("GET", self.path, b"")
        self._send(code, payload)

    def do_POST(self) -> None:  # noqa: N802
        if not self._client_ok():
            self._send(403, QNSRefuse("QNM-LOOPBACK-ONLY", "127.0.0.1 only").as_dict())
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        code, payload = self.node.handle("POST", self.path, body)
        self._send(code, payload)


def serve(node: Node, host: str = DEFAULT_BIND, port: int = DEFAULT_PORT) -> ThreadingHTTPServer:
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise QNSRefuse("QNM-LOOPBACK-ONLY", "bind 127.0.0.1 only")
    handler = type("QNSDHandler", (_Handler,), {"node": node})
    return ThreadingHTTPServer((host, port), handler)


def handle_node(node: Node, method: str, path: str, body: bytes = b"") -> tuple[int, dict[str, Any]]:
    """HTTP dispatch used by Node.handle and the loopback server."""
    parsed = urlparse(path)
    route = parsed.path.rstrip("/") or "/"
    if route not in LOCAL_PATHS:
        return 404, QNSRefuse("QNM-LOOPBACK-ONLY", "unknown local path").as_dict()
    try:
        return 200, _dispatch(node, method.upper(), route, body)
    except QNSRefuse as exc:
        return 403, exc.as_dict()


def attach_handle(node: Node) -> Node:
    return node


def _dispatch(node: Node, method: str, route: str, body: bytes) -> dict[str, Any]:
    if route == "/local/state" and method == "GET":
        return node.snapshot()
    if route == "/local/receipts" and method == "GET":
        return {"ok": True, "receipts": node.receipts(), "spec": SPEC, "author": AUTHOR}
    if route == "/local/outbox" and method == "GET":
        return {"ok": True, "outbox": node.outbox.list(), "visible": True}
    if route == "/local/boot" and method == "POST":
        payload = json.loads(body.decode("utf-8") or "{}") if body else {}
        entropy = bytes.fromhex(payload["entropy"]) if payload.get("entropy") else None
        nonce = bytes.fromhex(payload["nonce"]) if payload.get("nonce") else None
        genesis = bytes.fromhex(payload["genesis"]) if payload.get("genesis") else None
        return node.boot(
            entropy=entropy,
            nonce=nonce,
            genesis=genesis,
            resume_from=payload.get("resume_from"),
        )
    if route == "/local/policy" and method == "POST":
        payload = json.loads(body.decode("utf-8") or "{}") if body else {}
        return node.set_policy(payload)
    if route == "/local/declare" and method == "POST":
        payload = json.loads(body.decode("utf-8") or "{}") if body else {}
        via = str(payload.get("via") or payload.get("name") or "")
        extra = {k: v for k, v in payload.items() if k not in ("via", "name")}
        return node.declare(via, extra)
    if route == "/local/pair" and method == "POST":
        payload = json.loads(body.decode("utf-8") or "{}") if body else {}
        op = str(payload.get("op") or payload.get("phase") or "offer")
        if op == "cut":
            return node.pair_cut(str(payload.get("pair_id") or ""))
        if op == "offer":
            return node.pair_offer(
                str(payload.get("peer") or payload.get("root_b") or ""),
                nonce=payload.get("nonce") or payload.get("nonce_a"),
                via=payload.get("via"),
            )
        if op == "accept":
            return node.pair_accept(
                dict(payload.get("offer") or payload),
                nonce=payload.get("nonce") or payload.get("nonce_b"),
                via=payload.get("via"),
            )
        if op == "seal":
            return node.pair_seal(dict(payload.get("accept") or payload), via=payload.get("via"))
        raise QNSRefuse("AIH-HANDSHAKE", f"unknown pair op:{op}")
    if route == "/local/ingress" and method == "POST":
        via = "local"
        if body:
            try:
                peek = json.loads(body.decode("utf-8"))
                if isinstance(peek, dict) and peek.get("via"):
                    via = str(peek["via"])
            except json.JSONDecodeError:
                via = "local"
        return node.ingress(body, via=via)
    if route == "/local/forward" and method == "POST":
        payload = json.loads(body.decode("utf-8") or "{}") if body else {}
        return node.forward(
            str(payload.get("dest") or payload.get("dst") or ""),
            dict(payload.get("payload") or payload.get("photon", {}).get("payload") or {}),
            via=payload.get("via"),
            via_in=str(payload.get("via_in") or ""),
            hop_max=int(payload.get("hop_max") or node.policy.hop_max or HOP_MAX_DEFAULT),
            seen=list(payload.get("seen") or []),
            pair_id=str(payload.get("pair_id") or ""),
            start_at=payload.get("start_at"),
        )
    if route == "/local/outbox/cut" and method == "POST":
        payload = json.loads(body.decode("utf-8") or "{}")
        return node.cut_outbox(str(payload.get("id") or ""))
    if route == "/local/phoenix/arm" and method == "POST":
        return node.arm_phoenix()
    raise QNSRefuse("QNM-LOOPBACK-ONLY", f"{method} {route}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="qnsd",
        description="QNS-CD-1.0 local Quantum Node Signal daemon",
    )
    parser.add_argument("cmd", nargs="?", default="state", help="boot|state|serve|doctor")
    parser.add_argument("--root", default=".", help="install root directory")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    node = attach_handle(Node(root))
    cfg = node.cfg
    port = int(cfg.get("port") or args.port)
    try:
        if args.cmd == "boot":
            print(json.dumps(node.boot(), indent=2, sort_keys=True))
            return 0
        if args.cmd == "state":
            lock = load_lock(root)
            if lock and not lock.get("scorched") and node.state == "COLD":
                node.boot()
            print(json.dumps(node.snapshot(), indent=2, sort_keys=True))
            return 0
        if args.cmd == "doctor":
            report = {
                "ok": True,
                "identity": node.identity,
                "author": AUTHOR,
                "spec": SPEC,
                "via_order": list(node.snapshot()["via_order"]),
                "bind": DEFAULT_BIND,
                "radios": "off",
                "sticky_via": False,
                "softwares_tab": False,
                "node_gate": False,
                "mesh_enable": False,
            }
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0
        if args.cmd == "serve":
            if node.state == "COLD":
                node.boot()
            server = serve(node, DEFAULT_BIND, port if args.port == DEFAULT_PORT else args.port)
            print(
                json.dumps(
                    {
                        "ok": True,
                        "bind": DEFAULT_BIND,
                        "port": server.server_address[1],
                        "spec": SPEC,
                        "author": AUTHOR,
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                server.shutdown()
            return 0
        print(json.dumps(QNSRefuse("QNM-LOOPBACK-ONLY", args.cmd).as_dict()), file=sys.stderr)
        return 2
    except QNSRefuse as exc:
        print(json.dumps(exc.as_dict(), indent=2, sort_keys=True), file=sys.stderr)
        return 2


# Nodes constructed for tests get handle via attach in tests or here.
def NodeWithApi(root: Path | None = None) -> Node:
    return attach_handle(Node(root))
