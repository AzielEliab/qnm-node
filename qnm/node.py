"""Local node process — QNM-BUILD-1.0 §5.

State: COLD → LOCAL → LIVE (operator bearer) → DEGRADED → ISOLATED
→ PHOENIX_LOCK → SCORCHED.

No auto-heal. No LIVE from site ping. Local API binds 127.0.0.1 only.
Receipts go to disk. Radios stay off.
"""

from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from qnm.apg import APG
from qnm.bearers import Bearers
from qnm.boot import (
    AUTHOR,
    COMPANION,
    IDENTITY,
    SPEC,
    QNMRefuse,
    install,
    load_lock,
    lock_path,
    mark_scorched,
    resume,
)
from qnm.chain import Chain
from qnm.memorial import Memorial
from qnm.outbox import Outbox
from qnm.phoenix import Phoenix
from qnm.score import score_local
from qnm.tethers import Tethers

STATES = (
    "COLD",
    "LOCAL",
    "LIVE",
    "DEGRADED",
    "ISOLATED",
    "PHOENIX_LOCK",
    "SCORCHED",
)

# Forward-only. No auto-heal / reverse.
_FORWARD = {
    "COLD": ("LOCAL",),
    "LOCAL": ("LIVE", "DEGRADED", "ISOLATED", "PHOENIX_LOCK", "SCORCHED"),
    "LIVE": ("DEGRADED", "ISOLATED", "PHOENIX_LOCK", "SCORCHED"),
    "DEGRADED": ("ISOLATED", "PHOENIX_LOCK", "SCORCHED"),
    "ISOLATED": ("PHOENIX_LOCK", "SCORCHED"),
    "PHOENIX_LOCK": ("SCORCHED",),
    "SCORCHED": (),
}

DEFAULT_PORT = 8891
DEFAULT_BIND = "127.0.0.1"
LOCAL_PATHS = {
    "/local/boot",
    "/local/state",
    "/local/bearer",
    "/local/tether",
    "/local/ingress",
    "/local/outbox",
    "/local/outbox/cut",
    "/local/phoenix/arm",
    "/local/receipts",
}


def ensure_data_dirs(root: Path) -> None:
    for name in ("chain", "locks", "outbox", "receipts", "witness"):
        (Path(root) / "data" / name).mkdir(parents=True, exist_ok=True)


def load_cfg(root: Path) -> dict[str, Any]:
    path = Path(root) / "cfg" / "node.json"
    if not path.is_file():
        return {
            "spec": SPEC,
            "companion": COMPANION,
            "author": AUTHOR,
            "bind": DEFAULT_BIND,
            "port": DEFAULT_PORT,
            "radios": "off",
            "auto_heal": False,
            "live_from_site_ping": False,
            "anon_broadcast_publish": False,
        }
    return json.loads(path.read_text(encoding="utf-8"))


class Node:
    def __init__(self, root: Path | None = None, cfg: dict[str, Any] | None = None) -> None:
        self.root = Path(root) if root is not None else Path.cwd()
        ensure_data_dirs(self.root)
        self.cfg = cfg if cfg is not None else load_cfg(self.root)
        self.state = "COLD"
        self.identity = IDENTITY
        self.author = AUTHOR
        self.spec = SPEC
        self.install_root: str | None = None
        self.apg = APG()
        self.bearers = Bearers()
        self.chain = Chain(self.root)
        self.outbox = Outbox(self.root)
        self.tethers = Tethers(self.root)
        self.phoenix = Phoenix()
        self.memorial = Memorial(self.root)
        self._receipt_dir = self.root / "data" / "receipts"
        self._receipt_dir.mkdir(parents=True, exist_ok=True)
        self._receipt_log = self._receipt_dir / "receipts.jsonl"
        if not self._receipt_log.is_file():
            self._receipt_log.write_text("", encoding="utf-8")

    def _write_receipt(self, kind: str, body: dict[str, Any]) -> dict[str, Any]:
        link = self.chain.append(kind, body)
        receipt = {
            "kind": kind,
            "body": body,
            "hash": link.hash,
            "prev": link.prev,
            "seq": link.seq,
            "utc": link.utc,
            "spec": SPEC,
            "author": AUTHOR,
            "on_disk": True,
        }
        with self._receipt_log.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
            fh.flush()
        leaf = self._receipt_dir / f"{link.seq:06d}-{link.hash[:16]}.json"
        leaf.write_text(
            json.dumps(receipt, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return receipt

    def receipts(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for line in self._receipt_log.read_text(encoding="utf-8").splitlines():
            if line.strip():
                items.append(json.loads(line))
        return items

    def _advance(self, dest: str) -> None:
        if dest == self.state:
            return
        allowed = _FORWARD.get(self.state, ())
        if dest not in allowed:
            raise QNMRefuse(
                "QNM-NO-AUTO-HEAL",
                f"{self.state} cannot become {dest}",
            )
        self.state = dest

    def snapshot(self) -> dict[str, Any]:
        chain = self.chain.verify()
        return {
            "ok": True,
            "state": self.state,
            "install_root": self.install_root,
            "identity": self.identity,
            "author": self.author,
            "spec": self.spec,
            "companion": COMPANION,
            "bearers": self.bearers.snapshot(),
            "radios": "off",
            "auto_heal": False,
            "live_from_site_ping": False,
            "phoenix": self.phoenix.status(),
            "tethers": self.tethers.list(),
            "outbox": self.outbox.list(),
            "chain": {"ok": chain["ok"], "length": chain["length"], "tip": chain["tip"]},
            "bind": DEFAULT_BIND,
        }

    def boot(
        self,
        *,
        entropy: bytes | None = None,
        nonce: bytes | None = None,
        genesis: bytes | None = None,
        resume_from: str | Path | None = None,
    ) -> dict[str, Any]:
        if self.state == "SCORCHED":
            raise QNMRefuse("QNM-SCORCHED", "no account resurrection")
        lock = load_lock(self.root)
        if lock and lock.get("scorched"):
            self.install_root = str(lock.get("install_root") or "")
            self.state = "SCORCHED"
            raise QNMRefuse("QNM-NO-ACCOUNT", "scorched lock cannot resume live")
        if lock:
            record = resume(self.root, from_path=resume_from or lock_path(self.root))
        else:
            if resume_from is not None:
                record = resume(self.root, from_path=resume_from)
            else:
                record = install(self.root, entropy=entropy, nonce=nonce, genesis=genesis)
        self.install_root = str(record["install_root"])
        if self.state == "COLD":
            self._advance("LOCAL")
        self._write_receipt("boot", {"install_root": self.install_root, "state": self.state})
        return self.snapshot()

    def set_bearer(self, name: str, on: bool) -> dict[str, Any]:
        self._require_not_scorched()
        if self.state in ("ISOLATED", "PHOENIX_LOCK"):
            raise QNMRefuse("QNM-STATE-LOCKED", f"bearer refused in {self.state}")
        result = self.bearers.set(name, on)
        if name == "operator" and on and self.state == "LOCAL":
            self._advance("LIVE")
        if name == "operator" and not on and self.state == "LIVE":
            # Explicit operator drop is not auto-heal; LIVE requires bearer.
            # Forward-only: LIVE cannot return to LOCAL. Drop degrades.
            self._advance("DEGRADED")
        self._write_receipt("bearer", {"name": name, "on": on, "state": self.state})
        result["state"] = self.state
        return result

    def site_ping(self, url: str = "") -> dict[str, Any]:
        """Site ping never advances to LIVE. No network is opened."""
        _ = url
        if self.cfg.get("live_from_site_ping"):
            raise QNMRefuse("QNM-NO-LIVE-FROM-PING", "cfg forbids LIVE from ping")
        self._write_receipt("site_ping_ignored", {"url_present": bool(url)})
        return {
            "ok": True,
            "state": self.state,
            "live": self.state == "LIVE",
            "from_ping": False,
            "code": "QNM-NO-LIVE-FROM-PING",
            "spec": SPEC,
            "author": AUTHOR,
        }

    def heal(self) -> None:
        raise QNMRefuse("QNM-NO-AUTO-HEAL", "no auto-heal")

    def degrade(self, reason: str = "fault") -> dict[str, Any]:
        self._require_not_scorched()
        if self.state in ("LOCAL", "LIVE"):
            self._advance("DEGRADED")
        self._write_receipt("degrade", {"reason": reason, "state": self.state})
        return self.snapshot()

    def isolate(self, reason: str = "tamper") -> dict[str, Any]:
        self._require_not_scorched()
        if self.state in ("PHOENIX_LOCK",):
            raise QNMRefuse("QNM-STATE-LOCKED", "already waiting locally")
        if self.state != "ISOLATED":
            if "ISOLATED" not in _FORWARD.get(self.state, ()):
                raise QNMRefuse("QNM-TAMPER-ISOLATE", f"cannot isolate from {self.state}")
            self._advance("ISOLATED")
        self.bearers.drop_all_except_local()
        self._write_receipt("tamper_isolate", {"reason": reason, "state": self.state})
        return self.snapshot()

    def check_tamper(self) -> dict[str, Any]:
        verified = self.chain.verify()
        if not verified["ok"]:
            return self.isolate("chain_hash_mismatch")
        return {"ok": True, "tamper": False, "chain": verified}

    def arm_phoenix(self) -> dict[str, Any]:
        self._require_not_scorched()
        self.phoenix.arm()
        self._advance("PHOENIX_LOCK")
        self.bearers.drop_all_except_local()
        self._write_receipt("phoenix_arm", {"waiting": "local", "controller_hunt": False})
        snap = self.snapshot()
        snap["phoenix"] = self.phoenix.status()
        return snap

    def scorch(self, reason: str = "operator") -> dict[str, Any]:
        self._require_not_scorched()
        if self.state != "PHOENIX_LOCK":
            self.phoenix.arm()
            if self.state != "PHOENIX_LOCK":
                self._advance("PHOENIX_LOCK")
        install_root = self.install_root or ""
        memorial = self.memorial.write(install_root, reason)
        self.outbox.clear()
        self.tethers.clear()
        self.bearers.drop_all_except_local()
        mark_scorched(self.root)
        self._advance("SCORCHED")
        self._write_receipt("scorch", {"reason": reason, "memorial": memorial["hash"]})
        return {
            "ok": True,
            "state": self.state,
            "memorial": memorial,
            "resurrectable": False,
            "spec": SPEC,
            "author": AUTHOR,
        }

    def account_resurrect(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse("QNM-NO-ACCOUNT", "no account resurrection")

    def account_restore(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse("QNM-NO-ACCOUNT", "no account resurrection")

    def account_create(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse("QNM-NO-ACCOUNT", "no accounts")

    def declare_tether(self, src: str, dst: str) -> dict[str, Any]:
        self._require_active()
        item = self.tethers.declare(src, dst)
        self._write_receipt("tether_declare", {"src": src, "dst": dst})
        return item

    def cut_tether(self, src: str, dst: str) -> dict[str, Any]:
        self._require_not_scorched()
        result = self.tethers.cut(src, dst)
        self._write_receipt("tether_cut", {"src": src, "dst": dst, "residue": False})
        return result

    def queue_outbox(self, kind: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        self._require_active()
        item = self.outbox.queue(kind, payload)
        self._write_receipt("outbox_queue", {"id": item["id"], "kind": kind})
        return item

    def cut_outbox(self, item_id: str) -> dict[str, Any]:
        self._require_not_scorched()
        result = self.outbox.cut(item_id)
        self._write_receipt("outbox_cut", {"id": item_id})
        return result

    def ingress(self, raw: bytes | str) -> dict[str, Any]:
        self._require_not_scorched()
        payload = self.apg.admit(raw)
        op = str(payload.get("op") or "note")
        if op == "tamper":
            return self.isolate(str(payload.get("reason") or "ingress"))
        if op == "score":
            return self.score()
        if op == "tether":
            action = str(payload.get("action") or "declare")
            src = str(payload.get("src") or "")
            dst = str(payload.get("dst") or "")
            if action == "cut":
                return self.cut_tether(src, dst)
            return self.declare_tether(src, dst)
        self._write_receipt("ingress", {"op": op})
        return {"ok": True, "admitted": True, "op": op, "state": self.state}

    def score(self, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        verified = self.chain.verify()
        return score_local(
            chain_ok=verified["ok"],
            chain_length=verified["length"],
            isolated=self.state == "ISOLATED",
            phoenix=self.state == "PHOENIX_LOCK",
            scorched=self.state == "SCORCHED",
            extra=extra,
        )

    def _require_not_scorched(self) -> None:
        if self.state == "SCORCHED":
            raise QNMRefuse("QNM-SCORCHED", "node scorched")
        lock = load_lock(self.root)
        if lock and lock.get("scorched"):
            self.state = "SCORCHED"
            raise QNMRefuse("QNM-NO-ACCOUNT", "scorched lock")

    def _require_active(self) -> None:
        self._require_not_scorched()
        if self.state in ("COLD", "ISOLATED", "PHOENIX_LOCK"):
            raise QNMRefuse("QNM-STATE-LOCKED", f"inactive in {self.state}")

    def handle(self, method: str, path: str, body: bytes = b"") -> tuple[int, dict[str, Any]]:
        parsed = urlparse(path)
        route = parsed.path.rstrip("/") or "/"
        if route == "/local/outbox/cut":
            route = "/local/outbox/cut"
        elif route != "/local/outbox" and route.startswith("/local/"):
            pass
        if route not in LOCAL_PATHS and route != "/local/outbox/cut":
            return 404, QNMRefuse("QNM-LOOPBACK-ONLY", "unknown local path").as_dict()
        try:
            return 200, self._dispatch(method.upper(), route, body)
        except QNMRefuse as exc:
            return 403, exc.as_dict()

    def _dispatch(self, method: str, route: str, body: bytes) -> dict[str, Any]:
        if route == "/local/state" and method == "GET":
            return self.snapshot()
        if route == "/local/receipts" and method == "GET":
            return {"ok": True, "receipts": self.receipts(), "spec": SPEC, "author": AUTHOR}
        if route == "/local/outbox" and method == "GET":
            return {"ok": True, "outbox": self.outbox.list(), "visible": True}
        if route == "/local/boot" and method == "POST":
            payload = json.loads(body.decode("utf-8") or "{}") if body else {}
            entropy = bytes.fromhex(payload["entropy"]) if payload.get("entropy") else None
            nonce = bytes.fromhex(payload["nonce"]) if payload.get("nonce") else None
            genesis = bytes.fromhex(payload["genesis"]) if payload.get("genesis") else None
            resume_from = payload.get("resume_from")
            return self.boot(
                entropy=entropy,
                nonce=nonce,
                genesis=genesis,
                resume_from=resume_from,
            )
        if route == "/local/bearer" and method == "POST":
            payload = json.loads(body.decode("utf-8") or "{}")
            return self.set_bearer(str(payload.get("name") or ""), bool(payload.get("on")))
        if route == "/local/tether" and method == "POST":
            payload = json.loads(body.decode("utf-8") or "{}")
            op = str(payload.get("op") or "declare")
            src = str(payload.get("src") or payload.get("from") or "")
            dst = str(payload.get("dst") or payload.get("to") or "")
            if op == "cut":
                return self.cut_tether(src, dst)
            return self.declare_tether(src, dst)
        if route == "/local/ingress" and method == "POST":
            return self.ingress(body)
        if route == "/local/outbox/cut" and method == "POST":
            payload = json.loads(body.decode("utf-8") or "{}")
            return self.cut_outbox(str(payload.get("id") or ""))
        if route == "/local/phoenix/arm" and method == "POST":
            return self.arm_phoenix()
        raise QNMRefuse("QNM-LOOPBACK-ONLY", f"{method} {route}")


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
            self._send(403, QNMRefuse("QNM-LOOPBACK-ONLY", "127.0.0.1 only").as_dict())
            return
        code, payload = self.node.handle("GET", self.path, b"")
        self._send(code, payload)

    def do_POST(self) -> None:  # noqa: N802
        if not self._client_ok():
            self._send(403, QNMRefuse("QNM-LOOPBACK-ONLY", "127.0.0.1 only").as_dict())
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        code, payload = self.node.handle("POST", self.path, body)
        self._send(code, payload)


def serve(node: Node, host: str = DEFAULT_BIND, port: int = DEFAULT_PORT) -> ThreadingHTTPServer:
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise QNMRefuse("QNM-LOOPBACK-ONLY", "bind 127.0.0.1 only")
    handler = type("QNMHandler", (_Handler,), {"node": node})
    server = ThreadingHTTPServer((host, port), handler)
    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="qnm-node", description="QNM-BUILD-1.0 local node")
    parser.add_argument("cmd", nargs="?", default="state", help="boot|state|serve|doctor|score")
    parser.add_argument("--root", default=".", help="install root directory")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    node = Node(root)
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
        if args.cmd == "score":
            if node.state == "COLD":
                node.boot()
            print(json.dumps(node.score(), indent=2, sort_keys=True))
            return 0
        if args.cmd == "doctor":
            report = {
                "ok": True,
                "identity": IDENTITY,
                "author": AUTHOR,
                "spec": SPEC,
                "companion": COMPANION,
                "radios": "off",
                "bind": DEFAULT_BIND,
                "forbidden_live_symbols": ["Lumen", "Mandible", "lattice_online", "mesh_complete"],
            }
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0
        if args.cmd == "serve":
            if node.state == "COLD":
                lock = load_lock(root)
                if lock and not lock.get("scorched"):
                    node.boot()
                else:
                    node.boot()
            server = serve(node, DEFAULT_BIND, args.port)
            print(
                json.dumps(
                    {
                        "ok": True,
                        "bind": DEFAULT_BIND,
                        "port": args.port,
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
        print(json.dumps(QNMRefuse("QNM-LOOPBACK-ONLY", args.cmd).as_dict()), file=sys.stderr)
        return 2
    except QNMRefuse as exc:
        print(json.dumps(exc.as_dict(), indent=2, sort_keys=True), file=sys.stderr)
        return 2

