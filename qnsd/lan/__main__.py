"""Operator CLI for the opt-in LAN listener. Not the HTTP door.

Run ``python scripts/qns_lan.py``. That launcher imports ``qnm`` before
this package. ``python -m qnsd.lan`` hits a pre-existing import cycle
and is not the entry point.

``--loopback`` is an explicit single-host opt-in and still sets live false.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from qnsd.lan.contract import DEFAULT_PORT, LanRefuse
from qnsd.lan.node import LanNode


def _node(args: argparse.Namespace, *, enabled: bool) -> LanNode:
    return LanNode(
        Path(args.data_dir),
        enabled=enabled,
        allow_loopback=bool(getattr(args, "loopback", False)),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="qnsd lan-tls (opt-in, not the HTTP door)")
    parser.add_argument("--data-dir", required=True)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init")
    sub.add_parser("show")
    sub.add_parser("verify")

    listen = sub.add_parser("listen")
    listen.add_argument("--bind")
    listen.add_argument("--interface")
    listen.add_argument("--port", type=int, default=DEFAULT_PORT)
    listen.add_argument("--loopback", action="store_true")

    peer = sub.add_parser("peer-add")
    peer.add_argument("--card-file", required=True)
    peer.add_argument("--address", required=True)

    revoke = sub.add_parser("revoke")
    revoke.add_argument("--handle", required=True)
    revoke.add_argument("--reason", default="operator")

    send = sub.add_parser("send")
    send.add_argument("--to", required=True)
    send.add_argument("--text", required=True)
    send.add_argument("--loopback", action="store_true")

    flush = sub.add_parser("flush")
    flush.add_argument("--loopback", action="store_true")

    args = parser.parse_args(argv)
    try:
        if args.cmd == "init":
            node = _node(args, enabled=False)
            print(json.dumps({"ok": True, "handle": node.handle, "live": False}, sort_keys=True))
            return 0
        if args.cmd == "show":
            node = _node(args, enabled=False)
            print(json.dumps(node.public_material(), sort_keys=True))
            return 0
        if args.cmd == "verify":
            node = _node(args, enabled=False)
            print(json.dumps(node.verify(), sort_keys=True))
            return 0
        if args.cmd == "peer-add":
            node = _node(args, enabled=False)
            card = json.loads(Path(args.card_file).read_text(encoding="utf-8"))
            print(json.dumps(node.add_peer(card, args.address), sort_keys=True))
            return 0
        if args.cmd == "revoke":
            node = _node(args, enabled=False)
            print(json.dumps(node.revoke(args.handle, args.reason), sort_keys=True))
            return 0
        if args.cmd == "listen":
            from qnsd.lan.bind import interface_ipv4

            node = _node(args, enabled=True)
            host = args.bind
            if args.interface:
                host = interface_ipv4(args.interface)
                if not host:
                    raise LanRefuse("QNS-LAN-BIND", "interface has no address", outcome="refused", security=True)
            if not host:
                raise LanRefuse("QNS-LAN-BIND", "pass --bind or --interface", outcome="refused", security=True)
            started = node.listen(host, args.port, allow_loopback=bool(args.loopback))
            print(json.dumps(started, sort_keys=True), flush=True)
            try:
                node._stop.wait()
            except KeyboardInterrupt:
                node.close()
            return 0
        if args.cmd == "send":
            node = _node(args, enabled=True)
            result = node.send_payload(args.to, {"text": args.text})
            print(json.dumps(result.as_dict(), sort_keys=True))
            return 0 if result.outcome == "ok" else 2
        if args.cmd == "flush":
            node = _node(args, enabled=True)
            rows = [item.as_dict() for item in node.flush()]
            print(json.dumps({"ok": True, "live": False, "results": rows}, sort_keys=True))
            return 0
    except LanRefuse as exc:
        print(json.dumps({"ok": False, "code": exc.code, "outcome": exc.outcome, "live": False}, sort_keys=True))
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
