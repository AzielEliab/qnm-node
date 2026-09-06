"""AnonBroadcast loopback-only style tool — QNM-BUILD-1.0.

Radios off. Render stays on this machine. Never a publish path.
Not a Softwares-tab product. Author: Aziel Eliab only.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SPEC = "QNM-BUILD-1.0"
AUTHOR = "Aziel Eliab"
RADIOS = "off"


class AnonBroadcastRefuse(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(code if not detail else f"{code}: {detail}")


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def render(text: str, dest_dir: Path) -> dict[str, Any]:
    """Write a local communique receipt. Does not publish."""
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    record = {
        "kind": "anon-broadcast-loopback",
        "sha256": digest,
        "title": text[:80],
        "radios": RADIOS,
        "published": False,
        "loopback": True,
        "utc": _utc(),
        "spec": SPEC,
        "author": AUTHOR,
    }
    path = dest_dir / f"{digest[:16]}.json"
    path.write_text(json.dumps(record, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return {**record, "path": str(path)}


def publish(*_args: object, **_kwargs: object) -> None:
    raise AnonBroadcastRefuse(
        "QNM-ANON-NO-PUBLISH",
        "anon-broadcast is never a publish path",
    )
