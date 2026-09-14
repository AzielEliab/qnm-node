"""Internal bitmesh geo plane — FABRIC-MESH-PIPELINE-1.0.

Geohash (or equivalent) binds to a tip for **internal bitmesh routing
only**. This is not public ACT-RECEIPT geo. Public receipts stay no
user / no geo / no IP.

Author: Aziel Eliab only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from qnm.boot import AUTHOR, SPEC, QNMRefuse, _utc_now, sha256_hex

BITMESH_SPEC = "BITMESH-GEO-1.0"
BITMESH_PLANE = "bitmesh-internal"
GEOHASH_BASE32 = "0123456789bcdefghjkmnpqrstuvwxyz"

PUBLIC_GEO_KEYS = frozenset(
    {
        "geo",
        "geohash",
        "lat",
        "lon",
        "latitude",
        "longitude",
        "location",
        "user",
        "user_id",
        "userid",
        "ip",
        "client_ip",
    }
)


def geohash(lat: float, lon: float, *, precision: int = 8) -> str:
    """Encode a WGS-84 point. Internal routing token only."""
    if lat < -90.0 or lat > 90.0 or lon < -180.0 or lon > 180.0:
        raise QNMRefuse("QNM-BITMESH-GEO", "lat/lon out of range")
    precision = max(1, min(int(precision), 12))
    lat_range = [-90.0, 90.0]
    lon_range = [-180.0, 180.0]
    bits: list[int] = []
    lon_bit = True
    while len(bits) < precision * 5:
        if lon_bit:
            mid = (lon_range[0] + lon_range[1]) / 2.0
            if lon >= mid:
                bits.append(1)
                lon_range[0] = mid
            else:
                bits.append(0)
                lon_range[1] = mid
        else:
            mid = (lat_range[0] + lat_range[1]) / 2.0
            if lat >= mid:
                bits.append(1)
                lat_range[0] = mid
            else:
                bits.append(0)
                lat_range[1] = mid
        lon_bit = not lon_bit
    chars: list[str] = []
    for index in range(0, len(bits), 5):
        value = 0
        for bit in bits[index : index + 5]:
            value = (value << 1) | bit
        chars.append(GEOHASH_BASE32[value])
    return "".join(chars)


def public_receipt_has_geo(payload: dict[str, Any] | None) -> bool:
    """True when a public-facing mapping carries user/geo/IP keys."""
    return bool(_geo_keys_in(payload or {}))


def _geo_keys_in(obj: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(obj, dict):
        for key, value in obj.items():
            lowered = str(key).lower()
            if lowered in PUBLIC_GEO_KEYS:
                found.add(lowered)
            found |= _geo_keys_in(value)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            found |= _geo_keys_in(item)
    return found


def refuse_public_geo(payload: dict[str, Any] | None) -> dict[str, Any]:
    """Public receipts stay no user / geo. Refuse; do not rewrite."""
    body = dict(payload or {})
    if public_receipt_has_geo(body):
        raise QNMRefuse(
            "QNM-NO-PUBLIC-GEO",
            "public receipts stay no user/geo; bitmesh geo is internal only",
        )
    return body


class Bitmesh:
    """Internal geohash binds. Never a public ACT-RECEIPT field."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.dir = self.root / "data" / "bitmesh"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "binds.jsonl"
        if not self.path.is_file():
            self.path.write_text("", encoding="utf-8")

    def status(self) -> dict[str, Any]:
        return {
            "ok": True,
            "spec": BITMESH_SPEC,
            "build": SPEC,
            "author": AUTHOR,
            "plane": BITMESH_PLANE,
            "public": False,
            "public_receipt_geo": False,
            "binds": len(self.list()),
        }

    def list(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                items.append(json.loads(line))
        return items

    def bind(
        self,
        tip: str,
        *,
        lat: float,
        lon: float,
        precision: int = 8,
        public: bool = False,
    ) -> dict[str, Any]:
        """Bind a geohash to a tip on the internal bitmesh plane."""
        if public:
            raise QNMRefuse(
                "QNM-NO-PUBLIC-GEO",
                "bitmesh geo is not a public ACT-RECEIPT field",
            )
        digest = str(tip or "").strip().lower()
        if len(digest) != 64:
            raise QNMRefuse("QNM-WIRES-FAIL-CLOSED", "bitmesh bind needs a tip hash")
        token = geohash(float(lat), float(lon), precision=precision)
        rec = {
            "tip": digest,
            "geohash": token,
            "precision": int(precision),
            "plane": BITMESH_PLANE,
            "public": False,
            "public_receipt": False,
            "act_receipt_geo": False,
            "utc": _utc_now(),
            "spec": BITMESH_SPEC,
            "author": AUTHOR,
            "bind_id": sha256_hex(f"{digest}:{token}".encode("utf-8")),
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n")
            fh.flush()
        return rec

    def for_tip(self, tip: str) -> list[dict[str, Any]]:
        digest = str(tip or "").strip().lower()
        return [row for row in self.list() if row.get("tip") == digest]

    def route_token(self, tip: str) -> str | None:
        rows = self.for_tip(tip)
        if not rows:
            return None
        return str(rows[-1].get("geohash") or "") or None
