"""QNS1 photon — QNS-CD-1.0 / QNS-WP-1.3.

Photon is the packet. Canonical dumps/loads. photon_id is the identity
hash and does not change across hops or via translation.

pair_id uses AIH-WP-1.3: SHA256(root_A || root_B || nonce_A || nonce_B).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from qnm.pairs import compute_pair_id
from qnsd.boot import AUTHOR, PAIR_SPEC, SPEC, QNSRefuse, _utc_now, sha256_hex

MAGIC = "QNS1"
VER = "1.3"

# Wire field order (document law). Canonical dumps still sort keys.
PHOTON_FIELDS = (
    "magic",
    "ver",
    "photon_id",
    "pair_id",
    "src",
    "dst",
    "via",
    "via_in",
    "via_out",
    "translate",
    "hop",
    "hop_max",
    "seen",
    "payload",
    "utc",
    "author",
    "spec",
)

# Identity fields — via / hop / seen / translate must not enter the hash.
PHOTON_ID_FIELDS = ("magic", "ver", "src", "dst", "pair_id", "payload")

HOP_MAX_DEFAULT = 8


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def photon_id_hash(fields: dict[str, Any]) -> str:
    core = {key: fields[key] for key in PHOTON_ID_FIELDS}
    return sha256_hex(canonical_bytes(core))


@dataclass
class Photon:
    magic: str = MAGIC
    ver: str = VER
    photon_id: str = ""
    pair_id: str = ""
    src: str = ""
    dst: str = ""
    via: str = ""
    via_in: str = ""
    via_out: str = ""
    translate: bool = False
    hop: int = 0
    hop_max: int = HOP_MAX_DEFAULT
    seen: list[str] = field(default_factory=list)
    payload: dict[str, Any] = field(default_factory=dict)
    utc: str = ""
    author: str = AUTHOR
    spec: str = SPEC

    def seal_id(self) -> Photon:
        if not self.utc:
            self.utc = _utc_now()
        self.photon_id = photon_id_hash(self.to_dict())
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "magic": self.magic,
            "ver": self.ver,
            "photon_id": self.photon_id,
            "pair_id": self.pair_id,
            "src": self.src,
            "dst": self.dst,
            "via": self.via,
            "via_in": self.via_in,
            "via_out": self.via_out,
            "translate": bool(self.translate),
            "hop": int(self.hop),
            "hop_max": int(self.hop_max),
            "seen": list(self.seen),
            "payload": dict(self.payload),
            "utc": self.utc,
            "author": self.author,
            "spec": self.spec,
        }


def dumps(photon: Photon | dict[str, Any]) -> bytes:
    if isinstance(photon, Photon):
        body = photon.to_dict()
    else:
        body = {key: photon[key] for key in PHOTON_FIELDS if key in photon}
        for key in PHOTON_FIELDS:
            body.setdefault(key, [] if key == "seen" else {} if key == "payload" else "")
    missing = [key for key in PHOTON_FIELDS if key not in body]
    if missing:
        raise QNSRefuse("QNS-PHOTON", f"missing fields:{','.join(missing)}")
    ordered = {key: body[key] for key in PHOTON_FIELDS}
    return canonical_bytes(ordered)


def loads(raw: bytes | str | dict[str, Any]) -> Photon:
    if isinstance(raw, dict):
        obj = raw
    else:
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as exc:
            raise QNSRefuse("QNS-PHOTON", "not a photon") from exc
    if not isinstance(obj, dict):
        raise QNSRefuse("QNS-PHOTON", "object required")
    if obj.get("magic") != MAGIC:
        raise QNSRefuse("QNS-PHOTON", "magic must be QNS1")
    if str(obj.get("ver") or "") != VER:
        raise QNSRefuse("QNS-PHOTON", "ver must be 1.3")
    photon = Photon(
        magic=MAGIC,
        ver=VER,
        photon_id=str(obj.get("photon_id") or ""),
        pair_id=str(obj.get("pair_id") or ""),
        src=str(obj.get("src") or ""),
        dst=str(obj.get("dst") or ""),
        via=str(obj.get("via") or ""),
        via_in=str(obj.get("via_in") or ""),
        via_out=str(obj.get("via_out") or ""),
        translate=bool(obj.get("translate") or False),
        hop=int(obj.get("hop") or 0),
        hop_max=int(obj.get("hop_max") or HOP_MAX_DEFAULT),
        seen=list(obj.get("seen") or []),
        payload=dict(obj.get("payload") or {}),
        utc=str(obj.get("utc") or ""),
        author=str(obj.get("author") or AUTHOR),
        spec=str(obj.get("spec") or SPEC),
    )
    if not photon.photon_id:
        photon.seal_id()
    return photon


def photon_id(photon: Photon | dict[str, Any]) -> str:
    if isinstance(photon, Photon):
        body = photon.to_dict()
    else:
        body = dict(photon)
    return photon_id_hash(body)


def make_photon(
    *,
    src: str,
    dst: str = "",
    pair_id: str = "",
    payload: dict[str, Any] | None = None,
    via: str = "",
    hop_max: int = HOP_MAX_DEFAULT,
    seen: list[str] | None = None,
) -> Photon:
    photon = Photon(
        src=src,
        dst=dst,
        pair_id=pair_id,
        payload=dict(payload or {}),
        via=via,
        hop_max=int(hop_max),
        seen=list(seen or []),
        spec=SPEC,
        author=AUTHOR,
    )
    return photon.seal_id()


# Re-export pair hash so photon.py owns both identity hashes.
pair_id_hash = compute_pair_id

__all__ = [
    "HOP_MAX_DEFAULT",
    "MAGIC",
    "PAIR_SPEC",
    "PHOTON_FIELDS",
    "PHOTON_ID_FIELDS",
    "Photon",
    "VER",
    "canonical_bytes",
    "dumps",
    "loads",
    "make_photon",
    "pair_id_hash",
    "photon_id",
    "photon_id_hash",
]
