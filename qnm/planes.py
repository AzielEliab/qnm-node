"""Survival planes A/B/C — honest fielded facts (NO-FAN).

A = public hub mirrors. Today: LIVE on the same Cloudflare tunnel.
    Not four independent copies.
B = tip-pack shelf. SLOT until a hash-verified copy is seated.
    Zenodo is IP-banned and is **not required**. Do not invent a DOI.
    Alternate shelves (Codeberg / archive.org / GitFlic) count when
    the pack bytes hash-verify.
C = USB airgap tip-pack. READY until the operator offline-verifies /
    attests. Ready is not LIVE. Attest-before-LIVE. No FAN.

Author: Aziel Eliab only.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from qnm.boot import AUTHOR, SPEC, QNMRefuse, _utc_now, sha256_hex

PLANES_SPEC = "UNKILLABILITY-PLANES-1.1"
ZENODO_DOI_RE = re.compile(r"^10\.5281/zenodo\.\d{4,}$")
PACK_TIP_PREFIX = "ac07dfb99ead"
ZENODO_REQUIRED = False
ZENODO_IP_BANNED = True
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_SHELF_HOSTS = (
    "codeberg.org",
    "archive.org",
    "web.archive.org",
    "gitflic.ru",
)

FAKE_DOI = frozenset(
    {
        "",
        "null",
        "none",
        "slot",
        "pending",
        "todo",
        "example",
        "10.5281/zenodo.0",
        "doi:null",
    }
)


def valid_zenodo_doi(doi: str | None) -> bool:
    """Format check only. Does **not** mean Plane B is fielded-verified."""
    token = str(doi or "").strip().lower()
    if not token or token in FAKE_DOI:
        return False
    return bool(ZENODO_DOI_RE.match(token))


def valid_pack_digest(digest: str | None) -> bool:
    token = str(digest or "").strip().lower()
    return bool(DIGEST_RE.match(token))


def valid_shelf_url(url: str | None) -> bool:
    parsed = urlparse(str(url or "").strip())
    if parsed.scheme != "https":
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    for allowed in ALLOWED_SHELF_HOSTS:
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


def plane_b_is_verified(
    plane_b: dict[str, Any] | None = None,
    *,
    planes: dict[str, Any] | None = None,
) -> bool:
    """Hash-verified shelf (or hash-verified pack). Format-only DOI is not enough."""
    if planes and isinstance(planes.get("gates"), dict):
        gates = planes["gates"]
        if "plane_b_verified" in gates:
            return bool(gates["plane_b_verified"])
    rec = plane_b or (planes or {}).get("plane_b") or {}
    return bool(rec.get("hash_verified") and rec.get("pack_digest"))


class Planes:
    """Local plane lock. Never invents DOI or offline-verify success."""

    def __init__(self, root: Path, cfg: dict[str, Any] | None = None) -> None:
        self.root = Path(root)
        self.cfg = dict(cfg or {})
        self.dir = self.root / "data" / "planes"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "data" / "locks" / "planes.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.verify_path = self.dir / "offline-verify.jsonl"
        self.shelf_path = self.dir / "shelf-verify.jsonl"
        if not self.verify_path.is_file():
            self.verify_path.write_text("", encoding="utf-8")
        if not self.shelf_path.is_file():
            self.shelf_path.write_text("", encoding="utf-8")
        self._state = self._default()
        self._load()

    def _default(self) -> dict[str, Any]:
        cite = dict(self.cfg.get("planes") or {})
        files = cite.get("plane_c_files")
        return {
            "plane_a": {
                "id": "A",
                "name": "hubs",
                "status": "LIVE",
                "hubs": 4,
                "independence": "same-cf-tunnel",
                "independent": False,
                "kind": "LIVE",
            },
            "plane_b": {
                "id": "B",
                "name": "tip-pack-shelf",
                "status": "SLOT",
                "doi": None,
                "zenodo_required": ZENODO_REQUIRED,
                "zenodo_ip_banned": ZENODO_IP_BANNED,
                "shelf": None,
                "shelf_host": None,
                "pack_digest": None,
                "hash_verified": False,
                "kind": "SLOT",
                "live": False,
            },
            "plane_c": {
                "id": "C",
                "name": "usb-airgap-tip-pack",
                "status": "READY",
                "files": int(files) if files else 30,
                "pack_tip": None,
                "pack_tip_prefix": PACK_TIP_PREFIX,
                "offline_verify": False,
                "attest_required": True,
                "operator_offline_verify_required": True,
                "before_live": "operator offline-verify/attest required",
                "kind": "READY",
                "live": False,
                "fan": False,
                "no_fan": True,
            },
        }

    def _load(self) -> None:
        if not self.path.is_file():
            return
        stored = json.loads(self.path.read_text(encoding="utf-8"))
        for key in ("plane_a", "plane_b", "plane_c"):
            if isinstance(stored.get(key), dict):
                self._state[key].update(stored[key])
        b_rec = self._state["plane_b"]
        if not plane_b_is_verified(b_rec):
            b_rec["hash_verified"] = False
            if not valid_zenodo_doi(b_rec.get("doi")):
                b_rec["doi"] = None
            if b_rec.get("status") in ("DOI", "SHELF") and not b_rec.get("hash_verified"):
                b_rec["status"] = "DOI-UNVERIFIED" if b_rec.get("doi") else "SLOT"
            if not b_rec.get("hash_verified"):
                b_rec["kind"] = "SLOT"
                b_rec["live"] = False
        b_rec["zenodo_required"] = False
        b_rec["zenodo_ip_banned"] = True

    def _persist(self) -> None:
        self.path.write_text(
            json.dumps(
                {
                    **self._state,
                    "spec": PLANES_SPEC,
                    "author": AUTHOR,
                },
                sort_keys=True,
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    def snapshot(self) -> dict[str, Any]:
        b_ok = plane_b_is_verified(self._state["plane_b"])
        c_ok = bool(self._state["plane_c"].get("offline_verify"))
        plane_c = dict(self._state["plane_c"])
        plane_c["attest_required"] = True
        plane_c["operator_offline_verify_required"] = True
        plane_c["before_live"] = "operator offline-verify/attest required"
        plane_c["fan"] = False
        plane_c["no_fan"] = True
        plane_c["live"] = False
        return {
            "ok": True,
            "spec": PLANES_SPEC,
            "build": SPEC,
            "author": AUTHOR,
            "plane_a": dict(self._state["plane_a"]),
            "plane_b": dict(self._state["plane_b"]),
            "plane_c": plane_c,
            "zenodo_required": False,
            "zenodo_ip_banned": True,
            "allowed_shelves": list(ALLOWED_SHELF_HOSTS),
            "plane_c_attest_before_live": True,
            "gates": {
                "plane_b_doi": False,
                "plane_b_shelf": b_ok,
                "plane_b_verified": b_ok,
                "plane_c_offline_verify": c_ok,
                "plane_c_attest": c_ok,
                "fielded_ready": bool(b_ok and c_ok),
                "zenodo_required": False,
            },
            "no_fan": True,
            "plane_c_before_live": "operator offline-verify/attest required",
        }

    def seat_zenodo_doi(
        self,
        doi: str | None,
        *,
        body: bytes | str | None = None,
        digest: str | None = None,
    ) -> dict[str, Any]:
        """Optional DOI cite. Format-only is not fielded. Zenodo is not required."""
        if doi is None or str(doi).strip().lower() in FAKE_DOI:
            raise QNMRefuse(
                "QNM-NO-FAN-DOI",
                "Plane B DOI is null; do not invent a Zenodo DOI",
            )
        token = str(doi).strip()
        if not valid_zenodo_doi(token):
            raise QNMRefuse(
                "QNM-NO-FAN-DOI",
                "optional DOI cite must be 10.5281/zenodo.N; Zenodo is not required",
            )
        self._state["plane_b"]["doi"] = token.lower()
        self._state["plane_b"]["zenodo_required"] = False
        self._state["plane_b"]["zenodo_ip_banned"] = True
        self._state["plane_b"]["live"] = False
        if body not in (None, "", b""):
            self._verify_pack_bytes(body, digest)
            self._state["plane_b"]["status"] = "DOI-HASH"
            self._state["plane_b"]["kind"] = "REAL"
        else:
            self._state["plane_b"]["status"] = "DOI-UNVERIFIED"
            self._state["plane_b"]["kind"] = "SLOT"
            self._state["plane_b"]["hash_verified"] = False
        self._persist()
        return dict(self._state["plane_b"])

    def seat_shelf(
        self,
        url: str,
        digest: str,
        body: bytes | str,
    ) -> dict[str, Any]:
        """Hash-verify a Codeberg / archive.org / GitFlic tip-pack. Not a DOI."""
        if not valid_shelf_url(url):
            raise QNMRefuse(
                "QNM-NO-FAN-SHELF",
                "Plane B shelf must be https Codeberg, archive.org, or GitFlic",
            )
        rec = self._verify_pack_bytes(body, digest)
        parsed = urlparse(str(url).strip())
        self._state["plane_b"]["shelf"] = str(url).strip()
        self._state["plane_b"]["shelf_host"] = (parsed.hostname or "").lower()
        self._state["plane_b"]["status"] = "SHELF"
        self._state["plane_b"]["kind"] = "REAL"
        self._state["plane_b"]["live"] = False
        self._state["plane_b"]["zenodo_required"] = False
        self._persist()
        rec["shelf"] = self._state["plane_b"]["shelf"]
        rec["shelf_host"] = self._state["plane_b"]["shelf_host"]
        return dict(self._state["plane_b"]) | {"verify": rec}

    def _verify_pack_bytes(self, body: bytes | str, digest: str | None) -> dict[str, Any]:
        raw = body.encode("utf-8") if isinstance(body, str) else bytes(body)
        if not raw:
            raise QNMRefuse(
                "QNM-NO-FAN-SHELF",
                "Plane B shelf needs pack bytes; a URL alone is not verified",
            )
        got = sha256_hex(raw)
        expect = str(digest or "").strip().lower()
        if expect and not valid_pack_digest(expect):
            raise QNMRefuse("QNM-NO-FAN-SHELF", "Plane B digest must be 64 hex")
        if expect and expect != got:
            raise QNMRefuse(
                "QNM-NO-FAN-SHELF",
                "Plane B shelf digest does not match pack bytes",
            )
        rec = {
            "kind": "plane-b-shelf-verify",
            "pack_digest": got,
            "bytes": len(raw),
            "hash_verified": True,
            "utc": _utc_now(),
            "spec": PLANES_SPEC,
            "author": AUTHOR,
        }
        with self.shelf_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n")
            fh.flush()
        self._state["plane_b"]["pack_digest"] = got
        self._state["plane_b"]["hash_verified"] = True
        return rec

    def clear_zenodo_doi(self) -> dict[str, Any]:
        self._state["plane_b"]["doi"] = None
        self._state["plane_b"]["shelf"] = None
        self._state["plane_b"]["shelf_host"] = None
        self._state["plane_b"]["pack_digest"] = None
        self._state["plane_b"]["hash_verified"] = False
        self._state["plane_b"]["status"] = "SLOT"
        self._state["plane_b"]["kind"] = "SLOT"
        self._state["plane_b"]["live"] = False
        self._persist()
        return dict(self._state["plane_b"])

    def verify_airgap(
        self,
        body: bytes | str,
        *,
        pack_tip: str | None = None,
    ) -> dict[str, Any]:
        """Operator offline-verify / attest of USB airgap bytes.

        Missing body is not success. READY is not LIVE. No FAN.
        """
        raw = body.encode("utf-8") if isinstance(body, str) else bytes(body)
        if not raw:
            raise QNMRefuse(
                "QNM-NO-FAN-AIRGAP",
                "Plane C needs operator offline-verify/attest; READY is not LIVE",
            )
        digest = sha256_hex(raw)
        expect = str(pack_tip or "").strip().lower()
        if expect and expect != digest:
            raise QNMRefuse(
                "QNM-NO-FAN-AIRGAP",
                "Plane C pack tip does not match offline bytes",
            )
        rec = {
            "kind": "plane-c-offline-verify",
            "pack_tip": digest,
            "bytes": len(raw),
            "offline_verify": True,
            "utc": _utc_now(),
            "spec": PLANES_SPEC,
            "author": AUTHOR,
        }
        with self.verify_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n")
            fh.flush()
        self._state["plane_c"]["pack_tip"] = digest
        self._state["plane_c"]["offline_verify"] = True
        self._state["plane_c"]["status"] = "VERIFIED"
        self._state["plane_c"]["kind"] = "REAL"
        self._state["plane_c"]["live"] = False
        self._state["plane_c"]["fan"] = False
        self._state["plane_c"]["no_fan"] = True
        self._state["plane_c"]["attest_required"] = True
        self._persist()
        return rec

    def refuse_invent_doi(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-NO-FAN-DOI",
            "Plane B DOI is null; do not invent a Zenodo DOI",
        )

    def refuse_invent_shelf(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-NO-FAN-SHELF",
            "Plane B shelf URL must be hash-verified https Codeberg / archive.org / GitFlic; do not invent a DOI/URL",
        )

    def refuse_invent_airgap(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-NO-FAN-AIRGAP",
            "Plane C READY is not an offline-verify success; no FAN",
        )

    def refuse_plane_c_live(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-NO-FAN-AIRGAP",
            "Plane C USB airgap is not LIVE without operator offline-verify/attest; no FAN",
        )
