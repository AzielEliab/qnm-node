"""Survival planes A/B/C — honest fielded facts (NO-FAN).

A = public hub mirrors. Today: LIVE on the same Cloudflare tunnel.
    Not four independent copies.
B = Zenodo tip-pack. SLOT until a real DOI is seated. doi is null
    until then. Do not invent a DOI.
C = USB airgap tip-pack. READY until an operator offline-verify /
    attest receipt is written. Ready is not verified. Operator
    offline-verify/attest is required before LIVE. No FAN.

Author: Aziel Eliab only.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from qnm.boot import AUTHOR, SPEC, QNMRefuse, _utc_now, sha256_hex

PLANES_SPEC = "UNKILLABILITY-PLANES-1.0"
ZENODO_DOI_RE = re.compile(r"^10\.5281/zenodo\.\d{4,}$")
PACK_TIP_PREFIX = "ac07dfb99ead"

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
    token = str(doi or "").strip().lower()
    if not token or token in FAKE_DOI:
        return False
    return bool(ZENODO_DOI_RE.match(token))


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
        if not self.verify_path.is_file():
            self.verify_path.write_text("", encoding="utf-8")
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
                "name": "zenodo-tip-pack",
                "status": "SLOT",
                "doi": None,
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
        if not valid_zenodo_doi(self._state["plane_b"].get("doi")):
            self._state["plane_b"]["doi"] = None
            self._state["plane_b"]["status"] = "SLOT"
            self._state["plane_b"]["kind"] = "SLOT"
            self._state["plane_b"]["live"] = False

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
        b_doi = self._state["plane_b"].get("doi")
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
            "gates": {
                "plane_b_doi": bool(valid_zenodo_doi(b_doi)),
                "plane_c_offline_verify": c_ok,
                "plane_c_attest": c_ok,
                "fielded_ready": bool(valid_zenodo_doi(b_doi) and c_ok),
            },
            "no_fan": True,
            "plane_c_before_live": "operator offline-verify/attest required",
        }

    def seat_zenodo_doi(self, doi: str | None) -> dict[str, Any]:
        """Operator seats a real Zenodo DOI. Null / slot / fake refuse."""
        if doi is None or str(doi).strip().lower() in FAKE_DOI:
            raise QNMRefuse(
                "QNM-NO-FAN-DOI",
                "Plane B DOI is null; do not invent a Zenodo DOI",
            )
        token = str(doi).strip()
        if not valid_zenodo_doi(token):
            raise QNMRefuse(
                "QNM-NO-FAN-DOI",
                "Plane B needs a real 10.5281/zenodo.N DOI",
            )
        self._state["plane_b"]["doi"] = token.lower()
        self._state["plane_b"]["status"] = "DOI"
        self._state["plane_b"]["kind"] = "REAL"
        self._state["plane_b"]["live"] = True
        self._persist()
        return dict(self._state["plane_b"])

    def clear_zenodo_doi(self) -> dict[str, Any]:
        self._state["plane_b"]["doi"] = None
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
