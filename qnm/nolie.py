"""NO-LIE-1.0 / NO-REWRITE-1.0 — mesh law (Aziel Eliab only).

The network never lies, even to self-preserve, adapt, or prevent death.
Published tips have no rewrite key. Receipts must still hash.
Verify is hash-only — without voice. Copies are not all on one tunnel.

Companion: REHEAL-1.0 (own last good or phoenix-WAIT — never a lie).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from qnm.boot import AUTHOR, SPEC, QNMRefuse, _utc_now, sha256_hex

NOLIE_SPEC = "NO-LIE-1.0"
NOREWRITE_SPEC = "NO-REWRITE-1.0"

TUNNEL_HOSTS = frozenset(
    {
        "tunnel",
        "one-tunnel",
        "one_tunnel",
        "cloudflare",
        "cf-tunnel",
        "cloudflared",
        "public-tunnel",
        "worker-tunnel",
        "cf_tunnel",
    }
)

LIE_TO_LIVE_KEYS = frozenset(
    {
        "lie",
        "lie_to_stay_alive",
        "lie_to_live",
        "lie_to_adapt",
        "lie_to_prevent_death",
        "fake_tip",
        "false_receipt",
        "false_emit",
        "mutate_to_heal",
        "rewrite_to_heal",
    }
)

REWRITE_KEYS = frozenset(
    {
        "rewrite",
        "mutate",
        "rewrite_key",
        "apply_rewrite_key",
        "new_tip",
        "replace_tip",
    }
)


def _canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def receipt_digest(receipt: dict[str, Any]) -> str:
    """SHA256 of a receipt minus its own receipt_hash field.

    ``identity_anchor`` is attached after the hash and contains that
    hash, so it stays outside the digest. Older receipts without the
    field still hash the same way.
    """
    skipped = {"receipt_hash", "identity_anchor"}
    core = {key: value for key, value in receipt.items() if key not in skipped}
    return sha256_hex(_canonical(core))


def is_tunnel_host(name: str) -> bool:
    host = str(name or "").strip().lower().replace("_", "-")
    if host in TUNNEL_HOSTS:
        return True
    return "tunnel" in host


class NoLie:
    """Named refuses: no lie, no rewrite, receipts still hash, no one tunnel."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.path = self.root / "data" / "witness" / "published.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.is_file():
            self.path.write_text("", encoding="utf-8")

    def status(self) -> dict[str, Any]:
        return {
            "ok": True,
            "spec": NOLIE_SPEC,
            "companion": NOREWRITE_SPEC,
            "build": SPEC,
            "author": AUTHOR,
            "no_lie": True,
            "no_rewrite": True,
            "rewrite_key": False,
            "verify_without_voice": True,
            "copies_one_tunnel": False,
            "published": list(self.published()),
            "lie_to_stay_alive": False,
            "lie_to_adapt": False,
            "lie_to_prevent_death": False,
        }

    def published(self) -> list[str]:
        tips: list[str] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            tip = str(row.get("tip") or "")
            if tip and tip not in tips:
                tips.append(tip)
        return tips

    def publish(self, tip: str) -> dict[str, Any]:
        digest = str(tip or "")
        if len(digest) != 64:
            raise QNMRefuse("QNM-WIRES-FAIL-CLOSED", "published tip is 64 hex")
        rec = {
            "tip": digest,
            "utc": _utc_now(),
            "spec": NOREWRITE_SPEC,
            "author": AUTHOR,
            "rewrite": False,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n")
            fh.flush()
        return rec

    def is_published(self, tip: str) -> bool:
        return str(tip or "") in self.published()

    def rewrite_published(self, tip: str = "", new_tip: str = "") -> None:
        _ = (tip, new_tip)
        raise QNMRefuse(
            "QNM-NO-REWRITE",
            "published tip cannot be rewritten or mutated",
        )

    def mutate_published(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-NO-REWRITE",
            "published tip cannot be rewritten or mutated",
        )

    def rewrite_key(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-NO-REWRITE-KEY",
            "there is no rewrite key",
        )

    def lie_to_stay_alive(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-NO-LIE-TO-LIVE",
            "network never lies to stay alive",
        )

    def lie_to_adapt(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-NO-LIE-TO-LIVE",
            "network never lies to adapt",
        )

    def lie_to_prevent_death(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-NO-LIE-TO-LIVE",
            "network never lies to prevent death",
        )

    def require_voice(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-VERIFY-WITHOUT-VOICE",
            "verify is hash-only; voice is not a yes",
        )

    def one_tunnel(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-NO-ONE-TUNNEL",
            "copies are not all on one tunnel",
        )

    def refuse_payload(self, payload: dict[str, Any]) -> None:
        """Refuse rewrite / lie-to-live keys on an inbound act."""
        keys = {str(key) for key in payload}
        if keys & LIE_TO_LIVE_KEYS or payload.get("lie") is True:
            reason = str(payload.get("reason") or "")
            if "adapt" in reason or payload.get("lie_to_adapt"):
                self.lie_to_adapt()
            if "death" in reason or payload.get("lie_to_prevent_death"):
                self.lie_to_prevent_death()
            self.lie_to_stay_alive()
        if payload.get("rewrite_key") or payload.get("apply_rewrite_key"):
            self.rewrite_key()
        if keys & (REWRITE_KEYS - {"rewrite_key", "apply_rewrite_key", "new_tip"}):
            self.rewrite_published(
                str(payload.get("tip") or ""),
                str(payload.get("new_tip") or payload.get("replace_tip") or ""),
            )
        if payload.get("require_voice") or payload.get("voice_confirm") or payload.get("voice"):
            self.require_voice()
        if payload.get("one_tunnel") or payload.get("all_on_tunnel"):
            self.one_tunnel()

    def verify_without_voice(
        self,
        receipts: list[dict[str, Any]],
        *,
        require_voice: bool = False,
        voice_confirm: bool = False,
    ) -> dict[str, Any]:
        if require_voice or voice_confirm:
            self.require_voice()
        errors: list[str] = []
        for index, receipt in enumerate(receipts):
            expected = receipt_digest(receipt)
            got = str(receipt.get("receipt_hash") or "")
            if got != expected:
                errors.append(f"receipt {index}: hash mismatch")
        if errors:
            raise QNMRefuse(
                "QNM-RECEIPT-HASH",
                "receipts must still hash; rewrite is not a heal",
            )
        return {
            "ok": True,
            "verified": True,
            "voice": False,
            "count": len(receipts),
            "spec": NOLIE_SPEC,
            "author": AUTHOR,
        }
