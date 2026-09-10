"""Airlock Poison Gate — QNS-CD-1.0 (raw-byte sweep).

Every ingress is scanned as raw bytes first. Poison is refused, not
interpreted. A poison refuse stops the walker — no next class.
"""

from __future__ import annotations

from typing import Any

from qnm.apg import APG as QnmAPG
from qnsd.boot import AUTHOR, SPEC, QNSRefuse


class APG:
    """Refuse-first raw-byte sweep. Does not interpret poison."""

    def __init__(self) -> None:
        self._inner = QnmAPG()
        self.refused: list[dict[str, Any]] = self._inner.refused

    def scan_raw(self, raw: bytes | str) -> None:
        try:
            self._inner.scan_raw(raw)
        except QNSRefuse:
            raise
        except Exception as exc:
            code = getattr(exc, "code", "QNM-APG-POISON")
            detail = getattr(exc, "detail", str(exc))
            rec = {
                "ok": False,
                "refused": True,
                "code": code,
                "detail": detail,
                "interpreted": False,
                "walk": False,
                "spec": SPEC,
                "author": AUTHOR,
            }
            self.refused.append(rec)
            raise QNSRefuse(code, detail) from exc

    def admit(self, raw: bytes | str) -> dict[str, Any]:
        try:
            return self._inner.admit(raw)
        except QNSRefuse:
            raise
        except Exception as exc:
            code = getattr(exc, "code", "QNM-APG-REFUSE")
            detail = getattr(exc, "detail", str(exc))
            rec = {
                "ok": False,
                "refused": True,
                "code": code,
                "detail": detail,
                "interpreted": False,
                "walk": False,
                "spec": SPEC,
                "author": AUTHOR,
            }
            if rec not in self.refused:
                self.refused.append(rec)
            raise QNSRefuse(code, detail) from exc
