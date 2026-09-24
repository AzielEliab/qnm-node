"""Relay spool and HTTP client.

The spool stores ciphertext envelopes only. TTL and a per-handle byte
quota apply. Poll does not delete; ack does. A dead relay takes the
copies it alone held. Senders place a second copy on another live
relay when one is reachable.

Author: Aziel Eliab only.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from qnm.boot import QNMRefuse
from qnm.fedmesh.wire import envelope_id

DEFAULT_TTL_S = 86400
DEFAULT_QUOTA_BYTES = 1_000_000


class Spool:
    def __init__(self, root: Path, *, quota_bytes: int = DEFAULT_QUOTA_BYTES, ttl_s: int = DEFAULT_TTL_S) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.quota_bytes = int(quota_bytes)
        self.ttl_s = int(ttl_s)
        self._lock = threading.Lock()

    def _path(self, handle: str) -> Path:
        safe = "".join(ch for ch in handle if ch.isalnum())
        return self.root / f"{safe}.jsonl"

    def _read(self, handle: str, *, now: float | None = None) -> list[dict[str, Any]]:
        path = self._path(handle)
        if not path.is_file():
            return []
        moment = time.time() if now is None else now
        rows = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if float(row.get("expires") or 0) <= moment:
                continue
            rows.append(row)
        return rows

    def put(self, envelope: dict[str, Any], *, now: float | None = None) -> dict[str, Any]:
        handle = str(envelope.get("to") or "")
        if not handle:
            raise QNMRefuse("FED-TAMPER", "envelope has no recipient")
        ident = envelope_id(envelope)
        moment = time.time() if now is None else now
        encoded = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
        with self._lock:
            rows = self._read(handle, now=moment)
            if any(row.get("id") == ident for row in rows):
                raise QNMRefuse("FED-REPLAY", "relay already holds this envelope")
            used = sum(int(row.get("bytes") or 0) for row in rows)
            if used + len(encoded) > self.quota_bytes:
                raise QNMRefuse("FED-QUOTA", "relay storage quota for this handle")
            row = {
                "id": ident,
                "bytes": len(encoded),
                "expires": moment + self.ttl_s,
                "envelope": envelope,
            }
            rows.append(row)
            self._write(handle, rows)
        return {"ok": True, "stored": True, "id": ident, "bytes": len(encoded)}

    def poll(self, handle: str, *, now: float | None = None) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._read(handle, now=now)
            self._write(handle, rows)
            return [row["envelope"] for row in rows]

    def ack(self, handle: str, ids: list[str]) -> dict[str, Any]:
        drop = set(ids)
        with self._lock:
            rows = [row for row in self._read(handle) if row.get("id") not in drop]
            self._write(handle, rows)
        return {"ok": True, "kept": len(rows)}

    def _write(self, handle: str, rows: list[dict[str, Any]]) -> None:
        path = self._path(handle)
        text = "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows)
        path.write_text(text, encoding="utf-8")

    def bytes_for(self, handle: str) -> int:
        return sum(int(row.get("bytes") or 0) for row in self._read(handle))


def http_json(method: str, url: str, payload: dict[str, Any] | None = None, *, timeout: float = 0.6) -> dict[str, Any]:
    data = None if payload is None else json.dumps(payload, sort_keys=True).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            parsed = json.loads(body) if body else {}
            if not isinstance(parsed, dict):
                raise QNMRefuse("FED-NO-ROUTE", "relay returned a non-object")
            return parsed
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw)
        except Exception as inner:  # noqa: BLE001
            raise QNMRefuse("FED-NO-ROUTE", f"relay HTTP {exc.code}") from inner
        if isinstance(parsed, dict) and parsed.get("code"):
            raise QNMRefuse(str(parsed.get("code")), str(parsed.get("detail") or ""))
        raise QNMRefuse("FED-NO-ROUTE", f"relay HTTP {exc.code}") from exc
    except QNMRefuse:
        raise
    except Exception as exc:  # noqa: BLE001
        raise QNMRefuse("FED-NO-ROUTE", exc.__class__.__name__) from exc
