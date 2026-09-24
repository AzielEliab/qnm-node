"""Inbound quarantine, scanner reports, and sneakernet bundles.

Every inbound object lands here before it can be promoted into the
object store. Files are mode 0600 and are not executed.

ClamAV and YARA run only when those programs are on PATH. A missing
scanner is reported as absent. Promotion then needs an explicit
operator override. Scanners catch known malware only. The task
sandbox is the main defense. This is not a claim that the bytes are
safe.

Airgap export writes a GNU ``sha256sum -c`` manifest plus a signed
statement. Import checks the signature and every hash, then lands the
bytes back in quarantine. That is the same idea as Plane C offline
verify: the hash is checked on this machine, and a verified bundle is
not a live public plane.

Author: Aziel Eliab only.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

from qnm.boot import QNMRefuse
from qnm.fedmesh.wire import sha256_hex

MAX_SCAN_BYTES = 1_000_000


def _chmod_file(path: Path) -> None:
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def probe_scanner(names: tuple[str, ...]) -> dict[str, Any]:
    for name in names:
        path = shutil.which(name)
        if not path:
            continue
        version = _version(path)
        return {"name": name, "present": True, "path": path, "version": version, "verdict": "unscanned"}
    return {"name": names[0], "present": False, "path": None, "version": None, "verdict": "absent"}


def _version(path: str) -> str:
    try:
        proc = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=3, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    line = (proc.stdout or proc.stderr or "").strip().splitlines()
    return line[0][:120] if line else ""


def scanner_status(*, yara_rules: str | None = None) -> dict[str, Any]:
    clam = probe_scanner(("clamdscan", "clamscan"))
    yara = probe_scanner(("yara",))
    if yara["present"] and not yara_rules:
        yara = dict(yara)
        yara["verdict"] = "rules-absent"
        yara["rules"] = None
    elif yara["present"]:
        yara = dict(yara)
        yara["rules"] = yara_rules
    return {"clamav": clam, "yara": yara}


class Airlock:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, stat.S_IRWXU)
        self.yara_rules: str | None = None

    def land(self, data: bytes, *, claimed: str | None = None) -> dict[str, Any]:
        if len(data) > MAX_SCAN_BYTES:
            raise QNMRefuse("FED-QUOTA", "airlock object is too large")
        digest = sha256_hex(data)
        if claimed is not None and claimed != digest:
            raise QNMRefuse("FG-GATE-REFUSE", "object bytes do not match the hash")
        path = self.root / digest
        path.write_bytes(data)
        _chmod_file(path)
        return {
            "sha256": digest,
            "bytes": len(data),
            "promoted": False,
            "executable": False,
            "mode": oct(stat.S_IMODE(path.stat().st_mode)),
        }

    def has(self, digest: str) -> bool:
        return (self.root / digest).is_file()

    def read(self, digest: str) -> bytes:
        path = self.root / digest
        if not path.is_file():
            raise QNMRefuse("FED-FETCH", "object is not in airlock")
        data = path.read_bytes()
        if sha256_hex(data) != digest:
            raise QNMRefuse("FG-GATE-REFUSE", "airlock bytes do not match the hash")
        return data

    def scan(self, digest: str) -> dict[str, Any]:
        data = self.read(digest)
        path = self.root / digest
        clam = probe_scanner(("clamdscan", "clamscan"))
        yara = probe_scanner(("yara",))
        scanners = [self._run_clam(clam, path), self._run_yara(yara, path)]
        infected = any(row.get("verdict") == "infected" for row in scanners)
        absent = any(row.get("verdict") in ("absent", "rules-absent", "error") for row in scanners)
        return {
            "sha256": sha256_hex(data),
            "scanners": scanners,
            "infected": infected,
            "scanner_absent": absent,
            "executed": False,
        }

    def _run_clam(self, probe: dict[str, Any], path: Path) -> dict[str, Any]:
        if not probe["present"]:
            return {"name": "clamav", "present": False, "version": None, "verdict": "absent"}
        try:
            proc = subprocess.run(
                [str(probe["path"]), "--no-summary", str(path)],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"name": "clamav", "present": True, "version": probe.get("version"), "verdict": "error", "detail": exc.__class__.__name__}
        verdict = "clean" if proc.returncode == 0 else "infected" if proc.returncode == 1 else "error"
        return {"name": str(probe["name"]), "present": True, "version": probe.get("version"), "verdict": verdict}

    def _run_yara(self, probe: dict[str, Any], path: Path) -> dict[str, Any]:
        if not probe["present"]:
            return {"name": "yara", "present": False, "version": None, "verdict": "absent"}
        if not self.yara_rules:
            return {"name": "yara", "present": True, "version": probe.get("version"), "verdict": "rules-absent"}
        try:
            proc = subprocess.run(
                [str(probe["path"]), self.yara_rules, str(path)],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"name": "yara", "present": True, "version": probe.get("version"), "verdict": "error", "detail": exc.__class__.__name__}
        verdict = "infected" if proc.returncode == 0 and (proc.stdout or "").strip() else "clean" if proc.returncode == 0 else "error"
        return {"name": "yara", "present": True, "version": probe.get("version"), "verdict": verdict}


def sha256sums_text(files: list[tuple[str, bytes]]) -> str:
    lines = []
    for name, data in files:
        if "/" in name or name.startswith(".") or not name:
            raise QNMRefuse("FED-POLICY", "airgap name refused")
        lines.append(f"{sha256_hex(data)}  {name}")
    return "\n".join(lines) + ("\n" if lines else "")


def check_sha256sums(manifest: str, root: Path) -> list[dict[str, str]]:
    """Same check as ``sha256sum -c``: 64 hex, two spaces, then the name."""
    checked: list[dict[str, str]] = []
    if not manifest.strip():
        raise QNMRefuse("FG-GATE-REFUSE", "airgap manifest is empty")
    for line in manifest.splitlines():
        if not line.strip():
            continue
        if len(line) < 66 or line[64:66] != "  ":
            raise QNMRefuse("FG-GATE-REFUSE", "airgap manifest line is not sha256sum form")
        digest, name = line[:64], line[66:]
        if "/" in name or name.startswith(".") or any(ch not in "0123456789abcdef" for ch in digest):
            raise QNMRefuse("FG-GATE-REFUSE", "airgap manifest name refused")
        path = root / name
        if not path.is_file():
            raise QNMRefuse("FG-GATE-REFUSE", "airgap file missing")
        data = path.read_bytes()
        if sha256_hex(data) != digest:
            raise QNMRefuse("FG-GATE-REFUSE", "airgap file hash mismatch")
        checked.append({"name": name, "sha256": digest})
    if not checked:
        raise QNMRefuse("FG-GATE-REFUSE", "airgap manifest is empty")
    return checked
