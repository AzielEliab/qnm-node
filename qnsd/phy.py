"""Real OS radio bindings — LIVE | ABSENT | REFUSED.

Calls proven host tools and sysfs. Never invents tower chatter,
pairing success, a GNSS fix, or an NFC tap.

  cellular  ModemManager (`mmcli`) — LTE/5G. LIVE when modem+SIM.
  wifi      NetworkManager / `iw` / sysfs wireless — 2.4/5/6 GHz.
  bt        BlueZ (`bluetoothctl`) / sysfs bluetooth.
  gps       gpsd / NMEA — receive-only.
  nfc       libnfc (`nfc-list`) / PCSC.

HOOK-PENDING is not used here: these bindings compile as stdlib
subprocess. Missing tools or adapters are ABSENT. Emit without
hardware is REFUSED.

Author: Aziel Eliab only.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any, Callable

from qnm.boot import AUTHOR, SPEC

PHY_SPEC = "RADIO-PHY-1.0"
LABEL_LIVE = "LIVE"
LABEL_ABSENT = "ABSENT"
LABEL_REFUSED = "REFUSED"

PHY_NAMES = ("cellular", "wifi", "bt", "gps", "nfc")
VIA_TO_PHY = {
    "rf": "cellular",
    "cellular": "cellular",
    "wifi": "wifi",
    "bt": "bt",
    "gps": "gps",
    "gnss": "gps",
    "nfc": "nfc",
}

PACKAGES = {
    "cellular": {
        "packages": ["modemmanager"],
        "tools": ["mmcli"],
        "permissions": [
            "membership in group dialout or plugdev as required by the modem",
            "D-Bus: org.freedesktop.ModemManager1",
        ],
    },
    "wifi": {
        "packages": ["iw", "network-manager"],
        "tools": ["iw", "nmcli"],
        "permissions": [
            "netdev group or CAP_NET_ADMIN for iw",
            "D-Bus: org.freedesktop.NetworkManager",
        ],
    },
    "bt": {
        "packages": ["bluez"],
        "tools": ["bluetoothctl"],
        "permissions": [
            "lp or bluetooth group",
            "D-Bus: org.bluez",
        ],
    },
    "gps": {
        "packages": ["gpsd", "gpsd-clients"],
        "tools": ["gpspipe", "gpsd"],
        "permissions": [
            "dialout for GNSS USB/UART",
            "gpsd socket /var/run/gpsd.sock or 127.0.0.1:2947",
        ],
    },
    "nfc": {
        "packages": ["libnfc-bin", "pcscd", "pcsc-tools"],
        "tools": ["nfc-list", "pcsc_scan"],
        "permissions": [
            "plugdev for USB NFC readers",
            "pcscd service for PC/SC",
        ],
    },
}

REFUSE_CODES = {
    "cellular": "RADIO-NO-MODEM",
    "wifi": "RADIO-NO-WIFI",
    "bt": "RADIO-NO-BT",
    "gps": "RADIO-NO-GNSS",
    "nfc": "RADIO-NO-NFC",
}

Runner = Callable[[list[str], float], dict[str, Any]]


def run_cmd(argv: list[str], timeout: float = 2.0, runner: Runner | None = None) -> dict[str, Any]:
    """Run one host command. Missing binaries are ABSENT, not invented output."""
    if runner is not None:
        return runner(list(argv), timeout)
    binary = argv[0] if argv else ""
    path = shutil.which(binary)
    if not path:
        return {
            "ok": False,
            "code": 127,
            "stdout": "",
            "stderr": f"{binary}: not found",
            "missing": True,
            "argv": list(argv),
        }
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "ok": False,
            "code": 124,
            "stdout": "",
            "stderr": str(exc),
            "missing": False,
            "argv": list(argv),
        }
    return {
        "ok": proc.returncode == 0,
        "code": int(proc.returncode),
        "stdout": proc.stdout or "",
        "stderr": proc.stderr or "",
        "missing": False,
        "argv": list(argv),
    }


def _card(
    name: str,
    label: str,
    *,
    tool: str = "",
    adapter: str = "",
    sim: bool = False,
    detail: str = "",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body = {
        "ok": True,
        "name": name,
        "binding": "os",
        "label": label,
        "live": label == LABEL_LIVE,
        "absent": label == LABEL_ABSENT,
        "refused": label == LABEL_REFUSED,
        "tool": tool,
        "adapter": adapter,
        "sim": sim,
        "transmitted": False,
        "mock": False,
        "invented": False,
        "detail": detail,
        "packages": PACKAGES.get(name, {}),
        "spec": PHY_SPEC,
        "build": SPEC,
        "author": AUTHOR,
        "refuse_code": REFUSE_CODES.get(name, "RADIO-ABSENT"),
    }
    if extra:
        body.update(extra)
    return body


def _sys_children(path: str) -> list[str]:
    root = Path(path)
    if not root.is_dir():
        return []
    return [child.name for child in root.iterdir() if child.name not in (".", "..")]


def _wireless_ifaces() -> list[str]:
    found: list[str] = []
    net = Path("/sys/class/net")
    if not net.is_dir():
        return found
    for iface in net.iterdir():
        if (iface / "wireless").is_dir() or (iface / "phy80211").exists():
            found.append(iface.name)
    return found


def _bt_adapters() -> list[str]:
    root = Path("/sys/class/bluetooth")
    if not root.is_dir():
        return []
    return [child.name for child in root.iterdir() if child.name.startswith("hci")]


def probe_cellular(runner: Runner | None = None) -> dict[str, Any]:
    listed = run_cmd(["mmcli", "-L"], runner=runner)
    if listed.get("missing"):
        return _card(
            "cellular",
            LABEL_ABSENT,
            tool="mmcli",
            detail="ModemManager mmcli not installed",
        )
    text = str(listed.get("stdout") or "") + str(listed.get("stderr") or "")
    if "No modems were found" in text or not text.strip():
        return _card(
            "cellular",
            LABEL_ABSENT,
            tool="mmcli",
            detail="no modem on this host; never fake tower chatter",
        )
    modem = ""
    for token in text.replace(",", " ").split():
        if "/Modem/" in token:
            modem = token.rsplit("/", 1)[-1]
            break
        if token.isdigit() and not modem:
            modem = token
    if not modem:
        return _card(
            "cellular",
            LABEL_ABSENT,
            tool="mmcli",
            detail="mmcli -L listed no modem path",
        )
    info = run_cmd(["mmcli", "-m", modem], runner=runner)
    body = str(info.get("stdout") or "")
    has_sim = "SIM" in body and "/SIM/" in body.replace(" ", "")
    if not has_sim:
        lowered = body.lower()
        has_sim = "sim" in lowered and "unknown" not in lowered.split("sim", 1)[-1][:40]
        if "sim slot" in lowered or "primary sim" in lowered:
            has_sim = True
        if "sim path" in lowered or "sim:" in lowered:
            has_sim = True
    if not has_sim:
        return _card(
            "cellular",
            LABEL_ABSENT,
            tool="mmcli",
            adapter=f"modem/{modem}",
            sim=False,
            detail="modem present without SIM; RADIO-NO-MODEM until SIM seats",
            extra={"code": "RADIO-NO-MODEM"},
        )
    return _card(
        "cellular",
        LABEL_LIVE,
        tool="mmcli",
        adapter=f"modem/{modem}",
        sim=True,
        detail="modem+SIM present; TX only on explicit operator chatter",
    )


def probe_wifi(runner: Runner | None = None) -> dict[str, Any]:
    ifaces = _wireless_ifaces()
    iw = run_cmd(["iw", "dev"], runner=runner)
    if not iw.get("missing"):
        for line in str(iw.get("stdout") or "").splitlines():
            line = line.strip()
            if line.lower().startswith("interface "):
                name = line.split()[-1]
                if name and name not in ifaces:
                    ifaces.append(name)
    nm = run_cmd(
        ["nmcli", "-t", "-f", "TYPE,DEVICE,STATE", "device"],
        runner=runner,
    )
    if not nm.get("missing"):
        for line in str(nm.get("stdout") or "").splitlines():
            parts = line.strip().split(":")
            if len(parts) >= 2 and parts[0] == "wifi" and parts[1]:
                if parts[1] not in ifaces:
                    ifaces.append(parts[1])
    tool = "iw" if not iw.get("missing") else ("nmcli" if not nm.get("missing") else "sysfs")
    if not ifaces:
        return _card(
            "wifi",
            LABEL_ABSENT,
            tool=tool,
            detail="no 802.11 adapter (2.4/5/6 GHz) on this host",
        )
    return _card(
        "wifi",
        LABEL_LIVE,
        tool=tool,
        adapter=ifaces[0],
        detail=f"wireless iface {ifaces[0]}; no invented association",
        extra={"ifaces": ifaces},
    )


def probe_bluetooth(runner: Runner | None = None) -> dict[str, Any]:
    adapters = _bt_adapters()
    listed = run_cmd(["bluetoothctl", "list"], runner=runner)
    if not listed.get("missing"):
        for line in str(listed.get("stdout") or "").splitlines():
            if line.strip().lower().startswith("controller "):
                bits = line.split()
                if len(bits) >= 2 and bits[1] not in adapters:
                    adapters.append(bits[1])
    if not adapters:
        hci = run_cmd(["hciconfig"], runner=runner)
        if not hci.get("missing") and "hci" in str(hci.get("stdout") or "").lower():
            adapters.append("hci0")
    if not adapters:
        return _card(
            "bt",
            LABEL_ABSENT,
            tool="bluetoothctl",
            detail="no BlueZ adapter on this host",
        )
    return _card(
        "bt",
        LABEL_LIVE,
        tool="bluetoothctl",
        adapter=str(adapters[0]),
        detail=f"BlueZ adapter {adapters[0]}; no invented pairing",
        extra={"adapters": adapters},
    )


def _parse_tpv(text: str) -> dict[str, Any] | None:
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("class") == "TPV" and obj.get("mode", 0) >= 2:
            if "lat" in obj and "lon" in obj:
                return {
                    "lat": float(obj["lat"]),
                    "lon": float(obj["lon"]),
                    "mode": int(obj.get("mode") or 0),
                    "time": str(obj.get("time") or ""),
                }
    return None


def _gpsd_watch(timeout: float = 1.5) -> str:
    try:
        sock = socket.create_connection(("127.0.0.1", 2947), timeout=timeout)
    except OSError:
        return ""
    try:
        sock.sendall(b'?WATCH={"enable":true,"json":true}\n')
        sock.settimeout(timeout)
        chunks: list[str] = []
        while len("".join(chunks)) < 8192:
            try:
                piece = sock.recv(2048)
            except OSError:
                break
            if not piece:
                break
            chunks.append(piece.decode("utf-8", errors="replace"))
            if '"class":"TPV"' in "".join(chunks):
                break
        return "".join(chunks)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def probe_gnss(runner: Runner | None = None) -> dict[str, Any]:
    pipe = run_cmd(["gpspipe", "-w", "-n", "4"], timeout=2.5, runner=runner)
    text = str(pipe.get("stdout") or "")
    fix = _parse_tpv(text) if text else None
    if fix is None and not pipe.get("missing"):
        fix = _parse_tpv(text)
    if fix is None and runner is None:
        fix = _parse_tpv(_gpsd_watch())
    sock_path = Path("/var/run/gpsd.sock")
    if fix is None and (pipe.get("missing") and not sock_path.exists()) and runner is not None:
        return _card(
            "gps",
            LABEL_ABSENT,
            tool="gpspipe",
            detail="gpsd/NMEA receiver not present",
        )
    if fix is None and pipe.get("missing") and not sock_path.exists() and runner is None:
        return _card(
            "gps",
            LABEL_ABSENT,
            tool="gpsd",
            detail="gpsd/NMEA receiver not present",
        )
    if fix is None:
        if sock_path.exists() or (not pipe.get("missing") and "TPV" in text):
            return _card(
                "gps",
                LABEL_ABSENT,
                tool="gpspipe",
                detail="gpsd talking but no 2D/3D fix yet; receive-only, no invented position",
            )
        return _card(
            "gps",
            LABEL_ABSENT,
            tool="gpspipe",
            detail="gpsd/NMEA receiver not present",
        )
    return _card(
        "gps",
        LABEL_LIVE,
        tool="gpspipe",
        adapter="gpsd",
        detail="GNSS receiver LIVE; timing/position receipt only — not a GIS truth engine",
        extra={"fix": fix, "receive_only": True},
    )


def probe_nfc(runner: Runner | None = None) -> dict[str, Any]:
    listed = run_cmd(["nfc-list"], runner=runner)
    text = str(listed.get("stdout") or "") + str(listed.get("stderr") or "")
    if not listed.get("missing"):
        if "NFC device" in text and "No NFC device found" not in text:
            reader = ""
            for line in text.splitlines():
                stripped = line.strip()
                if stripped and not stripped.lower().startswith("nfc-list"):
                    if "found" not in stripped.lower():
                        reader = stripped
                        break
            return _card(
                "nfc",
                LABEL_LIVE,
                tool="nfc-list",
                adapter=reader or "libnfc",
                detail="NFC reader present; short-range handoff only",
            )
        if "No NFC device found" in text:
            return _card(
                "nfc",
                LABEL_ABSENT,
                tool="nfc-list",
                detail="libnfc installed; no reader",
            )
    pcsc = run_cmd(["pcsc_scan", "-n"], timeout=1.5, runner=runner)
    pcsc_text = str(pcsc.get("stdout") or "") + str(pcsc.get("stderr") or "")
    if not pcsc.get("missing") and (
        "Reader" in pcsc_text or "reader" in pcsc_text
    ) and "Waiting for the first reader" not in pcsc_text:
        return _card(
            "nfc",
            LABEL_LIVE,
            tool="pcsc_scan",
            adapter="pcsc",
            detail="PC/SC reader present; short-range handoff only",
        )
    return _card(
        "nfc",
        LABEL_ABSENT,
        tool="nfc-list" if not listed.get("missing") else "pcsc_scan",
        detail="no libnfc/PCSC reader on this host",
    )


PROBERS = {
    "cellular": probe_cellular,
    "wifi": probe_wifi,
    "bt": probe_bluetooth,
    "gps": probe_gnss,
    "nfc": probe_nfc,
}


def probe(name: str, runner: Runner | None = None) -> dict[str, Any]:
    phy = VIA_TO_PHY.get(name, name)
    fn = PROBERS.get(phy)
    if fn is None:
        return _card(phy, LABEL_ABSENT, detail=f"unknown phy:{phy}")
    return fn(runner=runner)


def probe_all(runner: Runner | None = None) -> dict[str, Any]:
    radios = {name: probe(name, runner=runner) for name in PHY_NAMES}
    labels = {name: radios[name]["label"] for name in PHY_NAMES}
    return {
        "ok": True,
        "spec": PHY_SPEC,
        "build": SPEC,
        "author": AUTHOR,
        "radios": radios,
        "labels": labels,
        "live": [name for name, row in radios.items() if row["live"]],
        "absent": [name for name, row in radios.items() if row["absent"]],
        "invented": False,
        "mock": False,
        "mesh_enable": False,
        "az_generator": False,
        "packages": PACKAGES,
    }


def refuse_emit(name: str, photon: dict[str, Any] | None = None) -> dict[str, Any]:
    phy = VIA_TO_PHY.get(name, name)
    code = REFUSE_CODES.get(phy, "RADIO-ABSENT")
    if phy == "gps":
        code = "RADIO-NO-GNSS"
    return {
        "ok": False,
        "label": LABEL_REFUSED,
        "code": code,
        "via": name,
        "phy": phy,
        "transmitted": False,
        "invented": False,
        "photon": photon,
        "detail": f"{phy} adapter absent; refuse, do not invent chatter",
        "spec": PHY_SPEC,
        "author": AUTHOR,
    }


def scripted_runner(script: dict[tuple[str, ...], dict[str, Any] | str]) -> Runner:
    """Test helper: map argv tuples to stdout. Missing keys are missing binaries."""

    def _run(argv: list[str], timeout: float = 2.0) -> dict[str, Any]:
        _ = timeout
        key = tuple(argv)
        if key not in script:
            return {
                "ok": False,
                "code": 127,
                "stdout": "",
                "stderr": f"{argv[0]}: not found",
                "missing": True,
                "argv": list(argv),
            }
        payload = script[key]
        if isinstance(payload, str):
            return {
                "ok": True,
                "code": 0,
                "stdout": payload,
                "stderr": "",
                "missing": False,
                "argv": list(argv),
            }
        body = dict(payload)
        body.setdefault("argv", list(argv))
        body.setdefault("missing", False)
        return body

    return _run


def env_runner() -> Runner | None:
    """Optional QNM_PHY_SCRIPT JSON for hermetic tests. Default is live OS."""
    raw = os.environ.get("QNM_PHY_SCRIPT")
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    mapped: dict[tuple[str, ...], str] = {}
    if isinstance(data, dict):
        for key, value in data.items():
            mapped[tuple(str(key).split())] = str(value)
    return scripted_runner(mapped)
