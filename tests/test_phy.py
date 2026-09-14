"""LIVE OS PHY probes: scripted LIVE parse + CI ABSENT/REFUSED."""

from __future__ import annotations

from pathlib import Path

import pytest

from qnm.boot import QNMRefuse
from qnm.node import Node
from qnsd.phy import REFUSE_CODES, probe, probe_all, scripted_runner
from qnsd.vias.base import FIELDING_ABSENT, FIELDING_LIVE, REFUSED, ViaContext
from qnsd.vias.bt import BtAdapter
from qnsd.vias.gps import GpsAdapter
from qnsd.vias.nfc import NfcAdapter
from qnsd.vias.rf import RfAdapter
from qnsd.vias.wifi import WifiAdapter


LIVE_SCRIPT = {
    ("mmcli", "-L"): "/org/freedesktop/ModemManager1/Modem/0 [Qualcomm]\n",
    ("mmcli", "-m", "0"): "  SIM | path: /org/freedesktop/ModemManager1/SIM/0\n",
    ("iw", "dev"): "phy#0\n        Interface wlan0\n",
    ("nmcli", "-t", "-f", "TYPE,DEVICE,STATE", "device"): "wifi:wlan0:disconnected\n",
    ("bluetoothctl", "list"): "Controller AA:BB:CC:DD:EE:FF BlueZ [default]\n",
    ("gpspipe", "-w", "-n", "4"): (
        '{"class":"TPV","mode":3,"lat":51.5074,"lon":-0.1278,"time":"2026-09-14T00:00:00.000Z"}\n'
    ),
    ("nfc-list"): "NFC device: pn532_uart:/dev/ttyUSB0 opened\n",
}


def test_ci_host_is_absent_and_emit_refuses() -> None:
    cards = probe_all()
    assert cards["invented"] is False
    assert cards["mock"] is False
    assert cards["mesh_enable"] is False
    assert cards["az_generator"] is False
    ctx = ViaContext()
    photon = {"op": "note"}
    for name, adapter in (
        ("rf", RfAdapter()),
        ("wifi", WifiAdapter()),
        ("bt", BtAdapter()),
        ("gps", GpsAdapter()),
        ("nfc", NfcAdapter()),
    ):
        assert cards["labels"][{"rf": "cellular"}.get(name, name)] == "ABSENT"
        assert adapter.presence(ctx) == "ABSENT"
        emitted = adapter.emit(photon, ctx)
        assert emitted.ok is False
        assert emitted.kind == REFUSED
        phy = {"rf": "cellular", "gps": "gps"}.get(name, name)
        assert emitted.code == REFUSE_CODES[phy] if name != "gps" else "RADIO-NO-GNSS"


def test_scripted_live_parse_does_not_invent_tx() -> None:
    runner = scripted_runner(LIVE_SCRIPT)
    ctx = ViaContext(phy_runner=runner)
    photon = {"op": "note"}
    cellular = probe("cellular", runner=runner)
    assert cellular["live"] is True
    assert cellular["sim"] is True
    assert cellular["transmitted"] is False
    wifi = probe("wifi", runner=runner)
    assert wifi["live"] is True
    assert wifi["adapter"] == "wlan0"
    bt = probe("bt", runner=runner)
    assert bt["live"] is True
    gps = probe("gps", runner=runner)
    assert gps["live"] is True
    assert gps["fix"]["lat"] == 51.5074
    nfc = probe("nfc", runner=runner)
    assert nfc["live"] is True
    rf = RfAdapter().emit(photon, ctx)
    assert rf.ok is True
    assert rf.live_link is True
    assert "transmitted=false" in rf.detail
    gnss = GpsAdapter().emit(photon, ctx)
    assert gnss.ok is False
    assert gnss.code == "RADIO-GNSS-RX-ONLY"
    assert gnss.kind == REFUSED


def test_bitmesh_binds_from_live_gnss(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    runner = scripted_runner(LIVE_SCRIPT)
    rec = node.bitmesh.bind(node.chain.tip, phy_runner=runner)
    assert rec["fielding"] == FIELDING_LIVE
    assert rec["gps_driver"] is True
    assert rec["geohash"]
    with pytest.raises(QNMRefuse) as exc:
        node.bitmesh.bind(node.chain.tip)
    assert exc.value.code == "RADIO-NO-GNSS"


def test_local_phy_route(tmp_path: Path) -> None:
    node = Node(tmp_path)
    node.boot(entropy=b"e", nonce=b"n")
    code, payload = node.handle("GET", "/local/phy", b"")
    assert code == 200
    assert payload["ok"] is True
    assert payload["mock"] is False
    assert set(payload["labels"]) >= {"cellular", "wifi", "bt", "gps", "nfc"}
    for label in payload["labels"].values():
        assert label in ("LIVE", "ABSENT", "REFUSED")
    from qnsd.node import Node as QnsdNode

    qnsd = QnsdNode(tmp_path / "q")
    qnsd.boot(entropy=b"q", nonce=b"n")
    code, qpayload = qnsd.handle("GET", "/local/phy", b"")
    assert code == 200
    assert qpayload["invented"] is False
