"""Two-host LAN proof. Skipped unless the operator sets the environment.

CI and a single machine must not set QNS_LAN_TWO_HOST. A pass here is
still not a software LIVE flag: the adapter keeps live false.
Procedure: docs/LAN-TWO-HOST-1.0.md.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import qnm  # noqa: F401

pytestmark = pytest.mark.skipif(
    os.environ.get("QNS_LAN_TWO_HOST") != "1",
    reason="needs two physical hosts; see docs/LAN-TWO-HOST-1.0.md",
)


def test_two_host_send() -> None:
    from qnsd.lan.node import LanNode

    data = Path(os.environ["QNS_LAN_DATA"])
    material = json.loads(Path(os.environ["QNS_LAN_PEER_FILE"]).read_text(encoding="utf-8"))
    address = os.environ["QNS_LAN_PEER_ADDRESS"]
    node = LanNode(data, enabled=True, allow_loopback=False)
    node.add_peer(material, address)
    result = node.send_payload(material["handle"], {"text": "two-host"})
    assert result.ack_level == "stored"
    assert result.outcome == "ok"
    assert result.live is False
    assert node.capabilities()["cross_host_proven"] is False
    assert node.capabilities()["live"] is False
    report = node.verify()
    assert report["ok"] is True
    assert report["live"] is False
