"""Two-host LAN proof. The send is skipped unless the operator opts in.

CI must not set QNS_LAN_TWO_HOST. A pass is still not a software LIVE
flag. ``same_machine`` and ``second_device`` are reported from the
peer file's ``machine_id`` and this host's ``/etc/machine-id``. A
missing id does not become a second device. Procedure:
docs/LAN-TWO-HOST-1.0.md.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import qnm  # noqa: F401

from qnsd.lan.node import host_facts, local_machine_id


def test_host_facts_stay_honest_without_a_second_machine() -> None:
    loopback = host_facts("127.0.0.1:9", local_id="aa", peer_id="bb", stored=True)
    assert loopback == {
        "same_machine": True,
        "second_device": False,
        "host_proven": True,
        "live": False,
        "loopback": True,
    }
    missing = host_facts("10.1.0.8:8894", local_id=local_machine_id(), peer_id="", stored=True)
    assert missing["second_device"] is False
    assert missing["live"] is False


@pytest.mark.skipif(
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
    peer_id = str(material.get("machine_id") or os.environ.get("QNS_LAN_PEER_MACHINE_ID") or "")
    local_id = str(os.environ.get("QNS_LAN_MACHINE_ID") or local_machine_id())
    facts = host_facts(address, local_id=local_id, peer_id=peer_id, stored=True)
    assert facts["live"] is False
    assert not (facts["same_machine"] and facts["second_device"])
    if os.environ.get("QNS_LAN_EXPECT_SECOND") == "1":
        assert facts["same_machine"] is False
        assert facts["second_device"] is True
        assert facts["host_proven"] is True
