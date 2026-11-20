"""Shared photon frame and a simulated optical link.

The frame matches aziel-runtime ``qnm-node/bearers/photon.js``:

    preamble 0xAA 0xAA 0xAA 0xAA, sync 0x7E, u16be length, payload, CRC-32.

This module does not open ``/sys``, ``/dev``, or a camera. Simulated
hardware is an in-memory luminance buffer. ``live`` and
``real_hardware`` stay false. A green roundtrip is not a light on a desk.
"""

from __future__ import annotations

import zlib
from typing import Any

from qnsd.boot import QNSRefuse

PHOTON_PREAMBLE = bytes((0xAA, 0xAA, 0xAA, 0xAA))
PHOTON_SYNC = 0x7E
PHOTON_MAX_PAYLOAD = 1024
FRAME_OVERHEAD = 4 + 1 + 2 + 4


def seal_frame(payload: bytes) -> bytes:
    """Length-prefixed frame. The CRC covers the payload only."""
    body = bytes(payload)
    if len(body) > PHOTON_MAX_PAYLOAD:
        raise QNSRefuse("QNS-PHOTON", f"photon payload over {PHOTON_MAX_PAYLOAD} bytes")
    crc = zlib.crc32(body) & 0xFFFFFFFF
    return PHOTON_PREAMBLE + bytes((PHOTON_SYNC,)) + len(body).to_bytes(2, "big") + body + crc.to_bytes(4, "big")


def open_frame(raw: bytes) -> bytes:
    """Return the payload when the preamble, length, and CRC all match."""
    data = bytes(raw)
    if len(data) < FRAME_OVERHEAD or not data.startswith(PHOTON_PREAMBLE):
        raise QNSRefuse("QNS-PHOTON", "photon frame preamble refused")
    if data[4] != PHOTON_SYNC:
        raise QNSRefuse("QNS-PHOTON", "photon frame sync refused")
    length = int.from_bytes(data[5:7], "big")
    if length > PHOTON_MAX_PAYLOAD or len(data) != FRAME_OVERHEAD + length:
        raise QNSRefuse("QNS-PHOTON", "photon frame length refused")
    payload = data[7 : 7 + length]
    crc = int.from_bytes(data[7 + length :], "big")
    if crc != (zlib.crc32(payload) & 0xFFFFFFFF):
        raise QNSRefuse("QNS-PHOTON", "photon frame crc refused")
    return payload


def _samples_for(frame: bytes) -> list[float]:
    """One luminance sample per bit. High is 1, low is 0. Not a sensor reading."""
    samples: list[float] = []
    for byte in frame:
        for shift in range(7, -1, -1):
            samples.append(1.0 if (byte >> shift) & 1 else 0.0)
    return samples


def _frame_from_samples(samples: list[float]) -> bytes:
    if len(samples) < 8 or len(samples) % 8:
        raise QNSRefuse("QNS-PHOTON", "simulated samples are not a whole frame")
    out = bytearray()
    for index in range(0, len(samples), 8):
        value = 0
        for sample in samples[index : index + 8]:
            value = (value << 1) | (1 if sample >= 0.5 else 0)
        out.append(value)
    return bytes(out)


class SimulatedHardware:
    """In-memory flash and sensor. No sysfs, no V4L2, no live claim."""

    def __init__(self) -> None:
        self.samples: list[float] = []
        self.real_hardware = False
        self.live = False
        self.hardware = "simulated"

    def transmit(self, payload: bytes) -> dict[str, Any]:
        framed = seal_frame(payload)
        self.samples = _samples_for(framed)
        return {
            "ok": True,
            "mock": False,
            "live": False,
            "real_hardware": False,
            "hardware": self.hardware,
            "fielded": False,
            "bytes": len(framed),
            "samples": len(self.samples),
        }

    def receive(self) -> dict[str, Any]:
        try:
            payload = open_frame(_frame_from_samples(self.samples))
        except QNSRefuse as exc:
            return {
                "ok": False,
                "mock": False,
                "live": False,
                "real_hardware": False,
                "hardware": self.hardware,
                "fielded": False,
                "code": exc.code,
                "detail": str(exc),
            }
        return {
            "ok": True,
            "mock": False,
            "live": False,
            "real_hardware": False,
            "hardware": self.hardware,
            "fielded": False,
            "payload": payload,
            "samples": len(self.samples),
        }
