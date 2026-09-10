"""OOK light codec — QNS-CD-1.0.

Preamble marks a photon. Bits without the preamble are a probe, not a
photon. Hash covers the payload bytes so a roundtrip can be verified.
"""

from __future__ import annotations

import json
from typing import Any

from qnsd.boot import sha256_hex
from qnsd.photon import Photon, dumps, loads

# 16-bit OOK preamble: 10101010 11110000
PREAMBLE_BITS = (1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0)
PREAMBLE_BYTES = bytes(PREAMBLE_BITS)


def _bytes_to_bits(data: bytes) -> list[int]:
    bits: list[int] = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def _bits_to_bytes(bits: list[int]) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        value = 0
        for bit in bits[i : i + 8]:
            value = (value << 1) | (1 if bit else 0)
        out.append(value)
    return bytes(out)


def _as_bits(raw: bytes | list[int] | tuple[int, ...]) -> list[int]:
    if isinstance(raw, (list, tuple)):
        return [1 if bit else 0 for bit in raw]
    if raw.startswith(b"OOK:"):
        return [1 if ch == 49 else 0 for ch in raw[4:]]
    if len(raw) >= len(PREAMBLE_BYTES) and raw[: len(PREAMBLE_BYTES)] == PREAMBLE_BYTES:
        return list(raw)
    return [1 if ch == 49 else 0 for ch in raw]


def encode(photon: Photon | dict[str, Any]) -> bytes:
    """Preamble + length + payload + sha256(payload). Returns OOK:bitstring."""
    payload = dumps(photon if isinstance(photon, Photon) else loads(photon))
    digest = sha256_hex(payload).encode("ascii")
    length = len(payload).to_bytes(4, "big")
    body = length + payload + digest
    bits = list(PREAMBLE_BITS) + _bytes_to_bits(body)
    return b"OOK:" + bytes(48 + b for b in bits)


def decode(raw: bytes | list[int] | tuple[int, ...]) -> dict[str, Any]:
    bits = _as_bits(raw)
    preamble = list(PREAMBLE_BITS)
    if len(bits) < len(preamble) or bits[: len(preamble)] != preamble:
        return {
            "kind": "probe",
            "is_photon": False,
            "probe": True,
            "code": "QNS-PROBE-NOT-PHOTON",
        }
    rest = bits[len(preamble) :]
    body = _bits_to_bytes(rest)
    if len(body) < 4 + 64:
        return {
            "kind": "probe",
            "is_photon": False,
            "probe": True,
            "code": "QNS-PROBE-NOT-PHOTON",
        }
    length = int.from_bytes(body[:4], "big")
    payload = body[4 : 4 + length]
    digest = body[4 + length : 4 + length + 64]
    expect = sha256_hex(payload).encode("ascii")
    if digest != expect:
        return {
            "kind": "probe",
            "is_photon": False,
            "probe": True,
            "code": "QNS-PROBE-NOT-PHOTON",
            "detail": "hash mismatch",
        }
    photon = loads(payload)
    return {
        "kind": "photon",
        "is_photon": True,
        "probe": False,
        "photon": photon.to_dict(),
        "hash": digest.decode("ascii"),
        "photon_id": photon.photon_id,
    }


def bits_without_preamble(photon: Photon | dict[str, Any]) -> bytes:
    """Test helper: payload OOK with no preamble → probe."""
    payload = dumps(photon if isinstance(photon, Photon) else loads(photon))
    bits = _bytes_to_bits(payload)
    return b"OOK:" + bytes(48 + b for b in bits)
