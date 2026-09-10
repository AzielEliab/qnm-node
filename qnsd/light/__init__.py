"""Camera-flash OCC — QNS-CD-1.0.

Light is not QNS. QNS is the native medium. Light is optical
camera-communication of the same photon.
"""

from __future__ import annotations

from qnsd.light.camera import Camera
from qnsd.light.codec import PREAMBLE_BITS, decode, encode
from qnsd.light.emitter import Emitter

__all__ = ["Camera", "Emitter", "PREAMBLE_BITS", "decode", "encode"]
