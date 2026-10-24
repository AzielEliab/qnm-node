"""PACKET-ADAPTER-1.0 constants and send results.

No socket. ``live`` on a result is always false.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from qnsd.boot import AUTHOR, QNSRefuse

PACKET_V = "QNS-PACKET-1.0"
LAN_V = "QNS-LAN-1.0"
ADAPTER_ID = "lan-tls"
ENC_ALG = "x25519-hkdf-sha256-aes-256-gcm"
SESSION_ALG = "tls1.3"
GENESIS = "0" * 64

MAX_FRAME = 65536
MAX_FRAGMENT = 16384
MIN_FRAGMENT = 256
DEFAULT_FRAGMENT = 4096
MAX_FRAGMENTS = 32
MAX_REASSEMBLY = 262144
MAX_QUEUE_ITEMS = 64
MAX_QUEUE_BYTES = 1_048_576
MAX_INFLIGHT = 8
MAX_CONN_PER_IP = 4
MAX_MESSAGES = 30
MESSAGE_WINDOW_S = 60.0
HANDSHAKE_TIMEOUT_S = 5.0
READ_TIMEOUT_S = 10.0
REASSEMBLY_TIMEOUT_S = 30.0
CLOCK_SKEW_S = 120
RETRY_BUDGET = 8
RETRY_BASE_S = 1.0
RETRY_CAP_S = 60.0
NONCE_BYTES = 32
MAX_NONCES = 1024
DEFAULT_PORT = 8894

ACK_LEVELS = ("received", "verified", "stored")
ROUTE_STATES = (
    "DISCOVERED",
    "AUTHENTICATED",
    "ELIGIBLE",
    "ATTEMPTED",
    "ACKNOWLEDGED",
)

FORBIDDEN_RECORD_KEYS = frozenset(
    {
        "payload",
        "plaintext",
        "text",
        "content",
        "content_b64",
        "password",
        "passphrase",
        "sign_seed",
        "box_seed",
        "private",
        "private_key",
        "lat",
        "lon",
        "latitude",
        "longitude",
        "geohash",
        "location",
        "address",
        "ip",
        "host",
    }
)


class LanRefuse(QNSRefuse):
    """Adapter refusal. ``security`` closes the route."""

    def __init__(
        self,
        code: str,
        detail: str = "",
        *,
        outcome: str = "refused",
        security: bool = True,
    ) -> None:
        super().__init__(code, detail)
        self.outcome = outcome
        self.security = security


@dataclass
class SendResult:
    outcome: str
    code: str = ""
    security: bool = False
    transport_accepted: bool = False
    ack_level: str = ""
    live: bool = False
    detail: str = ""
    packet_id: str = ""
    payload_hash: str = ""
    relay_contacted: bool = False
    levels: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.live = False
        self.relay_contacted = False

    def as_dict(self) -> dict[str, object]:
        return {
            "adapter": ADAPTER_ID,
            "outcome": self.outcome,
            "code": self.code,
            "security": self.security,
            "transport_accepted": self.transport_accepted,
            "ack_level": self.ack_level,
            "live": False,
            "detail": self.detail,
            "packet_id": self.packet_id,
            "payload_hash": self.payload_hash,
            "relay_contacted": False,
            "levels": list(self.levels),
            "author": AUTHOR,
            "v": PACKET_V,
        }
