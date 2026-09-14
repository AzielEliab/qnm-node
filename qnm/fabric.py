"""FABRIC-MESH-PIPELINE-1.0 — local fabric coordinator.

Ingress → APG → tip/dwell/claim strangers → via walker → photon
translate → outbox → cold-copy / phoenix / reheal / re-expand.

qnm-node never calls AZ Generator. Node Gate is a MirageGrid
subsystem only (outward claim surface). Radios stay off. Physical
vias may be protocol-complete mocks.

Author: Aziel Eliab only.
"""

from __future__ import annotations

from typing import Any

from qnm.boot import AUTHOR, SPEC, QNMRefuse
from qnm.wires import DWELL_CLOCK, DWELL_SOCKET, TICK_CLOCK, TICK_SOCKET

FABRIC_SPEC = "FABRIC-MESH-PIPELINE-1.0"
VIA_ORDER = ("lan", "plc", "bt", "rf", "light", "qns", "operator", "local")
DECLARE_REQUIRED = ("rf", "plc", "light")
ALWAYS_PRESENT = ("local", "qns", "operator")
PHYSICAL_MOCK = ("bt", "rf", "light")

CLAIM_CLOCK = "miragegrid_claim"
CLAIM_SOCKET = "node_gate_front"
TICK_SOCKET_NAME = TICK_SOCKET
DWELL_SOCKET_NAME = DWELL_SOCKET

STAGES = (
    "ingress",
    "apg",
    "tip_dwell_claim_strangers",
    "via_walker",
    "photon_translate",
    "outbox",
    "cold_copy_phoenix_reheal_reexpand",
)

AZ_GENERATOR_KEYS = frozenset(
    {
        "az_generator",
        "call_az_generator",
        "azgenerator",
        "invoke_generator",
        "back_gate",
        "stand_back",
    }
)
NODE_GATE_KEYS = frozenset(
    {
        "node_gate",
        "nodegate",
        "front_gate_call",
        "miragegrid_call",
        "miragegrid",
    }
)
MESH_ENABLE_KEYS = frozenset(
    {
        "mesh_enable",
        "enable_mesh",
        "lattice_online",
        "mesh_complete",
    }
)
PROXY_KEYS = frozenset(
    {
        "public_qnsd",
        "qnsd_proxy",
        "public_qnsd_proxy",
        "proxy_qnsd",
    }
)
FABRIC_OPS = frozenset(
    {
        "az_generator",
        "call_az_generator",
        "node_gate",
        "mesh_enable",
        "qnsd_proxy",
        "public_qnsd_proxy",
        "claim_clock",
        "miragegrid_claim",
    }
)

_CLOCKS = {
    TICK_CLOCK: TICK_SOCKET,
    DWELL_CLOCK: DWELL_SOCKET,
    CLAIM_CLOCK: CLAIM_SOCKET,
}


class Fabric:
    """Local fabric law. Does not open radios. Does not call MirageGrid."""

    def status(self) -> dict[str, Any]:
        return {
            "ok": True,
            "spec": FABRIC_SPEC,
            "build": SPEC,
            "author": AUTHOR,
            "stages": list(STAGES),
            "via_order": list(VIA_ORDER),
            "declare_required": list(DECLARE_REQUIRED),
            "always_present": list(ALWAYS_PRESENT),
            "physical_vias": {name: "mock" for name in PHYSICAL_MOCK},
            "radios": "off",
            "remote_bearer": False,
            "bind": "127.0.0.1",
            "sticky_via": False,
            "softwares_tab": False,
            "mesh_enable": False,
            "node_gate": False,
            "az_generator": False,
            "call_az_generator": False,
            "public_qnsd_proxy": False,
            "live_rf_mesh": False,
            "public_hostname_restore": False,
            "clocks": {
                "tick": TICK_CLOCK,
                "dwell": DWELL_CLOCK,
                "claim": CLAIM_CLOCK,
                "shared_socket": False,
                "claim_is_stranger": True,
            },
            "miragegrid": {
                "subsystem": "Node Gate only (not qnm-node)",
                "surface": "outward claim",
                "fed_by": "deep-node generator",
                "clock": CLAIM_CLOCK,
                "socket": CLAIM_SOCKET,
                "stranger_to": [TICK_CLOCK, DWELL_CLOCK],
                "called_from_qnm": False,
                "back_gate": False,
                "stand_back_call": False,
            },
        }

    def refuse_az_generator(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-NO-AZ-GENERATOR",
            "AZ Generator is not called from qnm; it exits outward "
            "through the MirageGrid FRONT Node Gate only",
        )

    def call_az_generator(self, *_args: object, **_kwargs: object) -> None:
        """Named hole stays a refuse. Do not implement a call path."""
        self.refuse_az_generator()

    def refuse_node_gate(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-NO-NODE-GATE",
            "Node Gate is a MirageGrid subsystem only; not qnm-node",
        )

    def refuse_mesh_enable(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-MESH-NEVER-ENABLES",
            "GET /v1/mesh never enables",
        )

    def refuse_public_qnsd_proxy(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-NO-QNSD-PROXY",
            "no public qnsd proxy",
        )

    def refuse_claim_clock(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-WIRES-THREE-CLOCKS",
            "MirageGrid claim clock is an external stranger to tip and dwell",
        )

    def refuse_shared_clock(
        self,
        clock: str,
        socket: str,
    ) -> dict[str, Any]:
        """Tip, dwell, and MirageGrid claim never share a socket."""
        expected = _CLOCKS.get(clock)
        if clock == CLAIM_CLOCK:
            self.refuse_claim_clock()
        if expected is None:
            raise QNMRefuse(
                "QNM-WIRES-THREE-CLOCKS",
                "unknown clock is not a yes",
            )
        if socket != expected:
            raise QNMRefuse(
                "QNM-WIRES-THREE-CLOCKS",
                "tip, dwell, and claim clocks stay strangers",
            )
        if clock == TICK_CLOCK and socket == DWELL_SOCKET:
            raise QNMRefuse("QNM-WIRES-THREE-CLOCKS", "1s loop stays off the 777s gate")
        if clock == DWELL_CLOCK and socket == TICK_SOCKET:
            raise QNMRefuse("QNM-WIRES-THREE-CLOCKS", "777s gate stays off the 1s loop")
        return {
            "ok": True,
            "clock": clock,
            "socket": socket,
            "claim_is_stranger": True,
            "spec": FABRIC_SPEC,
            "author": AUTHOR,
        }

    def refuse_payload(self, payload: dict[str, Any]) -> None:
        """Refuse generator / gate / mesh-enable / public-proxy acts."""
        keys = {str(key).lower() for key in payload}
        op = str(payload.get("op") or payload.get("action") or "").lower()
        if op in ("az_generator", "call_az_generator") or keys & {
            k.lower() for k in AZ_GENERATOR_KEYS
        }:
            self.refuse_az_generator()
        if op in ("node_gate", "miragegrid") or keys & {k.lower() for k in NODE_GATE_KEYS}:
            self.refuse_node_gate()
        if keys & {k.lower() for k in MESH_ENABLE_KEYS} or op in (
            "mesh_enable",
            "enable_mesh",
        ):
            self.refuse_mesh_enable()
        if keys & {k.lower() for k in PROXY_KEYS} or op in (
            "qnsd_proxy",
            "public_qnsd_proxy",
        ):
            self.refuse_public_qnsd_proxy()
        if op in ("claim_clock", "miragegrid_claim") or payload.get("clock") == CLAIM_CLOCK:
            self.refuse_claim_clock()
        if payload.get("authorize_by_claim") or payload.get("heal_from_claim"):
            self.refuse_claim_clock()

    def run(
        self,
        node: Any,
        raw: bytes | str | dict[str, Any],
        *,
        qnsd: Any | None = None,
        via: str = "local",
    ) -> dict[str, Any]:
        """One local pipeline pass. Does not call AZ Generator."""
        walked: list[str] = []
        if isinstance(raw, dict):
            self.refuse_payload(raw)
            import json

            body = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode("utf-8")
        elif isinstance(raw, str):
            body = raw.encode("utf-8")
        else:
            body = raw
        walked.append("ingress")
        payload = node.apg.admit(body)
        walked.append("apg")
        self.refuse_payload(payload)
        walked.append("tip_dwell_claim_strangers")
        self.refuse_shared_clock(TICK_CLOCK, TICK_SOCKET)
        self.refuse_shared_clock(DWELL_CLOCK, DWELL_SOCKET)

        via_out: dict[str, Any] | None = None
        if qnsd is not None and (
            payload.get("forward")
            or payload.get("photon")
            or str(payload.get("op") or "") == "forward"
        ):
            dest = str(payload.get("dest") or payload.get("dst") or "peer")
            inner = dict(payload.get("payload") or payload.get("photon") or {})
            if "op" not in inner:
                inner = {"op": "note", "text": str(payload.get("text") or "fabric")}
            via_out = qnsd.forward(
                dest,
                inner,
                via=via if via in VIA_ORDER else None,
                via_in=str(payload.get("via_in") or via or ""),
            )
            walked.append("via_walker")
            walked.append("photon_translate")
            if via_out.get("waiting"):
                walked.append("outbox")
        else:
            item = node.outbox.queue(
                "fabric-note",
                {
                    "op": str(payload.get("op") or "note"),
                    "via": via,
                    "az_generator": False,
                    "node_gate": False,
                },
            )
            walked.append("outbox")
            via_out = {"queued": item["id"], "via": via, "emitted": False}

        receipt = {
            "ok": True,
            "admitted": True,
            "stages": walked,
            "pipeline": list(STAGES),
            "via": via,
            "walk": via_out,
            "az_generator": False,
            "node_gate": False,
            "call_az_generator": False,
            "claim_clock": CLAIM_CLOCK,
            "claim_is_stranger": True,
            "radios": "off",
            "spec": FABRIC_SPEC,
            "author": AUTHOR,
            "state": getattr(node, "state", ""),
        }
        if hasattr(node, "_write_receipt"):
            node._write_receipt("fabric", {"stages": walked, "via": via})
        return receipt
