"""PHOENIX-LOCK + REHEAL — QNM-BUILD-1.0 §11 / REHEAL-1.0.

Wait / re-seal after poison or isolation. Does not hunt a controller.
Does not open radios. Does not restore a public hostname, .uk,
Cloudflare tunnel, Worker, or public rollup. Public tunnels and sites
die with the pull.

REHEAL: a poisoned node heals from its own last good tip plus a
verified pull of bytes it already trusted — or it phoenix-WAITs.
It does not heal by listening to neighbors. Allowed chatter:
live / locked / isolated / tip-hash. Forbidden: bodies, diffs,
“here’s what you should be,” vote-to-fix. No majority fanfic.
No lie to stay alive, adapt, or prevent death (NO-LIE-1.0).
No rewrite / mutate of a published tip to look healthy.

Arm is an operator act. After arm, the node stays on this machine.
Mesh does not climb back onto the public hostname by itself.
Neighbors do not phoenix because a neighbor phoenix’d.
"""

from __future__ import annotations

from typing import Any

from qnm.boot import AUTHOR, SPEC, QNMRefuse

REHEAL_SPEC = "REHEAL-1.0"
ALLOWED_STATUS = frozenset({"live", "locked", "isolated"})
CHATTER_FORBIDDEN = frozenset(
    {
        "body",
        "diff",
        "file",
        "payload",
        "should_be",
        "should",
        "advice",
        "vote",
        "votes",
        "majority",
        "fix",
        "vote_to_fix",
    }
)


class Phoenix:
    def __init__(self) -> None:
        self.armed = False
        self.waiting_local = False
        self.controller_hunt = False
        self.last_good_tip: str | None = None
        self.last_good_bytes: str | None = None

    def arm(self) -> dict[str, Any]:
        self.armed = True
        self.waiting_local = True
        self.controller_hunt = False
        return self.status()

    def hunt_controller(self) -> None:
        raise QNMRefuse(
            "QNM-PHOENIX-LOCAL-WAIT",
            "PHOENIX-LOCK waits / re-seals locally; no controller hunt; "
            "no public hostname restore",
        )

    def remember_good(self, tip: str, chain_digest: str) -> None:
        self.last_good_tip = tip
        self.last_good_bytes = chain_digest

    def neighbor_heal(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-REHEAL-NO-NEIGHBOR",
            "does not heal by listening to neighbors",
        )

    def vote_to_fix(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-REHEAL-NO-MAJORITY",
            "no majority fanfic reheal",
        )

    def lie_to_stay_alive(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-NO-LIE-TO-LIVE",
            "network never lies to stay alive",
        )

    def lie_to_adapt(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-NO-LIE-TO-LIVE",
            "network never lies to adapt",
        )

    def lie_to_prevent_death(self, *_args: object, **_kwargs: object) -> None:
        raise QNMRefuse(
            "QNM-NO-LIE-TO-LIVE",
            "network never lies to prevent death",
        )

    def admit_chatter(self, message: dict[str, Any]) -> dict[str, Any]:
        extra = set(message) - {"status", "tip_hash", "tip", "plane", "peer"}
        banned = extra | (set(message) & CHATTER_FORBIDDEN)
        if banned:
            raise QNMRefuse(
                "QNM-REHEAL-CHATTER",
                "allowed chatter is live/locked/isolated/tip-hash only",
            )
        status = str(message.get("status") or "")
        if status not in ALLOWED_STATUS:
            raise QNMRefuse(
                "QNM-REHEAL-CHATTER",
                "allowed chatter is live/locked/isolated/tip-hash only",
            )
        if message.get("plane") not in (None, "tick"):
            raise QNMRefuse("QNM-REHEAL-CHATTER", "chatter stays on the tick plane")
        return {
            "ok": True,
            "status": status,
            "tip_hash": message.get("tip_hash") or message.get("tip") or "",
            "body": False,
            "heal": False,
            "spec": REHEAL_SPEC,
            "author": AUTHOR,
        }

    def status(self) -> dict[str, Any]:
        return {
            "ok": True,
            "armed": self.armed,
            "waiting": "local" if self.waiting_local else "off",
            "controller_hunt": False,
            "last_good_tip": self.last_good_tip,
            "last_good_bytes": self.last_good_bytes,
            "heal_from_neighbor": False,
            "majority_reheal": False,
            "lie_to_stay_alive": False,
            "spec": SPEC,
            "reheal": REHEAL_SPEC,
            "author": AUTHOR,
        }
