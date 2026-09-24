"""Local ethics check for design-mode publish. Fail closed.

Three checks are required before a site ref is signed: a nudity/sexual
image check, a child-image check, and a hate-text check. They run on
this machine. The bytes are not sent anywhere to be classified.

This process ships no model weights. A missing model is
``verdict: absent`` and publish is refused. Absence is not a violation
and does not isolate the handle. A test double is not a detector.

A positive result names a reason code and an evidence hash. The hash is
SHA-256 of the model id and the content hash. The content is not copied
into the receipt. Classifiers miss things and they false-positive.
This check does not catch everything.

Author: Aziel Eliab only.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any, Callable

from qnm.boot import QNMRefuse
from qnm.fedmesh.wire import canonical, sha256_hex

MODEL_IDS = ("nudity", "child-image", "hate-text")
REASONS = {
    "nudity": "ETHICS-NUDITY",
    "child-image": "ETHICS-CHILD-IMAGE",
    "hate-text": "ETHICS-HATE",
}
ENV_KEYS = {
    "nudity": "QNM_ETHICS_NUDITY",
    "child-image": "QNM_ETHICS_CHILD",
    "hate-text": "QNM_ETHICS_HATE",
}


class EthicsGate:
    def __init__(self) -> None:
        self.commands = {name: os.environ.get(ENV_KEYS[name]) or "" for name in MODEL_IDS}
        self.runners: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {}

    def probe(self) -> list[dict[str, Any]]:
        rows = []
        for name in MODEL_IDS:
            runner = self.runners.get(name)
            if runner is not None:
                version = str(getattr(runner, "version", "") or "in-process")
                rows.append(
                    {
                        "name": name,
                        "version": version,
                        "verdict": "present",
                        "source": "in-process",
                        "detector": False,
                    }
                )
                continue
            command = self.commands.get(name) or ""
            path = shutil.which(command) if command else None
            if not path:
                rows.append(
                    {
                        "name": name,
                        "version": None,
                        "verdict": "absent",
                        "source": "none",
                        "detector": False,
                    }
                )
                continue
            rows.append(
                {
                    "name": name,
                    "version": _version(path),
                    "verdict": "present",
                    "source": "local-executable",
                    "detector": False,
                }
            )
        return rows

    def status(self) -> dict[str, Any]:
        rows = self.probe()
        absent = [row["name"] for row in rows if row["verdict"] != "present"]
        return {
            "models": rows,
            "absent": absent,
            "fail_closed": True,
            "content_leaves_node": False,
            "catches_everything": False,
            "publish_blocked": bool(absent),
        }

    def check(self, *, texts: list[str], images: list[bytes]) -> dict[str, Any]:
        rows = self.probe()
        absent = [row["name"] for row in rows if row["verdict"] != "present"]
        if absent:
            raise QNMRefuse("FED-ETHICS-ABSENT", "ethics model absent; publish is blocked")
        versions = {row["name"]: row["version"] for row in rows}
        for image in images:
            digest = sha256_hex(image)
            for name in ("nudity", "child-image"):
                hit = self._run(name, {"kind": "image", "sha256": digest}, image, versions[name])
                if hit is not None:
                    return hit
        for text in texts:
            raw = text.encode("utf-8")
            digest = sha256_hex(raw)
            hit = self._run("hate-text", {"kind": "text", "sha256": digest}, raw, versions["hate-text"])
            if hit is not None:
                return hit
        return {
            "ok": True,
            "verdict": "clear",
            "models": [{"name": row["name"], "version": row["version"], "verdict": "clear"} for row in rows],
            "content_stored": False,
            "catches_everything": False,
        }

    def _run(self, name: str, header: dict[str, Any], raw: bytes, version: str | None) -> dict[str, Any] | None:
        runner = self.runners.get(name)
        if runner is not None:
            payload = dict(header)
            payload["body"] = raw
            result = runner(payload)
        else:
            result = _exec(self.commands[name], header, raw)
        verdict = str(result.get("verdict") or "")
        if verdict not in ("clear", "refuse"):
            raise QNMRefuse("FED-ETHICS-ABSENT", "ethics model returned no verdict; publish is blocked")
        if verdict == "clear":
            return None
        model_version = str(result.get("version") or version or "")
        evidence = sha256_hex(
            canonical({"model": name, "version": model_version, "input_sha256": header["sha256"]})
        )
        return {
            "ok": False,
            "verdict": "refuse",
            "reason": REASONS[name],
            "model": name,
            "version": model_version,
            "evidence": evidence,
            "input_sha256": header["sha256"],
            "content_stored": False,
            "catches_everything": False,
        }


def _exec(command: str, header: dict[str, Any], raw: bytes) -> dict[str, Any]:
    path = shutil.which(command)
    if not path:
        raise QNMRefuse("FED-ETHICS-ABSENT", "ethics model absent; publish is blocked")
    proc = subprocess.run(
        [path],
        input=canonical(header) + b"\n" + raw,
        capture_output=True,
        timeout=5,
        check=False,
    )
    if proc.returncode != 0:
        raise QNMRefuse("FED-ETHICS-ABSENT", "ethics model failed; publish is blocked")
    try:
        parsed = json.loads(proc.stdout.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QNMRefuse("FED-ETHICS-ABSENT", "ethics model returned non-JSON; publish is blocked") from exc
    if not isinstance(parsed, dict):
        raise QNMRefuse("FED-ETHICS-ABSENT", "ethics model returned a non-object; publish is blocked")
    return parsed


def _version(path: str) -> str:
    try:
        proc = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=3, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    line = (proc.stdout or proc.stderr or "").strip().splitlines()
    return line[0][:120] if line else ""
