"""Task sandbox: a separate process running an allowlisted interpreter.

This is a Python daemon, not Node.js. ``worker_threads`` is not
available here. Tasks run in a child process:

* Cooperative caps inside the interpreter (CPU seconds, allocation
  size) so a normal task stops itself.
* Parent wall-clock timeout kills the process group.
* Parent sets ``RLIMIT_CPU``, ``RLIMIT_AS``, ``RLIMIT_FSIZE``, and
  ``RLIMIT_NOFILE`` before the child runs. The address-space limit is
  a coarse backstop (it includes the interpreter) and is not a precise
  malloc quota. The quota the tenant hits first is the interpreter cap.
* The interpreter has no filesystem or network opcodes. It cannot
  import the parent. Secret environment variables are stripped.
* A child crash, quota, or timeout is caught. It does not exit the
  parent.

This is not a hypervisor, not seccomp, and not a defence against the
OS user who owns the daemon. That user can ptrace the process. Same-UID
escape is out of scope. What the sandbox does guarantee is that an
allowlisted task cannot open the network or the filesystem through the
opcodes we ship, and that a runaway child is killed without taking the
parent down.

"Smart contract" here means this task, not an EVM and not a gas market.

Author: Aziel Eliab only.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from typing import Any

DROP_ENV = {
    "QNM_NODE_PASSPHRASE",
    "QNM_SHELF_KEY",
    "QNM_SHELF_KEY_FILE",
    "QNM_LOCAL_TOKEN",
}


def sandbox_env() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if key not in DROP_ENV}


def worker_main() -> None:
    raw = sys.stdin.buffer.read()
    try:
        job = json.loads(raw.decode("utf-8") or "{}")
    except Exception:
        _emit({"ok": False, "code": "FED-SANDBOX", "detail": "job is not JSON"})
        return
    if not isinstance(job, dict):
        _emit({"ok": False, "code": "FED-SANDBOX", "detail": "job is not an object"})
        return
    limits = job.get("limits") if isinstance(job.get("limits"), dict) else {}
    cpu_seconds = float(limits.get("cpu_seconds") or 1)
    memory_bytes = int(limits.get("memory_bytes") or 0)
    op = str(job.get("op") or "")
    try:
        if op == "add":
            result = _num(job.get("a")) + _num(job.get("b"))
        elif op == "sha256":
            import hashlib

            text = str(job.get("text") or "")
            if len(text) > 4096:
                raise _Quota("text cap")
            result = hashlib.sha256(text.encode("utf-8")).hexdigest()
        elif op == "alloc":
            size = int(job.get("bytes") or 0)
            if size < 0 or size > memory_bytes:
                raise _Quota("memory cap")
            blob = bytearray(size)
            result = len(blob)
            del blob
        elif op == "burn":
            requested = float(job.get("seconds") or 0)
            if requested > cpu_seconds:
                deadline = time.monotonic() + cpu_seconds
                while time.monotonic() < deadline:
                    pass
                raise _Quota("cpu cap")
            deadline = time.monotonic() + requested
            while time.monotonic() < deadline:
                pass
            result = requested
        elif op == "hang":
            while True:
                time.sleep(0.05)
        elif op == "crash":
            raise RuntimeError("task crashed")
        elif op == "echo":
            text = str(job.get("text") or "")
            if len(text) > 1024:
                raise _Quota("echo cap")
            result = text
        else:
            _emit({"ok": False, "code": "FED-SANDBOX", "detail": "opcode refused"})
            return
    except _Quota as exc:
        _emit({"ok": False, "code": "FED-QUOTA", "detail": str(exc)})
        return
    except Exception as exc:  # noqa: BLE001
        _emit({"ok": False, "code": "FED-SANDBOX", "detail": exc.__class__.__name__})
        return
    _emit({"ok": True, "code": "", "result": result})


def _num(value: object) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _Quota("numbers only")
    return value


class _Quota(Exception):
    pass


def _emit(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    sys.stdout.write("\n")


def _preexec(cpu: int, as_bytes: int, fsize: int):
    def _inner() -> None:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (max(cpu, 1), max(cpu, 1) + 1))
        resource.setrlimit(resource.RLIMIT_AS, (as_bytes, as_bytes))
        resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
        resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))

    return _inner


def run_job(
    job: dict[str, Any],
    *,
    cpu_seconds: float,
    wall_seconds: float,
    memory_bytes: int,
    as_bytes: int = 768 * 1024 * 1024,
) -> dict[str, Any]:
    """Run one job. Always returns a dict. Does not raise on quota or crash."""
    payload = dict(job)
    payload["limits"] = {"cpu_seconds": cpu_seconds, "memory_bytes": memory_bytes}
    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "qnm.fedmesh.sandbox"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=sandbox_env(),
            start_new_session=True,
            preexec_fn=_preexec(int(max(cpu_seconds, 1)), as_bytes, 1024 * 1024),
        )
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "code": "FED-SANDBOX", "detail": exc.__class__.__name__}
    try:
        out, _err = proc.communicate(json.dumps(payload).encode("utf-8"), timeout=wall_seconds)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
        return {"ok": False, "code": "FED-QUOTA", "detail": "wall clock"}
    text = out.decode("utf-8", errors="replace") if out else ""
    if len(text) > 65536:
        return {"ok": False, "code": "FED-QUOTA", "detail": "worker output cap"}
    line = text.strip().splitlines()[-1] if text.strip() else ""
    try:
        result = json.loads(line) if line else {"ok": False, "code": "FED-SANDBOX", "detail": "no output"}
    except Exception:
        return {"ok": False, "code": "FED-SANDBOX", "detail": "worker output refused"}
    if proc.returncode not in (0, None) and result.get("ok"):
        return {"ok": False, "code": "FED-SANDBOX", "detail": f"exit {proc.returncode}"}
    if not isinstance(result, dict):
        return {"ok": False, "code": "FED-SANDBOX", "detail": "worker output refused"}
    return result


if __name__ == "__main__":
    worker_main()
