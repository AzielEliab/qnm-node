"""Reserved hub mirrors. Four slots, not user-nameable.

Restore replaces a local copy only after the statement verifies and
every file hash matches. A mismatch writes nothing. This node can
serve the verified copy on loopback. It does not write the origin hub.

Author: Aziel Eliab only.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from qnm.boot import QNMRefuse
from qnm.fedmesh.design import RESERVED_IDS, RESERVED_SLOTS
from qnm.fedmesh.secwire import verify_statement
from qnm.fedmesh.wire import canonical, sha256_hex

GENESIS = "0" * 64


class MirrorStore:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, stat.S_IRWXU)

    def status(self) -> dict[str, Any]:
        rows = []
        for slot in RESERVED_SLOTS:
            tip = self._tip(slot["id"])
            rows.append(
                {
                    "id": slot["id"],
                    "name": slot["name"],
                    "user_nameable": False,
                    "held": tip is not None,
                    "served_locally": tip is not None,
                    "origin_restored": False,
                }
            )
        return {"ok": True, "slots": rows, "origin_restored": False}

    def restore(self, statement: dict[str, Any], files: dict[str, bytes]) -> dict[str, Any]:
        verify_statement(statement)
        if statement.get("kind") != "mirror-restore":
            raise QNMRefuse("FED-TAMPER", "mirror statement kind refused")
        slot = str(statement.get("slot") or "")
        if slot not in RESERVED_IDS:
            raise QNMRefuse("FED-SLOT", "mirror slot is not a reserved hub mirror")
        listed = statement.get("files")
        if not isinstance(listed, list) or not listed:
            raise QNMRefuse("FED-TAMPER", "mirror manifest refused")
        checked: list[tuple[str, bytes]] = []
        for row in listed:
            if not isinstance(row, dict):
                raise QNMRefuse("FED-TAMPER", "mirror file row refused")
            name = str(row.get("name") or "")
            digest = str(row.get("sha256") or "")
            if not name or "/" in name or name.startswith("."):
                raise QNMRefuse("FG-GATE-REFUSE", "mirror file name refused")
            blob = files.get(name)
            if blob is None or sha256_hex(blob) != digest:
                raise QNMRefuse("FG-GATE-REFUSE", "mirror bytes do not match the hash")
            checked.append((name, blob))
        self._link(slot, statement)
        folder = self.root / slot
        folder.mkdir(parents=True, exist_ok=True)
        os.chmod(folder, stat.S_IRWXU)
        for name, blob in checked:
            path = folder / name
            path.write_bytes(blob)
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        record = {
            "handle": statement.get("handle"),
            "seq": int(statement.get("seq") or 0),
            "prev": str(statement.get("prev") or ""),
            "hash": sha256_hex(canonical({key: value for key, value in statement.items() if key != "sig"})),
            "index": str(statement.get("index") or checked[0][0]),
            "files": [{"name": name, "sha256": sha256_hex(blob)} for name, blob in checked],
        }
        tip_path = folder / "tip.json"
        tip_path.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(tip_path, stat.S_IRUSR | stat.S_IWUSR)
        return {
            "ok": True,
            "slot": slot,
            "verified": True,
            "served_locally": True,
            "origin_restored": False,
            "hash": record["hash"],
        }

    def serve(self, slot: str) -> dict[str, Any]:
        if slot not in RESERVED_IDS:
            raise QNMRefuse("FED-SLOT", "mirror slot is not a reserved hub mirror")
        tip = self._tip(slot)
        if tip is None:
            raise QNMRefuse("FED-FETCH", "reserved mirror is empty")
        name = str(tip.get("index") or "")
        expected = ""
        for row in tip.get("files") or []:
            if row.get("name") == name:
                expected = str(row.get("sha256") or "")
        path = self.root / slot / name
        if not expected or not path.is_file():
            raise QNMRefuse("FG-GATE-REFUSE", "mirror bytes do not match the hash")
        data = path.read_bytes()
        if sha256_hex(data) != expected:
            raise QNMRefuse("FG-GATE-REFUSE", "mirror bytes do not match the hash")
        return {
            "ok": True,
            "slot": slot,
            "name": name,
            "sha256": expected,
            "bytes": len(data),
            "text": data.decode("utf-8", "replace"),
            "served_locally": True,
            "origin_restored": False,
        }

    def _tip(self, slot: str) -> dict[str, Any] | None:
        path = self.root / slot / "tip.json"
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def _link(self, slot: str, statement: dict[str, Any]) -> None:
        seq = int(statement.get("seq") or 0)
        prev = str(statement.get("prev") or "")
        tip = self._tip(slot)
        if tip is None:
            if seq != 1 or prev != GENESIS:
                raise QNMRefuse("FED-GAP", "mirror restore must start at the genesis link")
            return
        if str(statement.get("handle") or "") != str(tip.get("handle") or ""):
            raise QNMRefuse("FED-WRONG-KEY", "reserved mirror signer does not match the held copy")
        if seq <= int(tip.get("seq") or 0) or prev != str(tip.get("hash") or ""):
            raise QNMRefuse("FED-FORK", "mirror restore conflicts with the held copy")
