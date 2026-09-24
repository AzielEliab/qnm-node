"""Local site drafts for the three user domain slots.

Block order is the edit model. A visual drag surface belongs to the
browser that opens this node. Preview HTML names image hashes and does
not paint image bytes. Embeds cite local apps only.

The four hub names are reserved mirrors, not user labels. The
self-certifying ``<handle>.aziel`` name is not one of the three slots.
MirageGrid Cap-7 factory names are a separate layer and are not edited
here.

Author: Aziel Eliab only.
"""

from __future__ import annotations

import html
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from qnm.boot import AUTHOR, QNMRefuse
from qnm.fedmesh.wire import sha256_hex

USER_SLOTS = 3
THEMES = ("night", "day", "aziel")
TEMPLATES = ("blank", "note", "links")
BLOCK_TYPES = ("text", "image", "link", "gallery", "embed")
LOCAL_APPS = ("receipts", "state", "fedmesh")
RESERVED_SLOTS = (
    {"id": "ae", "name": "AZ.AzielEliab.AZ"},
    {"id": "corpus", "name": "AZ.AzielCorpusLibrary.AZ"},
    {"id": "godlock", "name": "AZ.Godlock.AZ"},
    {"id": "hdj", "name": "AZ.HeDidntJump.AZ"},
)
RESERVED_NAMES = {row["name"].casefold() for row in RESERVED_SLOTS}
RESERVED_IDS = {row["id"] for row in RESERVED_SLOTS}
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.aziel$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

THEME_CSS = {
    "night": "body{background:#000000;color:#ffffff;font-family:sans-serif}",
    "day": "body{background:#ffffff;color:#000000;font-family:sans-serif}",
    "aziel": (
        "body{background:#000000;color:#ffffff;font-family:sans-serif}"
        ".surface{background:#4b0082;color:#ffffff}"
        ".accent{color:#d4af37}"
    ),
}


def self_name(handle: str) -> str:
    body = str(handle or "")
    if body.startswith("#"):
        body = body[1:]
    return body.lower() + ".aziel"


def check_label(label: str, handle: str) -> str:
    name = str(label or "").strip().lower()
    if name in RESERVED_NAMES or name.split(".", 1)[0] in RESERVED_IDS:
        raise QNMRefuse("FED-SLOT", "reserved hub mirrors are not user-nameable")
    if name == self_name(handle):
        raise QNMRefuse("FED-SLOT", "the self-certifying name is not a user slot")
    if not _LABEL_RE.match(name) or len(name) > 64:
        raise QNMRefuse("FED-SLOT", "user domain label refused")
    return name


class DesignBook:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, stat.S_IRWXU)

    def public_slots(self) -> dict[str, Any]:
        return {
            "reserved": [dict(row) | {"user_nameable": False} for row in RESERVED_SLOTS],
            "user_slots": USER_SLOTS,
            "themes": list(THEMES),
            "templates": list(TEMPLATES),
            "block_types": list(BLOCK_TYPES),
            "cap7_factory_unchanged": True,
            "remote": False,
        }

    def load(self, handle: str) -> list[dict[str, Any]]:
        folder = self._folder(handle)
        rows = []
        if not folder.is_dir():
            return rows
        for path in sorted(folder.glob("*.json")):
            rows.append(json.loads(path.read_text(encoding="utf-8")))
        return rows

    def save(self, handle: str, document: dict[str, Any]) -> dict[str, Any]:
        slot = int(document["slot"])
        if slot < 0 or slot >= USER_SLOTS:
            raise QNMRefuse("FED-SLOT", "a handle has 3 user slots")
        folder = self._folder(handle)
        folder.mkdir(parents=True, exist_ok=True)
        os.chmod(folder, stat.S_IRWXU)
        path = folder / f"{slot}.json"
        path.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        return document

    def get(self, handle: str, slot: int) -> dict[str, Any]:
        path = self._folder(handle) / f"{int(slot)}.json"
        if not path.is_file():
            raise QNMRefuse("FED-SLOT", "that user slot is empty")
        return json.loads(path.read_text(encoding="utf-8"))

    def _folder(self, handle: str) -> Path:
        body = handle[1:] if handle.startswith("#") else handle
        allowed = set("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
        if not body or any(ch not in allowed for ch in body):
            raise QNMRefuse("FED-SLOT", "design handle refused")
        return self.root / body


def draft_document(
    *,
    handle: str,
    slot: int,
    label: str,
    template: str,
    theme: str,
    blocks: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    if template not in TEMPLATES:
        raise QNMRefuse("FED-SLOT", "unknown template")
    if theme not in THEMES:
        raise QNMRefuse("FED-SLOT", "unknown theme")
    name = check_label(label, handle)
    chosen = [_clean_block(block) for block in blocks] if blocks is not None else _template_blocks(template)
    return {
        "v": "FED-MESH-1.0",
        "author": AUTHOR,
        "handle": handle,
        "slot": int(slot),
        "label": name,
        "template": template,
        "theme": theme,
        "blocks": chosen,
        "published": False,
    }


def move_block(document: dict[str, Any], source: int, dest: int) -> dict[str, Any]:
    blocks = list(document.get("blocks") or [])
    if source < 0 or dest < 0 or source >= len(blocks) or dest >= len(blocks):
        raise QNMRefuse("FED-SLOT", "block move refused")
    block = blocks.pop(source)
    blocks.insert(dest, block)
    updated = dict(document)
    updated["blocks"] = blocks
    return updated


def preview_html(document: dict[str, Any]) -> str:
    theme = str(document.get("theme") or "night")
    if theme not in THEME_CSS:
        raise QNMRefuse("FED-SLOT", "unknown theme")
    label = html.escape(str(document.get("label") or ""))
    parts = [
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">",
        f"<title>{label}</title><style>{THEME_CSS[theme]}</style></head>",
        f"<body class=\"surface\"><h1 class=\"accent\">{label}</h1>",
    ]
    for block in document.get("blocks") or []:
        parts.append(_render_block(block))
    parts.append("</body></html>")
    page = "".join(parts)
    return page


def page_html(*, handle: str, unlocked: bool) -> str:
    slots = "".join(f"<li>{html.escape(row['name'])}</li>" for row in RESERVED_SLOTS)
    state = "unlocked" if unlocked else "locked"
    return (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Design mode</title>"
        "<style>body{background:#000000;color:#ffffff;font-family:sans-serif}"
        ".surface{background:#4b0082;color:#ffffff}.accent{color:#d4af37}</style></head>"
        f"<body><h1 class=\"accent\">Design mode</h1>"
        f"<p>Local only. Handle key {state}. Remote access is refused.</p>"
        f"<p>Self-certifying name {html.escape(self_name(handle))} is not a user slot.</p>"
        f"<p>{USER_SLOTS} user slots. Themes: night, day, aziel.</p>"
        f"<ul>{slots}</ul></body></html>"
    )


def collect_texts(document: dict[str, Any]) -> list[str]:
    texts = [str(document.get("label") or "")]
    for block in document.get("blocks") or []:
        kind = block.get("type")
        if kind == "text":
            texts.append(str(block.get("text") or ""))
        elif kind == "link":
            texts.append(str(block.get("text") or ""))
            texts.append(str(block.get("href") or ""))
        elif kind == "embed":
            texts.append(str(block.get("app") or ""))
    return texts


def image_hashes(document: dict[str, Any]) -> list[str]:
    found: list[str] = []
    for block in document.get("blocks") or []:
        if block.get("type") == "image" and block.get("sha256"):
            found.append(str(block["sha256"]))
        if block.get("type") == "gallery":
            found.extend(str(item) for item in block.get("images") or [])
    return found


def site_bytes(document: dict[str, Any]) -> bytes:
    public = {
        "v": document["v"],
        "author": AUTHOR,
        "handle": document["handle"],
        "label": document["label"],
        "theme": document["theme"],
        "template": document["template"],
        "blocks": document["blocks"],
    }
    return json.dumps(public, sort_keys=True, separators=(",", ":")).encode("utf-8")


def site_digest(document: dict[str, Any]) -> str:
    return sha256_hex(site_bytes(document))


def _template_blocks(template: str) -> list[dict[str, Any]]:
    if template == "note":
        return [{"type": "text", "text": "Write here"}]
    if template == "links":
        return [{"type": "link", "href": "https://example.invalid/", "text": "Link"}]
    return []


def _clean_block(block: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(block, dict):
        raise QNMRefuse("FED-SLOT", "block refused")
    kind = str(block.get("type") or "")
    if kind not in BLOCK_TYPES:
        raise QNMRefuse("FED-SLOT", "block type refused")
    if kind == "text":
        return {"type": "text", "text": str(block.get("text") or "")[:4000]}
    if kind == "link":
        href = str(block.get("href") or "")
        if not href.startswith(("https://", "http://", "/")) or "javascript:" in href.lower():
            raise QNMRefuse("FED-SLOT", "link refused")
        return {"type": "link", "href": href[:500], "text": str(block.get("text") or "")[:200]}
    if kind == "embed":
        app = str(block.get("app") or "")
        if app not in LOCAL_APPS:
            raise QNMRefuse("FED-SLOT", "embed is a local app cite")
        return {"type": "embed", "app": app}
    if kind == "image":
        digest = str(block.get("sha256") or "")
        if not _HEX64.match(digest):
            raise QNMRefuse("FED-SLOT", "image block needs a sha256")
        return {"type": "image", "sha256": digest, "alt": str(block.get("alt") or "")[:200]}
    images = [str(item) for item in list(block.get("images") or [])]
    if not images or any(not _HEX64.match(item) for item in images):
        raise QNMRefuse("FED-SLOT", "gallery needs sha256 names")
    return {"type": "gallery", "images": images[:12]}


def _render_block(block: dict[str, Any]) -> str:
    kind = block.get("type")
    if kind == "text":
        return f"<p>{html.escape(str(block.get('text') or ''))}</p>"
    if kind == "link":
        href = html.escape(str(block.get("href") or ""), quote=True)
        text = html.escape(str(block.get("text") or ""))
        return f"<p><a href=\"{href}\">{text}</a></p>"
    if kind == "embed":
        return f"<p>local app {html.escape(str(block.get('app') or ''))}</p>"
    if kind == "image":
        return f"<p>image {html.escape(str(block.get('sha256') or ''))}</p>"
    names = " ".join(html.escape(str(item)) for item in block.get("images") or [])
    return f"<p>gallery {names}</p>"
