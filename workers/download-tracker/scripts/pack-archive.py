#!/usr/bin/env python3
"""Pack workers/download-tracker/public/qnm-node-<version>.tar.gz from this repo.

The version comes from pyproject.toml. The archive is the Worker download.
It is a source snapshot, not a GitHub release asset.
"""

from __future__ import annotations

import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TRACKER = Path(__file__).resolve().parents[1]
PUBLIC = TRACKER / "public"


def read_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("version = "):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise SystemExit("version missing from pyproject.toml")


SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "node_modules",
    ".wrangler",
}
SKIP_FILES = {".env", ".qnm-shelf-key"}


def skipped(path: Path) -> bool:
    rel = path.relative_to(ROOT)
    if any(part in SKIP_DIRS for part in rel.parts):
        return True
    if path.name in SKIP_FILES or path.name.endswith(".shelf.key"):
        return True
    if path.suffix == ".tar.gz" or path.name.endswith(".tar.gz"):
        return True
    if path.suffix in {".pyc", ".pyo"}:
        return True
    return False


def main() -> None:
    version = read_version()
    prefix = f"qnm-node-{version}"
    dest = PUBLIC / f"{prefix}.tar.gz"
    PUBLIC.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        dest.unlink()
    files = [p for p in ROOT.rglob("*") if p.is_file() and not skipped(p)]
    with tarfile.open(dest, "w:gz") as tar:
        for path in sorted(files):
            rel = path.relative_to(ROOT).as_posix()
            tar.add(path, arcname=f"{prefix}/{rel}", recursive=False)
    print(f"wrote {dest} ({dest.stat().st_size} bytes, {len(files)} files)")


if __name__ == "__main__":
    main()
