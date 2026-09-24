"""The download archive is the repository at the version the code claims."""

from __future__ import annotations

import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "workers" / "download-tracker" / "public" / "qnm-node-1.6.0.tar.gz"
PREFIX = "qnm-node-1.6.0"


def _version_from_pyproject() -> str:
    for line in (ROOT / "pyproject.toml").read_text(encoding="utf-8").splitlines():
        if line.startswith("version = "):
            return line.split("=", 1)[1].strip().strip('"')
    raise AssertionError("version missing")


def test_versions_match() -> None:
    version = _version_from_pyproject()
    assert version == "1.6.0"
    init = (ROOT / "qnm" / "__init__.py").read_text(encoding="utf-8")
    assert f'__version__ = "{version}"' in init
    product = (ROOT / "workers" / "download-tracker" / "src" / "product.js").read_text(encoding="utf-8")
    assert f'export const VERSION = "{version}"' in product
    wrangler = (ROOT / "workers" / "download-tracker" / "wrangler.toml").read_text(encoding="utf-8")
    assert 'name = "qnm-node-download-tracker"' in wrangler


def test_archive_is_this_repo() -> None:
    assert ARCHIVE.is_file()
    with tarfile.open(ARCHIVE, "r:gz") as tar:
        names = tar.getnames()
    assert f"{PREFIX}/pyproject.toml" in names
    assert f"{PREFIX}/qnm/__init__.py" in names
    assert f"{PREFIX}/qnsd/__init__.py" in names
    assert f"{PREFIX}/README.md" in names
    assert f"{PREFIX}/LICENSE" in names
    assert not any(name.endswith(".tar.gz") for name in names)
    with tarfile.open(ARCHIVE, "r:gz") as tar:
        packed = tar.extractfile(f"{PREFIX}/pyproject.toml")
        assert packed is not None
        text = packed.read().decode("utf-8")
    assert 'version = "1.6.0"' in text


def test_landing_source_has_no_public_score() -> None:
    home = (ROOT / "workers" / "download-tracker" / "src" / "home.js").read_text(encoding="utf-8")
    assert "prefers-color-scheme" in home
    assert "THIS IS NOT" not in home
    assert "identity-lock" not in home
    assert "fielded_score" not in home
    assert "architecture_score" not in home
