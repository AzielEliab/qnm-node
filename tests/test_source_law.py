"""§14 extra: live symbols must not be assigned as success states."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_no_live_completeness_assignments() -> None:
    banned_assigns = (
        'state = "lattice_online"',
        'state = "mesh_complete"',
        'STATE = "Lumen"',
        'STATE = "Mandible"',
        "bell_pair = True",
        "qubit = True",
    )
    for path in (ROOT / "qnm").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for token in banned_assigns:
            assert token not in text, f"{path.name} assigns {token}"
