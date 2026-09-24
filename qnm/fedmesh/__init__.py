"""Federated mesh for the local qnm daemon.

The wire format, receipt anchor, and rollup bytes live in
``qnm.fedmesh.wire``. That module is the alignment point with
aziel-runtime ``docs/designs/FED-MESH-1.0.md`` (not on main when this
daemon side was written).

Author: Aziel Eliab only.
"""

from __future__ import annotations

__author__ = "Aziel Eliab"
WIRE_SPEC = "FED-MESH-1.0-draft"
