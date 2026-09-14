# RE-EXPAND-1.0

**Author:** Aziel Eliab only
**Companion:** [SPLIT-WIRES-1.0](SPLIT-WIRES-1.0.md) · [COLD-COPY-1.0](COLD-COPY-1.0.md) · [QNM-BUILD-1.0](QNM-BUILD-1.0.md)
**License:** Apache-2.0
**Date:** September 2026

Public identity is **Aziel Eliab** only.

Keep split-the-wires, cold-copy, and die-with-the-pull.

## Locked law

- **Bytes of the chain survive, not summaries.** The archive tarball
  holds `chain/node.jsonl` bytes plus a manifest of their hashes.
- **Re-expand = archive verify + a new local node seated on that tip.**
  New `install_root`. Same chain bytes. Tip unchanged.
- **Not mesh growing from an index.** No peer list, crawl map, or
  spiderweb expansion from an index file.
- **Crawlers do not re-expand.**
- **Weights ≠ tarball.** A model blob (`.pt`, `.safetensors`, …) is
  not a chain archive.

Phoenix still does not restore a public hostname. Public tunnels and
sites **die with the pull**. Cold copies of the tarball may remain.

## Close tests

- Packed archive bytes equal the live chain file.
- Re-expand boots a different install on the same tip.
- `from_index` refused. `actor=crawler` refused.
- Weights filename / weights refuse. Summary-only archive refused.

Specified 2026-09-14. Author: Aziel Eliab only.
