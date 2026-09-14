# COLD-COPY-1.0

**Author:** Aziel Eliab only
**Companion:** [SPLIT-WIRES-1.0](SPLIT-WIRES-1.0.md) · [QNM-BUILD-1.0](QNM-BUILD-1.0.md)
**License:** Apache-2.0
**Date:** September 2026

Public identity is **Aziel Eliab** only.

Keep **split-the-wires** and **die-with-the-pull**. This paper does not
climb back onto a public hostname.

## Locked law

Make a tip expensive to erase by multiplying **cold copies** and
**refusing live sync** of bodies across the network.

- **Unkillable by single-server pull:** N cold replicas (MESH-VAULT on
  transfer, reader local vaults, optional pin of already-public tip /
  receipt hashes). Pulling the origin / Worker / DNS does **not** erase
  cold copies.
- **Impossible to just pull down from the server:** public rollup may
  **die with the pull**; records remain on cold copies plus local
  verify / append.
- **Hard to poison:** hash-absolute fail-closed ingest; cite prev +
  lockset; equivocation isolates the peer; **no live body sync** that
  could spray poison; majority cannot outvote a broken hash.
- **Data outlives the creators:** tips / receipts / vault tips are
  content-addressed; local node keeps verifying / appending without the
  creator online; no dependency on a living operator session for cold
  verify.
- **Refuse live sync of bodies across the network.** Tip plane stays
  presence + tip hash only. Payloads stay **pull-only** cold replicas on
  the second plane.

### Hosts

- **Named hosts only.**
- **No unmarked hydra.**
- **No VPN concealment.**

This is not a VPN, mixnet, or anonymity overlay. Replica placement is
an explicit named host (`local`, `mesh-vault`, `reader`, or an operator
declared name). Device-class hosts for persist/transfer: `laptop`,
`phone`, `apple-watch`, `phone-watch`, `radio`, `bluetooth`. A pull
or offline hop does not erase those copies. `*`, hydra, unmarked,
VPN, Tor, and conceal hosts refuse.

## Close tests

- Three named replicas survive `pull_origin`.
- After pull: origin / Worker / DNS down; objects + replicas remain;
  local verify / append still works; Phoenix does not restore the
  public name.
- `live_sync` refused (`QNM-COLD-NO-LIVE-SYNC`).
- Cold verify does not require a creator session.
- Unmarked hydra and VPN concealment refused.
- Public pin stores a hash only — no live body.

Specified 2026-09-14. Author: Aziel Eliab only.
