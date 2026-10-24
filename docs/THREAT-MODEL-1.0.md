# THREAT-MODEL-1.0 — packet path

**Author:** Aziel Eliab only
**Date:** 2026-10-24
**Software:** qnm-node
**Contract:** [PACKET-ADAPTER-1.0](PACKET-ADAPTER-1.0.md)
**License:** Apache-2.0

This is the threat model for the local packet path and for the
specified `lan-tls` adapter. It is not a third-party audit. It is not
a claim that two physical machines have exchanged a packet.

Status words: **implemented** (in the code this commit runs),
**specified** (required of the LAN adapter, not in the Phase 0 tree),
**out of scope** (this version does not promise it).

`GET /v1/mesh` never enables. The HTTP door stays on 127.0.0.1.
Relays stay untrusted for confidentiality and for availability. The
body cipher is not forward secret. TLS 1.3 session keys are a
separate hop property and do not upgrade that claim.

## Assets

- Ed25519 signing seed and X25519 box seed in `data/identity/`
- Photon payload and FED-MESH plaintext
- `photon_id`, receipt history, and per-handle sequence
- Peer pins (public keys, certificate, approved addresses)
- Operator passphrase, when set, and the unattended seal file

## Actors

- A peer who completes, or tries to complete, a session
- A relay that stores ciphertext (existing daemon path)
- A host that can read this process's files
- A LAN attacker who can inject, drop, reorder, or replay frames
- The operator

## Decisions

| Threat | Detected | Prevented | Out of scope |
| --- | --- | --- | --- |
| Malicious peer | **Implemented** on the FED-MESH path: bad signature `FED-TAMPER`, handle mismatch `FED-WRONG-KEY`, cipher failure `FED-E2E`, poison peer lists rejected whole. **Specified** for `lan-tls`: handshake and packet signatures, pinned identity, `QNS-LAN-IDENTITY` / `QNS-LAN-REFUSED`. A refusal closes the route. A weaker adapter is not tried. | **Implemented:** unsigned or wrong-key envelopes are not decrypted into the ledger. **Specified:** no trust-on-first-use; unknown handle is refused before the photon is admitted. | A peer who was honestly pinned and then lies about an application fact inside a valid signature. The node does not execute received bytes. Content truth is not this layer. |
| Malicious relay | **Implemented:** relays see routing metadata and ciphertext, not the body (`seal_envelope`). Envelope signature is checked. One relay is not a quorum. | **Implemented:** body cipher. Relay hosting default off. **Specified:** `lan-tls` does not contact a relay. A temporary LAN failure does not fall through to a relay in this version. | A relay that drops, delays, or keeps ciphertext. Availability of the relay path is not guaranteed. A relay that logs metadata. Hiding metadata from a relay that is actually used. |
| Compromised endpoint key | **Specified:** `key_status=revoked` refuses new sessions (`QNS-LAN-REVOKED`) and does not rewrite old receipts. Old signatures still verify against the archived public key. | **Implemented:** the seed is not written into receipts or logs. Tenant passphrase is not stored. **Specified:** revocation is an operator act, not a network vote. | Detecting theft of a key that is still marked active. Forward secrecy of old FED-MESH bodies after the recipient box key leaks. A same-UID user who can read `unattended.seal` (file permissions, not a passphrase). |
| Replay | **Implemented:** `classify_link` returns `FED-REPLAY` for the same handle, seq, and hash, and `FED-FORK` for the same seq and a different hash. Relay store refuses a repeated envelope id. | **Implemented:** a replay is not a second ledger link. **Specified:** handshake nonce memory (cap 1024) and idempotent `packet_id`. The same packet and payload hash returns the existing stored ack and does not append a second effect. A different payload hash is a fork refusal. | Replays older than the nonce memory and the retained ledger, on a verifier that does not hold the chain. Exactly-once across a partition. |
| LAN spoofing | **Implemented** for the HTTP door: non-loopback clients get `QNM-LOOPBACK-ONLY`. UDP discovery does not merge an unsigned or oversized list and does not authorize a data path. **Specified:** TLS 1.3 mutual auth to the pinned certificate, transcript bound to both handles, both nonces, both cert fingerprints, and `QNS-LAN-1.0`. Source address must be in the approved list. | **Implemented:** the HTTP API is not a LAN mesh. **Specified:** an unpinned certificate or an unlisted source address does not reach `AUTHENTICATED`. Binding `0.0.0.0` or a public address is refused. | A holder of the pinned private keys, speaking from an approved address. That is a compromised key, not a spoof. Switches and ARP are not a trusted identity layer. mDNS is not used. |
| Loss and reorder | **Implemented:** a sequence gap is `FED-GAP` and is not stored. A backwards seq is `FED-FORK`. The outbox keeps a waited photon. | **Specified:** at-least-once send, idempotent `packet_id`, in-order seq advance only after `stored` or a permanent refusal. Fragments may arrive out of order and reassemble under a signed index. A gap is refused, not filled in as success. | Exactly-once. Global order across senders or partitions. A packet still queued when the retry budget or the expiry runs out (that becomes permanent, and the receipt says so). |
| Disk loss | **Implemented:** chain verify reports a broken hash or prev. Outbox wait is restored only from the lock file that is still on disk. A missing lock is not invented. | **Specified:** queue, inbox, and receipts use `fsync`. Verify reports a receipt whose inbox bytes are gone. It does not rewrite the receipt to hide the loss. | Reconstructing bytes that were not copied. Cold-copy of the LAN queue onto another machine (that remains the existing cold-copy design, not an automatic LAN act). Silent heal from a neighbor. |
| Clock skew | **Implemented:** timestamps are metadata. Causal order is `seq` and `prev`. TemporalLock is not invented (`applied: false`). | **Specified:** expiry and a future `created_utc` allow 120 seconds of skew, then `QNS-LAN-EXPIRED` or `QNS-LAN-CLOCK`, permanent, no weaker route. | Proving wall-clock time. Using the clock as a substitute for the predecessor hash. NTP attacks that stay inside 120 seconds. |
| Storage exhaustion | **Implemented:** ciphertext over `MAX_CT_BYTES` is `FED-QUOTA` / `FED-TAMPER`. Peer lists over the card cap are rejected whole. | **Specified:** frame length over 65536 is refused without reading the body. Queue caps at 64 items and 1 MiB. A new append that would pass the cap is `QNS-LAN-QUOTA` and does not delete other packets or receipts. `ENOSPC` is a temporary IO failure, not a rewrite. | Freeing disk by dropping history. Surviving a full disk. Quota fairness across every future adapter. |
| Denial of service | **Implemented:** peer-list rate limit, relay byte quotas, sandbox rlimits on the task path. The HTTP door is loopback. | **Specified:** handshake timeout 5s, read timeout 10s, reassembly timeout 30s, 4 connections per source address, 30 messages per 60 seconds, 8 in flight, fragment count cap 32, reassembly cap 262144 bytes. Excess closes. A quota refusal is not a reason to try a weaker path. | Volumetric attack on the host's NIC or power. DoS by the operator against their own disk. Anonymous internet exposure: this listener refuses public bind, and NAT traversal is not implemented. |
| Device theft | **Implemented:** keystore mode 0600. With a passphrase, scrypt + AES-256-GCM. Without one, the unattended seal file is the key, and a disk copy includes it. Receipts do not contain the seed. | **Specified:** LAN logs and receipts use an allowlist that omits plaintext, keys, and location. Revoke the pin on the surviving peer. Old receipts remain verifiable. | Preventing theft. Remote wipe. Detecting that a powered-off disk was copied. Protecting the unattended seal from the same OS user. |

## Route-closing rule

A `refused` outcome, and any result with `security: true`, stops the
planner. The packet is not offered to a lower-priority adapter.
`permanent` stops the packet as well. `temporary` may retry and may
try a lower adapter that is actually registered. `absent` is not
eligible.

Phase 0 has no `lan-tls` registration. The rule is normative until
the adapter lands. The frozen via walker is a different mechanism and
stays as QNS-CD-1.0 wrote it.

## Honesty limits

- A flag, an imported module, a codec round-trip, or a loopback TLS
  session is not `LIVE`.
- `cross_host_proven` stays false in this version.
- No qubit channel and no entanglement.
- This document is not a pentest and not a certification.

## Cite

Eliab, Aziel. (2026). THREAT-MODEL-1.0
[Software]. Apache-2.0. https://github.com/AzielEliab/qnm-node

Apache-2.0. Forks are welcome and always allowed.
