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
**partial** (`qnsd/lan` runs it; loopback tests pass; two physical
hosts have not), **out of scope** (this version does not promise it).

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
| Malicious peer | **Implemented** on the FED-MESH path: bad signature `FED-TAMPER`, handle mismatch `FED-WRONG-KEY`, cipher failure `FED-E2E`, poison peer lists rejected whole. **Partial** for `lan-tls`: handshake and packet signatures, pinned identity, `QNS-LAN-IDENTITY` / `QNS-LAN-REFUSED`. A refusal closes the route. A weaker adapter is not tried. Loopback tests cover a bad signature. | **Implemented:** unsigned or wrong-key envelopes are not decrypted into the ledger. **Partial:** no trust-on-first-use; unknown handle is refused before the photon is admitted. | A peer who was honestly pinned and then lies about an application fact inside a valid signature. The node does not execute received bytes. Content truth is not this layer. Not a pentest. |
| Malicious relay | **Implemented:** relays see routing metadata and ciphertext, not the body (`seal_envelope`). Envelope signature is checked. One relay is not a quorum. | **Implemented:** body cipher. Relay hosting default off. **Partial:** `lan-tls` keeps `relay_urls` empty and `relay_contacts` at 0. It does not import the relay client. A temporary LAN failure does not fall through to a relay. | A relay that drops, delays, or keeps ciphertext. Availability of the relay path is not guaranteed. A relay that logs metadata. Hiding metadata from a relay that is actually used. |
| Compromised endpoint key | **Partial:** `key_status=revoked` refuses new sessions (`QNS-LAN-REVOKED`) and does not rewrite old receipts. Old signatures still verify against the archived public key. | **Implemented:** the seed is not written into receipts or logs. Tenant passphrase is not stored. **Partial:** revocation is an operator act, not a network vote. The TLS certificate is not the Ed25519 identity. | Detecting theft of a key that is still marked active. Forward secrecy of old FED-MESH bodies after the recipient box key leaks. A same-UID user who can read `unattended.seal` (file permissions, not a passphrase). |
| Replay | **Implemented:** `classify_link` returns `FED-REPLAY` for the same handle, seq, and hash, and `FED-FORK` for the same seq and a different hash. Relay store refuses a repeated envelope id. **Partial:** a repeated handshake nonce is `QNS-LAN-REPLAY`. | **Implemented:** a replay is not a second ledger link. **Partial:** nonce memory cap 1024 and idempotent `packet_id`. The same packet and payload hash returns the existing stored ack and does not append a second effect. A different payload hash is `QNS-LAN-FORK`. | Replays older than the nonce memory and the retained ledger, on a verifier that does not hold the chain. Exactly-once across a partition. |
| LAN spoofing | **Implemented** for the HTTP door: non-loopback clients get `QNM-LOOPBACK-ONLY`. UDP discovery does not merge an unsigned or oversized list and does not authorize a data path. **Partial:** TLS 1.3 mutual auth to the pinned certificate, transcript bound to both handles, both nonces, both cert fingerprints, and `QNS-LAN-1.0`. Source address must be in the approved list. There is no TLS exporter in this Python; the signed transcript is the binding. | **Implemented:** the HTTP API is not a LAN mesh. **Partial:** an unpinned certificate or an unlisted source address does not reach `AUTHENTICATED`. Binding `0.0.0.0`, a public address, or CGNAT is refused. Loopback requires an explicit opt-in. | A holder of the pinned private keys, speaking from an approved address. That is a compromised key, not a spoof. Switches and ARP are not a trusted identity layer. mDNS is not used. |
| Loss and reorder | **Implemented:** a sequence gap is `FED-GAP` and is not stored. A backwards seq is `FED-FORK`. The outbox keeps a waited photon. **Partial:** `FED-GAP` on this adapter is temporary and does not close the route. | **Partial:** at-least-once send, idempotent `packet_id`, in-order seq. Two packets sealed before either is stored get seq 1 then seq 2. A gap is not filled in as success. Signed fragment indexes are checked. CI sends those indexes in order on one TCP connection. | Exactly-once. Global order across senders or partitions. A packet still queued when the retry budget or the expiry runs out (that becomes permanent, and the receipt says so). A permanently refused outstanding predecessor can block a later sealed seq until an operator clears it. Out-of-order fragment arrival was not measured on two hosts. |
| Disk loss | **Implemented:** chain verify reports a broken hash or prev. Outbox wait is restored only from the lock file that is still on disk. A missing lock is not invented. **Partial:** `verify()` reports `missing_inbox` when an ok receipt's file is gone. | **Partial:** queue, inbox, and receipts use `fsync`. Verify does not rewrite the receipt to hide the loss. | Reconstructing bytes that were not copied. Cold-copy of the LAN queue onto another machine (that remains the existing cold-copy design, not an automatic LAN act). Silent heal from a neighbor. `ENOSPC` is not given a special healer. |
| Clock skew | **Implemented:** timestamps are metadata. Causal order is `seq` and `prev`. TemporalLock is not invented (`applied: false`). | **Partial:** expiry and a future `created_utc` allow 120 seconds of skew, then `QNS-LAN-EXPIRED` or `QNS-LAN-CLOCK`, permanent, no weaker route. | Proving wall-clock time. Using the clock as a substitute for the predecessor hash. NTP attacks that stay inside 120 seconds. |
| Storage exhaustion | **Implemented:** ciphertext over `MAX_CT_BYTES` is `FED-QUOTA` / `FED-TAMPER`. Peer lists over the card cap are rejected whole. **Partial:** frame length over 65536 is refused without reading the body. Queue caps at 64 items and 1 MiB. | **Partial:** a new append that would pass the cap is `QNS-LAN-QUOTA` and does not delete other packets or receipts. | Freeing disk by dropping history. Surviving a full disk. Quota fairness across every future adapter. |
| Denial of service | **Implemented:** peer-list rate limit, relay byte quotas, sandbox rlimits on the task path. The HTTP door is loopback. **Partial:** handshake timeout 5s, read timeout 10s, reassembly timeout 30s, 4 connections per source address, 30 messages per 60 seconds, 8 in flight, fragment count cap 32, reassembly cap 262144 bytes. | **Partial:** excess closes. A quota refusal is security and is not a reason to try a weaker path. CI checks the frame cap, the queue cap, and the message counter. It does not flood a NIC. | Volumetric attack on the host's NIC or power. DoS by the operator against their own disk. Anonymous internet exposure: this listener refuses public bind, and NAT traversal is not implemented. |
| Device theft | **Implemented:** keystore mode 0600. With a passphrase, scrypt + AES-256-GCM. Without one, the unattended seal file is the key, and a disk copy includes it. Receipts do not contain the seed. | **Partial:** LAN logs and receipts use an allowlist that omits plaintext, keys, and location. Revoke the pin on the surviving peer. Old receipts remain verifiable. The inbox file is recipient custody and does hold the photon. | Preventing theft. Remote wipe. Detecting that a powered-off disk was copied. Protecting the unattended seal from the same OS user. |

## Route-closing rule

A `refused` outcome, and any result with `security: true`, stops the
planner. The packet is not offered to a lower-priority adapter.
`permanent` stops the packet as well. `temporary` may retry and may
try a lower adapter that is actually registered. `absent` is not
eligible.

`LanNode` registers only `LanTLSAdapter`. The frozen via walker is a
different mechanism and stays as QNS-CD-1.0 wrote it. A test double
used to prove this rule is not a route and is not LIVE.

## Phase 1 socket notes

These are the notes for the new listener. They are partial. They are
not a claim that two machines have met.

- **Socket.** Default off. Bind is one operator-selected IPv4 address that is assigned on this host. `0.0.0.0`, `::`, public, and CGNAT are refused. Loopback needs `--loopback`. Port default 8894. The HTTP door stays `127.0.0.1`. Importing the package does not bind.
- **Peer identity.** Mutual TLS 1.3, pinned certificate, Ed25519 transcript over both handles, both nonces, both cert fingerprints, and `QNS-LAN-1.0`. No trust on first use. Source IP must match the pinned host, not the ephemeral port. A security refusal is a signed outcome when the handshake has already passed TLS, and the planner does not try a lower route.
- **Replay.** Nonces are remembered (cap 1024). `packet_id` plus `payload_hash` is idempotent. Sequence uses `classify_link` unchanged. `FED-GAP` is temporary. Other sequence failures are security refusals.
- **Resource exhaustion.** Frame length is rejected before the body. Queue, fragment, message, and connection caps close or refuse. A full queue does not delete other rows. This does not absorb a NIC flood.

## Honesty limits

- A flag, an imported module, a codec round-trip, or a loopback TLS
  session is not `LIVE`.
- `cross_host_proven` stays false. The field is not set by a successful
  loopback session and it is not set by CI.
- Phase 1 is not done. Done needs two independent physical machines
  run by Aziel. CI cannot show that.
- No qubit channel and no entanglement.
- This document is not a pentest and not a certification.

## Cite

Eliab, Aziel. (2026). THREAT-MODEL-1.0
[Software]. Apache-2.0. https://github.com/AzielEliab/qnm-node

Apache-2.0. Forks are welcome and always allowed.
