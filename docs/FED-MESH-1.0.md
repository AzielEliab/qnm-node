# FED-MESH-1.0 — local-first edge mesh (daemon)

**Author:** Aziel Eliab only
**Software:** qnm-node
**Wire module:** `qnm/fedmesh/wire.py`
**Status:** daemon draft. `docs/designs/FED-MESH-1.0.md` is not on
aziel-runtime `main`. This process does not claim the Worker speaks
this draft.

Lamb Lens holds under every flag below. **Service:** a participant is
a handle, messages can be delivered, tasks run locally. **Clarity:**
the sections below say what is encrypted, what a relay can read, what
the sandbox stops, and what this process does not do. **Peace:**
relay, direct, LAN discovery, edge compute, and multisig are off
until an Admin turns that one thing on. Quotas apply. `GET` never
enables.

## What this process does

The inner core stays on the daemon. Keys, content-addressed files,
tenant tasks, and heavy compute run in this process. They do not wait
on a network round-trip.

Default outbound policy is enforced in `qnm/fedmesh/policy.py` on every
post, not only described here. Without an explicit share, a post may
be a signed receipt, a ref update, a rollup of hashes, a peer card, a
digest, a fetch request, or a similar light record. Raw fields
(`text`, `plaintext`, `content`, `content_b64`, `password`,
`passphrase`, seeds, private keys, file bytes) are refused. A message
or task leaves only when the caller sets `share` and the body is
already ciphertext.

A share is end-to-end between handles: ephemeral X25519 to the
recipient's static X25519 key, HKDF-SHA256 (salt `FED-MESH-1.0`, info
`FED-MESH-1.0|from|to|seq`), AES-256-GCM with a 12-byte nonce and no
additional data. A later leak of the recipient key opens old bodies.
This process does not claim forward secrecy, and it has no
XChaCha20-Poly1305. Relays see the runtime message fields: version
`FED-MESH-1.0`, kind `msg`, handle, signing public key, to, sequence,
previous hash, nonce, ephemeral public key, ciphertext, and the
envelope signature. The inner kind (note, file, object, task) sits
inside the ciphertext.

Author identity remains **Aziel Eliab**. The handle is the participant.

## Handle

`#` plus 11 Crockford base32 characters (no I, L, O, or U, no padding) of
SHA-256 of the raw 32-byte Ed25519 public key. `key_id` is the hex
SHA-256 of that same public key. Anyone can recompute the handle from
the public key. There is no central registry.

The owner keystore is `data/identity/`. With `QNM_NODE_PASSPHRASE` set
(environment only, never an argument), the seal is scrypt + AES-256-GCM.
Argon2id is not used: it is not in the standard library or in the
`cryptography` package this process depends on. With no passphrase, a
random 32-byte `unattended.seal` (mode 0600) is the sealing key. A full
disk copy includes that file. That is file-permission protection, not a
passphrase.

Tenant keys use the tenant passphrase (minimum 8 characters). The
passphrase is not stored and is not logged. Admin has no decrypt API.
Admin cannot unlock a tenant keystore. A copy of the sealed file is
still readable by anyone with the operating-system user's rights; the
passphrase is what keeps the seed closed.

## Several instances

Instances do not share keys or state.

```bash
python -m qnm doctor --data-dir /tmp/qnm-a --profile alpha
python -m qnm serve --port 8891 --data-dir /tmp/qnm-a --profile alpha
python -m qnm serve --port 8892 --data-dir /tmp/qnm-a --profile beta
```

`--data-dir` is the instance root. `--profile` nests
`profiles/<name>` under that root (`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`).
Passing both a non-default `--root` and a different `--data-dir`
refuses (`FED-PROFILE`). `--port` is the loopback listen port.

## Relays

`--relay URL` (repeatable) sets outbound relay URLs. It does not enable
relay hosting. `cfg/node.json` `fedmesh.use_default_relay` defaults to
false, so this process does not contact
`https://aziel-runtime.vibelock.workers.dev` unless the operator turns
that on or passes the URL. The Worker is one configurable relay among
many. This daemon does not claim the Worker accepts this draft.

Any daemon can opt in as a relay (`POST /local/fedmesh` `{"op":"relay_on"}`,
Admin only, default off). The relay speaks the same `/v1/fedmesh/*`
paths on the same 127.0.0.1 listener. It stores ciphertext, with a TTL
(default 86400 seconds) and a per-handle byte quota. Poll does not
delete; ack does. The sender writes a second copy to another healthy
relay when one is reachable. One relay's death does not drop a message
that was replicated. A message accepted by only one relay dies with
that relay. That is two copies, not a quorum.

Health is a failed send or poll, not a background heartbeat. Direct or
cluster is preferred when the direct inbox is on and a peer URL is
known. Otherwise the client uses a relay. `upstream_off` stops relay
contact and leaves cluster delivery alone.

NAT, STUN, TURN, and ICE are not implemented. The HTTP listener refuses
WAN bind. Peers that are not on this host's loopback fall back to a
relay they can both reach. Calling that local-network speed means
loopback between instances on one host. It is not zero-latency, and it
is not a cross-machine LAN HTTP mesh.

## Neighborhood

Cluster peers are handles this node has marked, with their base URLs.
Messaging, object fetch, ref fan-out, and rollup fan-out try those
URLs first. With upstream cut (relay URLs dead or `upstream_off`), two
loopback instances still exchange a message, share a file by hash, and
co-sign a rollup. The rollup stays pending until a later `sync` and is
then stored by a relay. The relay records `temporal_lock: false` and
`chainlock_upstream: false`. This process does not claim runtime
ChainLock or TemporalLock sealed it. `temporal.applied` is true only
when an importable TemporalLock engine returns a stamp. None is
imported here, so the stamp is local UTC and `applied` is false.

Each new receipt also carries an `identity_anchor` in the
ACT-RECEIPT-1.1 shape: `v`, `handle`, `public_key`, `seq`, `prev`,
`receipt_hash`, and `sig`. It is attached after `receipt_hash` is
computed and is excluded from that hash, so older receipts still
verify. `public_key` is the signing key. The hex `key_id` stays on the
mesh anchor; the runtime anchor statement does not include `key_id`.
This signature is local. `chainlock_upstream` stays false. The anchor
does not claim the runtime four-field ACT-RECEIPT-1.0 hash.

LAN discovery is opt-in UDP (`lan_on`), magic `QNM1`, default bind
127.0.0.1. It is not mDNS. Broadcast to 255.255.255.255 is a separate
call and is reported as failed when the OS refuses it. Peer lists are
signed, capped (32 peers, 8 relays, 4 addresses, 8192 bytes), and
rate-limited. An oversized, unsigned, or over-rate list is rejected
whole.

Bluetooth: `bt` already exists as an opt-in PHY bearer, default off,
LIVE only when BlueZ is present. This mesh does not send over
Bluetooth. `bluetooth.mesh_transport` is false. A Bluetooth bearer for
the mesh is future work, not a tested radio.

## Content model

Objects live under `data/fedmesh/objects/<sha256>`, mode 0600, and are
checked against the hash on read. Private by default. Only the owner
handle can share. A fetch is served only to a handle in that share
list, and only as ciphertext. Other handles on the same daemon get
`FED-SHARE`. Fetch tries cluster URLs, then other known peer URLs, then
relays if upstream is on. The client checks the hash before caching.
Storage quotas apply.

A push publishes one signed ref update: version, kind `ref`, author,
handle, key id, signing public key, ref name, object hash, previous
ref hash, sequence, time, hash, signature. That update is the default
broadcast. Receipt chains are per-handle branches. Co-signed rollups
are merges of hashes, not of file bytes. Conflicting ref updates for
the same handle and ref use the same fork check as receipts
(`FED-FORK`, `FED-REPLAY`, `FED-GAP`).

A node can push while upstream is off. The ref stays in a pending list.
`sync` publishes it when a relay accepts. Cluster fan-out does not
clear that pending list.

## Receipts

Every local receipt gains a `mesh` anchor before `receipt_hash`: signer
handle, key id, per-handle sequence, previous hash, payload hash, time,
signature. The existing QNM chain sequence is unchanged. Private keys
and message plaintext are not written into receipts. The anchor hash
covers the anchor core; the signature covers that core.

Relays verify the envelope signature, the handle binding, and replay or
fork of envelopes they have seen. They do not enforce sequence gaps,
because they have not seen the sender's local boot history. The
recipient enforces gaps. The sender includes a prefix of public anchors
inside the ciphertext (cap 128) so the recipient can walk from genesis.

Incoming envelopes reject replay (same envelope id), forks, wrong-key
handles, gaps, and tampered ciphertext (`FED-E2E` when AES-GCM fails).

## Tenants, roles, sandbox

Admin manages tenants, quotas, relay, direct, LAN, edge, and multisig.
Admin acts as the host identity and cannot read another identity's key,
inbox, or private objects.

Developer may message, fetch, put, push, share, sync, run tasks, and
join rollups, inside quota.

Guest may message, fetch, poll, and read the public GET routes. Guest
receipt and inbox views are redacted.

A missing `X-QNM-Role-Token` on 127.0.0.1 is the host Admin, so existing
local callers stay owners. A presented token is enforced on every local
route, including loopback. In-process `handle()` without an actor stays
the owner path used by the existing suite.

Tasks run in a child process (`python -m qnm.fedmesh.sandbox`): an
allowlisted interpreter (add, sha256, alloc, burn, hang, crash, echo).
No network or filesystem opcodes. The parent sets `RLIMIT_CPU`,
`RLIMIT_AS` (768MB coarse backstop, including the interpreter, not a
precise malloc quota), `RLIMIT_FSIZE`, and `RLIMIT_NOFILE`, and kills
the process group on the wall clock. Cooperative caps inside the
worker are the quota a tenant hits first. Secret environment variables
are stripped. One tenant's quota, crash, or hang does not exit the
parent.

This is not a hypervisor, not seccomp, and not a defence against the
same-UID OS user (that user can ptrace). "Smart contract" here means
this task, not an EVM and not a gas market.

Edge compute is off by default. A `purpose=task` envelope is refused
with `FED-EDGE-OFF` before decrypt and before the sandbox runs. When
an Admin enables it, the host writes a `fedmesh_edge_host` receipt of
hashes only, and the sender already wrote a local message receipt.
Both are signatures this process can show. Neither is a runtime
ChainLock ack.

## Multisig

Off by default, stored in that node's `book.json` only. M-of-N
Ed25519 approvals over the envelope id. The sender's own signature
counts if they are a member. Below the threshold the envelope is not
routed. A node with the vault off sends immediately. Signatures can be
checked by anyone with the public keys; this process does not claim an
upstream chain stored them.

## Bootstrap

A new node needs at least one address: a relay URL, a peer URL, or LAN
discovery. `needs_bootstrap` is true until one of those exists. There
is no hidden directory.

## Mesh security

The runtime paper on `cursor/fed-mesh-e546` (`b6b2ea9a`) has a Mesh
Security section. It does not yet define design mode, ethics reason
codes, isolation records, or reserved hub slots. Statements this
daemon signs use version `FED-MESH-1.0`, the same canonical JSON, and
Ed25519 over the statement with `sig` removed. Keys and signatures on
those statements are unpadded base64url.

Payload mesh traffic cannot turn end-to-end encryption off (`e2e_off`
is `FED-POLICY`). Ref updates, receipts, and digests stay signed
public copies, which is what FED-MESH-1.0 already says. Two-hop is
opt-in and off by default. The entry relay is given a hop statement
whose `to` is the exit handle. The recipient handle and the inner
envelope sit inside a layer the entry cannot open. The exit is given a
`hop-exit` view with no origin handle. It opens a `blind` object that
names the recipient and carries ciphertext, not the origin. Hop HKDF
info is `FED-MESH-1.0|hop|<exit>|<seq>`. Blind info is
`FED-MESH-1.0|blind|<recipient>|<seq>`. The runtime message cipher puts
the origin in HKDF info, so it cannot hide the origin from a relay that
must decrypt. This hop schedule is the one that matches the operator
rule. It is not in the runtime paper yet.

Tor is an optional SOCKS5 adapter (default `127.0.0.1:9050`), off by
default. It is not an onion network this process runs. If the proxy is
down, the send is `FED-TOR-ABSENT` and does not fall back to clearnet.
TLS-through-Tor is not implemented. There is no zero-knowledge claim
and no claim of safety against a state-level adversary.

Each peer has a message and byte budget and a circuit breaker
(`FED-PEER-QUOTA`, `FED-BREAKER`). Quarantine is a signed local
decision (`network_wide: false`). Island mode drops relays and peer
URLs, keeps local put/task/ref, and on leave restores them and syncs
pending refs. A conflicting ref is still a fork.

Inbound objects and files land in `data/fedmesh/airlock/` mode 0600 and
are not executed. Promotion scans with ClamAV and YARA when those
programs are on PATH. A missing scanner is `verdict: absent` (or
`rules-absent` / `error`). Promotion then needs an Admin `override`.
The receipt records scanner name, version, and verdict. Scanners catch
known malware only. The task sandbox is the main defense.

Airgap export writes `SHA256SUMS` in `sha256sum -c` form plus a signed
`airgap.json`. Import checks both, then lands the bytes back in the
airlock. That does not mark Plane C live.

Local trust is one peer at a time: chain length, chain age, heartbeats
seen, hash matches, vouches, an equivocation flag, and advisory flags.
There is no score and no ranking. An advisory list is a signed
statement. It changes only the subscriber. Name claims are not
finalized here (`FED-WITNESS`); witness and proof-of-work belong to the
relay spec.

## Design mode, ethics, isolation, reserved mirrors

Design mode edits the three user `.aziel` slots on this process only.
The HTTP peer must be loopback, and the handle must sign a one-time
challenge. A remote peer is `FG-GATE-REFUSE`. `GET /local/design` and
`GET /local/fedmesh` do not unlock it and do not enable anything.

A draft is templates, an ordered block list (text, image, link,
gallery, embed of a local app), and a theme: night, day, or aziel.
Preview HTML is generated here. It does not paint image bytes and it
does not fetch links. Block order is the edit model. The self-certifying
`<handle>.aziel` name is not one of the three slots. The handle body
is Crockford base32. The runtime vector seed `0102…1f20` yields
`#CPV0CWYPXP4`.

Publish checks ethics before any ref is signed. The required checks are
nudity/sexual images, images of children, and hate text. They run in a
local process. Content is not sent off the node to be classified. This
program ships no model weights. A missing model is `absent` and publish
is `FED-ETHICS-ABSENT`. That is fail closed. Absence does not isolate
the handle. A test double is not a detector. Classifiers miss things
and they false-positive. This does not catch everything.

A refusal writes an isolation record in the runtime field set:
`reason` (`NUDITY`, `CHILD`, `HATE`, or `CSAM`), `check`, `model`,
`evidence_hash`, and the signature fields. `author`, `content_stored`,
`chainlock`, and `temporal_lock` are not in that signed record. Local
metadata still records `content_stored: false` and `chainlock: false`.
The record is anchored on the local receipt chain, posted to each
configured relay at `/v1/mesh/relay/isolation`, and only then does the
handle's node enter island mode. Local keys and drafts stay. `leave_island` is
refused while that isolation stands. A child-image refusal deletes the
staged bytes and keeps the hash. This program does not store or forward
that image, and it does not file a report. Operators follow the law
where they are, including a US duty to report child sexual abuse
material to NCMEC. An appeal is a signed request for a re-check.
`lifted` stays false. This process has no review board.

A relay that is shown a self-signed isolation record refuses that
handle's later relay acts. Relays that never see the record are not
updated. `network_wide` is false.

Four reserved slots mirror `AZ.AzielEliab.AZ`,
`AZ.AzielCorpusLibrary.AZ`, `AZ.Godlock.AZ`, and `AZ.HeDidntJump.AZ`
(`ae`, `corpus`, `godlock`, `hdj`). They are not user-nameable. Restore
keeps a local copy only when the statement verifies and every file hash
matches. A mismatch is `FG-GATE-REFUSE` and writes nothing. Serving
re-checks the hash. `origin_restored` stays false: this node does not
write the public hub. MirageGrid Cap-7 factory names
(`azgrid.az` and the rest of that allowlist) are a separate layer and
are not changed here.

## Open alignment with aziel-runtime

The runtime spec was not on `main` when this draft was written. The
wire format lives in `qnm/fedmesh/wire.py` so it can move later.
Alignment points:

1. Refs, anchors, and most daemon objects stay `FED-MESH-1.0-draft`. Message envelopes and isolation records use `FED-MESH-1.0`.
2. Handle length is 11 Crockford base32 characters. Seed `0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20` yields `#CPV0CWYPXP4`.
3. `key_id` is hex SHA-256 of the raw 32-byte Ed25519 public key.
4. Canonical JSON is UTF-8, sorted keys, separators `,` and `:`.
5. Ed25519 signs the canonical object with `sig` removed.
6. Message E2E is ephemeral X25519, HKDF-SHA256 salt `FED-MESH-1.0`, info `FED-MESH-1.0|from|to|seq`, AES-256-GCM, 12-byte nonce, no additional data. The recipient key is static. This is not a forward-secrecy claim.
7. Send, direct, refs, and fetch stay under `/v1/fedmesh/*`. Isolation is posted to `/v1/mesh/relay/isolation`. `GET /v1/mesh` never enables radios. `GET /v1/mesh/relay` is health and does not enable.
8. Rollups are signed plaintext hashes, not ciphertext. This daemon records them as relay-stored. It does not claim ChainLock or TemporalLock.
9. The default relay URL is the Worker origin. This daemon does not claim the Worker speaks this draft.
10. Ref update fields: `v`, `kind=ref`, `author`, `handle`, `key_id`, `sign_pub`, `ref`, `object` (64 hex), `prev`, `seq`, `utc`, `hash`, `sig`.
11. Fetch request: `kind=fetch`, `from`, `key_id`, `sign_pub`, `object`, `utc`, `sig`. The response is a normal `msg` envelope whose plaintext is `{kind:object, object, content_b64}` inside ciphertext only.
12. NAT traversal is not implemented. Relay listen is 127.0.0.1 only. Cross-host neighborhood HTTP is not implemented; cluster URLs in tests are other loopback ports.

## Limits (plain)

- No anonymity. Handles and routing metadata are visible to relays.
- No forward secrecy.
- No NAT traversal and no cross-machine LAN HTTP. Neighborhood delivery
  here is loopback between instances, plus opt-in UDP that defaults to
  127.0.0.1.
- No Bluetooth mesh transport, no mDNS, no tested radio link.
- No hypervisor sandbox. Same-UID ptrace is out of scope.
- Replication is two copies, not a quorum. A single-homed message dies
  with its relay.
- Upstream ChainLock / TemporalLock acknowledgement is not claimed.
- Owner unattended seal is file permissions. Tenant passphrase seals
  are real scrypt seals; the OS user can still copy the ciphertext.
