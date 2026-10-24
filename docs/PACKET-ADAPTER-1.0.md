# PACKET-ADAPTER-1.0 — versioned packet and transport contract

**Author:** Aziel Eliab only
**Date:** 2026-10-24
**Software:** qnm-node
**Parents:** [QNS-CD-1.0](QNS-CD-1.0.md) · [FED-MESH-1.0](FED-MESH-1.0.md) · [FABRIC-MESH-PIPELINE-1.0](FABRIC-MESH-PIPELINE-1.0.md) · [RADIO-PHY-1.0](RADIO-PHY-1.0.md)
**Companion threat model:** [THREAT-MODEL-1.0](THREAT-MODEL-1.0.md)
**License:** Apache-2.0

This paper freezes the packet identity that already ships and specifies
the adapter contract the LAN transport must implement. It does not
change `photon_id`, `VIA_ORDER`, sequence rules, receipt hashes, or
identity derivation. It does not claim a route is live.

Runtime companion re-read on 2026-10-24:
`aziel-runtime` `docs/designs/FED-MESH-1.0.md` is on `main`. This
daemon does not edit that repo. It does not paint Worker L1 LIVE, does
not change FragGate, Cap-7 names, Softwares 42, or MCP 36, and does
not open the awareness socket on `0.0.0.0`.

## Status

| Piece | Status |
| --- | --- |
| `photon_id` (QNS1 1.3) | **implemented**, frozen |
| `VIA_ORDER` and the restriction walker | **implemented**, frozen |
| FED-MESH envelope signature and E2E cipher | **implemented**, frozen |
| Per-handle sequence (`classify_link`) | **implemented**, frozen |
| QNM chain hash and `receipt_digest` | **implemented**, frozen |
| Handle, `key_id`, `install_root`, `pair_id` | **implemented**, frozen |
| Lock-backed visible outbox | **implemented**. Not the QueueStore below |
| `PacketEnvelope`, `TransportAdapter`, `HopReceipt`, `DeliveryAck`, `QueueStore`, `PeerDirectory`, route planner | **partial**. `qnsd/lan` implements them for `lan-tls` only. The via walker is unchanged |
| Authenticated cross-host LAN (`lan-tls`) | **partial**. Opt-in TLS 1.3 listener, default off. Loopback tests pass. Two physical hosts have not been run. `live` stays false. Procedure: [LAN-TWO-HOST-1.0](LAN-TWO-HOST-1.0.md) |
| UDP discovery as a data path, BLE, NAT, optical, adaptive multipath, RF bands | **planned** or out of scope. Not this adapter |

A passing unit test is not a two-host delivery. `GET /v1/mesh` never
enables. No quantum-entanglement claim. QNS names the packet.

Phase 1 code lives in `qnsd/lan/`. The operator entry point is
`python scripts/qns_lan.py` (it imports `qnm` before `qnsd`).
`python -m qnsd.lan` still hits the pre-existing boot/vias import
cycle and is not a listen. The HTTP door is still `127.0.0.1` only.
This adapter does not set `live` from CI or from one machine.

## 1. Audit (code, not the older prose)

Checked against `main` at the Phase 0 freeze. Paths are the ones that
run.

### Packet identity — implemented

`qnsd/photon.py`. Magic `QNS1`, version `1.3`.

```
photon_id = SHA256(canonical({magic, ver, src, dst, pair_id, payload}))
```

Canonical JSON is UTF-8, sorted keys, separators `,` and `:`.
`PHOTON_ID_FIELDS` is exactly those six names. `via`, `via_in`,
`via_out`, `translate`, `hop`, `hop_max`, `seen`, `utc`, `author`,
and `spec` are hop-mutable or metadata. They must not enter
`photon_id`. `loads` refuses any other magic or version. `hop_max`
default is 8.

Golden (`payload` `{"label":"freeze","n":1}`, src `src-freeze`, dst
`dst-freeze`, pair `pair-freeze`):

`5e3369621394ca3b7c64f3f4034f9d53841a32aee6e99e18836e88b34838ca5e`

Pinned by `tests/test_contract_freeze.py`.

### VIA_ORDER — implemented

`qnsd/vias/base.py`:

```
lan, wifi, plc, bt, rf, gps, nfc, light, qns, operator, local
```

`qnsd/walker.py` `ViaStack.walk` advances on absent, fail, perm,
hook-pending, and refused when `force_via` is empty, inside one call.
`force_via` waits. It does not remap. That walker is a via-class
restriction. It is **not** the security router in §3. A refused OS
emit today still walks the next class. Do not change that walk to
"fix" it. Security refusals on the new router are a separate rule.

`qnsd/vias/lan.py` is software `PRESENT`. Emit returns `QNS-LAN-FAIL`
unless a link is declared. It does not send bytes. Declaring a link
is not a live mesh and is not cross-host delivery.

### Envelope signature — implemented

`qnm/fedmesh/wire.py`. Message version `FED-MESH-1.0`. Ed25519 over
`canonical(message_statement)` with `sig` removed. Signature and
public key are unpadded base64url. Relay-visible fields are
`MSG_FIELDS` plus `sig`. Extra fields are `FED-TAMPER`.

Body cipher, unchanged and not forward secret: ephemeral X25519,
HKDF-SHA256, salt `FED-MESH-1.0`, info
`FED-MESH-1.0|from|to|seq` (not sorted), AES-256-GCM, 12-byte nonce,
no additional data. Ciphertext cap `MAX_CT_BYTES` (65536).

`verify_statement` in `qnm/fedmesh/secwire.py` is locked to version
`FED-MESH-1.0` and author `Aziel Eliab`. New packet objects must not
be forced through that function. They reuse `canonical` and Ed25519.
They do not change it.

Pinned envelope (sign seed `0102…1f20`, box seed `4041…5f`, recipient
sign seed `21`×32, box seed `61`×32, ephemeral `71`×32, nonce
`81`×12, seq 1, prev 64 zeros, plaintext `{"kind":"note","text":"freeze"}`):
envelope id `afa667dde9be1843de142f04150481065af073ccbae5d425839d81ab7297e279`.
The full object is pinned in the freeze test.

### Sequence — implemented

Two sequences exist. Neither is rewritten by this contract.

1. QNM chain (`qnm/chain.py`): `seq = len + 1`, `prev` is the tip hash,
   genesis prev is 64 zeros. Hash covers `author, body, kind, prev,
   seq, spec, utc`.
2. Per-handle ledger (`qnm/fedmesh/chain.py` `classify_link`):
   - seq `< 1` → `FED-GAP`
   - same `(handle, seq)` and same hash → `FED-REPLAY`
   - same seq, other hash → `FED-FORK`
   - first link must be seq 1 and prev genesis, else `FED-GAP` or
     `FED-FORK`
   - next seq must be `tip + 1` and prev the tip hash, else `FED-FORK`
   - seq `> tip + 1` → `FED-GAP`
   - seq going backwards → `FED-FORK`

Relays still do not enforce gaps. Recipients do. Ordering is per
sender handle, not global.

### Receipt hashes — implemented

- Chain link hash: SHA-256 of the canonical core above.
- `qnm/nolie.py` `receipt_digest`: SHA-256 of the receipt **minus**
  `receipt_hash` and `identity_anchor`. Those two fields are attached
  after the digest. Older receipts still hash.
- Mesh anchor (`make_anchor`): version `FED-MESH-1.0-draft`, hash and
  Ed25519 over the core. `temporal.applied` is false unless an
  importable TemporalLock engine stamps. None is imported here.
- Identity anchor (`identity_anchor_statement`): version
  `FED-MESH-1.0`, fields `v, handle, public_key, seq, prev,
  receipt_hash`. No `key_id`. Vector receipt hash
  `49ef88c622177cd9662ea63d147589c9cea6c32adede83b7e7d127f853022dba`
  still verifies.

Public receipts stay free of user geo (`refuse_public_geo`). Private
keys and plaintext are not receipt fields.

### Identity — implemented

- `install_root = SHA256(entropy || nonce || optional_genesis)` with
  empty genesis as `b""` (`qnm/boot.py`). Two installs, two roots.
  Resume only from `data/locks/`.
- `pair_id = SHA256(root_A || root_B || nonce_A || nonce_B)` after
  lexicographic root order (`qnm/pairs.py`). Not Bell-pair physics.
- Handle: `#` plus 11 Crockford base32 characters (no I, L, O, U)
  from the high 55 bits of SHA-256 of the raw 32-byte Ed25519 public
  key (`handle_from_pubkey`).
- `key_id`: hex SHA-256 of that public key.
- Vector seed `0102…1f20` yields handle `#CPV0CWYPXP4` and key id
  `65b60673d6ed884bf01c2c222d82ada0740f29ac3355d6a925c81f17f47a27b8`.

Author identity remains the string `Aziel Eliab`. A handle is not
that author.

### Outbox and errors — implemented, partial against QueueStore

`qnsd/outbox.py` appends `visible.jsonl` and `data/locks/wait.jsonl`.
Restart reconciles from the lock file. `publish` and
`anon-broadcast-publish` raise `QNM-ANON-NO-PUBLISH`. A waited photon
keeps its `photon_id`. There is no expiry, backoff, retry budget, or
custody record. That gap is why QueueStore is specified separately.
Do not change the visible-outbox id formula.

Bind errors that already ship: `QNM-LOOPBACK-ONLY` (HTTP is
127.0.0.1; `0.0.0.0` and `::` refuse), `QNM-MESH-NEVER-ENABLES`,
`QNS-STICKY-VIA`, `QNS-HOP-MAX`, `QNS-LOOP-DROP`, `QNS-PAIR-CUT`,
`QNS-LAN-FAIL`, `QNS-VIA-ABSENT`, `QNS-HOOK-PENDING`, `RADIO-NO-*`,
`FED-REPLAY`, `FED-FORK`, `FED-GAP`, `FED-TAMPER`, `FED-WRONG-KEY`,
`FED-E2E`, `FED-QUOTA`. UDP discovery (`qnm/fedmesh/discover.py`) is
opt-in, magic `QNM1`, default bind 127.0.0.1, not mDNS, and not a
packet data path.

### What the docs got wrong

`docs/FED-MESH-1.0.md` said the runtime design was absent from
`aziel-runtime` `main`. On 2026-10-24 that file is on `main`. The
daemon draft in this repo is still the code that runs. The runtime
paper's awareness bind on `0.0.0.0` is not this process. This process
does not listen on `0.0.0.0`.

## 2. Frozen rules (normative)

Implementations of later phases must keep all of the following:

1. `photon_id` inputs and encoding stay `PHOTON_ID_FIELDS` and
   `canonical_bytes`. A new critical packet version is a new `ver`,
   refused by `loads` until a migration note lands. Do not silently
   accept it.
2. `VIA_ORDER` stays the eleven-name tuple. New transports are
   adapters beside the walker, not extra names inserted into it.
3. `classify_link` codes and the chain-link hash inputs stay as they
   are. A LAN ledger may **call** `classify_link`. It may not fork
   the function.
4. `receipt_digest` keeps skipping only `receipt_hash` and
   `identity_anchor`.
5. Handle, `key_id`, `install_root`, and `pair_id` formulas stay.
6. HTTP `qnm` and `qnsd serve` stay on 127.0.0.1 through
   `refuse_wan_bind`. A LAN listener is a different socket.
7. `live` is not a configuration flag and not an import probe.
   `LIVE` / `ABSENT` / `REFUSED` / `HOOK-PENDING` keep their current
   meanings for OS PHYs and camera/emitter. The LAN adapter in this
   version reports `live: false` even after a successful socket.
   Two physical machines are an operator procedure.
8. No mock radio, no simulated delivery success, no entanglement
   claim. Plaintext, private keys, passphrases, and location stay
   out of logs and receipts.

## 3. New objects (specified)

Version string for these objects: `QNS-PACKET-1.0`.
LAN session version: `QNS-LAN-1.0`.
Adapter id: `lan-tls`.

Unknown `v` on a packet, ack, receipt, fragment, or handshake is a
**permanent** refusal. Do not parse the body as a photon.

Signing for these objects: Ed25519 over `canonical(document without
sig)`, unpadded base64url. Include `author` = `Aziel Eliab`. Include
the signer's `public_key` (unpadded base64url) and `handle` where the
field list below says so. Reuse `qnm.fedmesh.wire.canonical`. Do not
invent a cipher. The payload cipher stays the FED-MESH body cipher.
The session cipher is TLS 1.3.

### PacketEnvelope

| Field | Rule |
| --- | --- |
| `v` | `QNS-PACKET-1.0` |
| `kind` | `packet` |
| `author` | `Aziel Eliab` |
| `packet_id` | equal to `photon_id` of the inner photon. Not a second hash |
| `src_handle`, `dst_handle` | FED-MESH handles |
| `created_utc`, `expiry_utc` | `YYYY-MM-DDTHH:MM:SSZ`. Metadata. Not causal order |
| `payload_hash` | hex SHA-256 of `canonical(photon.payload)` |
| `enc.alg` | `x25519-hkdf-sha256-aes-256-gcm` |
| `enc.session` | `tls1.3` |
| `body` | FED-MESH message envelope (`seal_envelope` output). Ciphertext, not plaintext |
| `public_key`, `sig` | sender Ed25519 |

`body` carries the photon dict as the sealed plaintext
`{"kind":"qns-photon","photon": <photon dict>}`. Hop-mutable photon
fields may change only by the existing translate rules. `packet_id`
does not. The inner envelope `seq` / `prev` obey `classify_link` on a
**LAN-local** ledger file. That ledger is not the QNM chain.

### TransportAdapter

Methods: `capabilities()`, `open()`, `send(frame)`, `receive()`,
`close()`, `health()`.

`capabilities()` and `health()` are measured facts. Required keys:

| Key | Rule |
| --- | --- |
| `adapter` | `lan-tls` for this adapter |
| `v` | `QNS-PACKET-1.0` |
| `presence` | `PRESENT` only while a socket this process opened is bound, or a session is up. Otherwise `ABSENT`. An import is not `PRESENT` |
| `live` | `false` in this version |
| `fielding` | `ABSENT` for the mesh-live claim |
| `hook_pending` | `false` (the socket can run; it is not a camera hook) |
| `authenticated_peer` | true only after the handshake in §4 verifies |
| `reachable` | true only after a measured handshake or a stored ack on this process |
| `loopback` | true when the bound or peer address is loopback |
| `cross_host_proven` | `false`. This process does not certify two physical machines |
| `mtu_bytes` | the configured fragment ceiling, from config, not from an example |
| `relay` | `false` |
| `nat_traversal` | `false` |
| `mock` | `false` |
| `simulated_success` | `false` |

Do not copy sample RTT, loss, or timestamps into production. Omit a
measurement that was not taken.

`send` returns an outcome:

| `outcome` | Meaning | Lower-priority route |
| --- | --- | --- |
| `absent` | listener off, peer not pinned, address not approved | not eligible. Skip. Do not invent success |
| `temporary` | timeout, TCP reset, peer down, retryable IO | may be tried |
| `refused` | security, identity, policy, bad signature, revocation, tamper, fork | **never** |
| `permanent` | expired, unknown critical version, over the hard cap, retry budget spent | **never** for this packet |
| `ok` | only together with ack level `stored` | stop, delivered |

`transport_accepted` may be true when TLS writes finished.
That is not delivery. Delivery is ack level `stored`.
`security: true` on identity, signature, policy, and malicious-payload
refusals. `live` on every result is false.

`code` values for the LAN adapter (new, beside the frozen codes):

`QNS-LAN-ABSENT`, `QNS-LAN-BIND`, `QNS-LAN-WAN`, `QNS-LAN-UNAVAILABLE`,
`QNS-LAN-TIMEOUT`, `QNS-LAN-REFUSED`, `QNS-LAN-IDENTITY`,
`QNS-LAN-REPLAY`, `QNS-LAN-FORK`, `QNS-LAN-REVOKED`, `QNS-LAN-EXPIRED`,
`QNS-LAN-CLOCK`, `QNS-LAN-QUOTA`, `QNS-LAN-MALFORMED`, `QNS-LAN-VERSION`,
`QNS-LAN-RETRY`.

`QNS-LAN-FAIL` stays the frozen via-walker code. Do not reuse it for
this socket.

### HopReceipt

Signed statement. One leaf per attempt or stored outcome. Append-only.

| Field | Rule |
| --- | --- |
| `v`, `kind` | `QNS-PACKET-1.0`, `hop-receipt` |
| `author`, `handle`, `public_key`, `sig` | signer of this hop |
| `packet_id`, `payload_hash` | the packet |
| `prev` | previous hop-receipt hash for this packet on this node, or 64 zeros |
| `from_handle`, `to_handle` | hop endpoints |
| `adapter` | `lan-tls` |
| `hop` | integer |
| `sent_utc` | sender clock, metadata |
| `received_utc` | optional, receiver clock, metadata |
| `outcome` | the outcome word |
| `hash` | hex SHA-256 of canonical receipt **without** `hash` and `sig` |

Forbidden in the receipt and in logs: `payload`, `plaintext`, `text`,
`content`, `password`, `passphrase`, private keys, seeds, raw address,
latitude, longitude, geohash. The hash does not cover a secret.

### DeliveryAck

Recipient-signed. Three levels, in order, each a separate statement:

| `level` | When it is true |
| --- | --- |
| `received` | the frame set parsed into one envelope. Not yet verified |
| `verified` | sender signature, handle binding, `photon_id == packet_id`, `payload_hash`, and the body cipher all checked |
| `stored` | the inbox file and the hop receipt were `fsync`ed |

Fields: `v`, `kind=delivery-ack`, `author`, `packet_id`,
`payload_hash`, `level`, `from_handle` (recipient), `to_handle`
(sender), `prev` (previous ack hash for this packet, or 64 zeros),
`public_key`, `sig`.

The sender marks the packet delivered only at `stored`. A second
`stored` for the same `packet_id` and `payload_hash` is the same
custody, not a second effect. The same `packet_id` with a different
`payload_hash` is `QNS-LAN-FORK` and closes the route.

### QueueStore

Crash-safe JSONL under the node data root, `fsync` on append and
rewrite. Idempotency key is `packet_id`.

Fields: `packet_id`, `payload_hash`, `created_utc`, `expiry_utc`,
`attempts`, `next_attempt_utc`, `state` (`queued`, `waiting`, `done`,
`expired`, `refused`), `last_outcome`, `last_code`, `nbytes`,
`custody` (`local` until a stored ack).

Bounds: 64 items, 1 MiB total. Over the bound, refuse the new append
(`QNS-LAN-QUOTA`) and do not delete other history. Expiry drops the
item from the ready set and does not rewrite receipts. Backoff is
exponential with jitter, base 1 second, cap 60 seconds, budget 8
attempts, then `permanent` / `QNS-LAN-RETRY`. Restart reloads the
file. Custody stays `local` until `stored`. Deletion of a done item's
queue row is allowed. Deletion of receipt history is not.

This store is not `qnsd/outbox.py`. The visible outbox stays as it is.

### PeerDirectory

Operator-pinned. Discovery does not write it.

| Field | Rule |
| --- | --- |
| `handle`, `sign_pub`, `box_pub` | pinned identity. `sign_pub` is standard base64 as on the key card |
| `cert_pem`, `cert_sha256` | pinned TLS certificate |
| `addresses` | `ip:port` only. No hostname in this version |
| `adapters` | includes `lan-tls` |
| `key_status` | `active` or `revoked` |
| `last_success_utc` | set only after a stored ack |
| `revocation` | null, or `{utc, reason}` |

No private key. An unknown handle is refused. There is no
trust-on-first-use. Revocation stops new sessions and does not rewrite
old receipts. Historical signatures still verify against the archived
public key.

### Routing states

```
DISCOVERED → AUTHENTICATED → ELIGIBLE → ATTEMPTED → ACKNOWLEDGED
```

- `DISCOVERED` is an operator pin, not a UDP sighting. UDP discovery
  stays unauthorized.
- `AUTHENTICATED` is the handshake in §4.
- `ELIGIBLE` means policy allows `lan-tls`, the key is active, the
  address is approved, and the packet is inside expiry (skew below).
- `ATTEMPTED` is a send that has not reached `stored`.
- `ACKNOWLEDGED` is a `stored` ack.

Unavailable stays unavailable. A temporary failure may retry and may
try a lower-priority **registered** adapter. A security, identity, or
policy refusal must not. Phase 1 production registers `lan-tls` only,
so a temporary failure queues. It does not call a relay. A relay
adapter is not part of this version.

Clock skew allowance for expiry and for `created_utc` in the future
is 120 seconds. Outside that window the packet is `QNS-LAN-EXPIRED`
or `QNS-LAN-CLOCK` and is permanent. Sequence and `prev` remain the
causal order. Timestamps are not.

## 4. LAN session (specified)

Listener default **off**. Bind only an operator-selected address that
is assigned to a local interface.

Refuse, and do not listen:

- `0.0.0.0`, `::`, empty, unspecified, multicast
- public and CGNAT addresses (`QNS-LAN-WAN`)
- an address that is not configured on a local interface (`QNS-LAN-BIND`)
- loopback, unless the operator sets an explicit loopback opt-in

Loopback opt-in is for a single-host procedure. It sets `loopback:
true` and still `live: false`. It is not cross-host proof.

The existing HTTP API is unchanged and stays loopback-only.

Handshake, after mutual TLS 1.3 (`CERT_REQUIRED`, TLS 1.3 only,
pinned peer certificate as the trust anchor, hostname check off
because the pin is the certificate fingerprint):

1. Initiator hello: `v=QNS-LAN-1.0`, `kind=hello`, both handles,
   initiator nonce (32 bytes, hex), initiator cert SHA-256, signer's
   `public_key`, `author`, `sig` over that hello.
2. Responder checks the pin, the cert fingerprint against the TLS peer
   cert, the handle against the key, nonce freshness, revocation, and
   the approved source address. It answers with its nonce and a
   signature over the transcript below.
3. Initiator returns `kind=confirm` with its signature over the same
   transcript.
4. The session is `AUTHENTICATED` only after step 3 verifies.

Transcript (both sides sign these exact fields):

```
v, kind=handshake-transcript, protocol=QNS-LAN-1.0, author,
initiator_handle, responder_handle,
initiator_nonce, responder_nonce,
initiator_cert_sha256, responder_cert_sha256
```

Nonces are remembered (cap 1024). A repeated initiator nonce is
`QNS-LAN-REPLAY`. This build's Python `ssl` module has no
`export_keying_material`. The transcript does not pretend an exporter
exists. Certificate pin plus both nonces plus both identities plus the
protocol version is the binding. A later build may add the exporter
as an extra field under a version bump.

Frames: 4-byte big-endian length, then UTF-8 JSON. Length must be
1..65536. A length outside that range closes the socket and does not
read the body. One JSON object. Handshake timeout 5 seconds. Read
timeout 10 seconds.

Fragments, when the canonical envelope exceeds `max_fragment_bytes`
(default 4096, config floor 256, ceiling 16384): `kind=fragment`,
`index`, `count` (1..32), `total`, `sha256` of the raw piece,
`body_b64` (standard base64 of that piece), `packet_id`,
`payload_hash`, `sig`. Reassembly timeout 30 seconds. Duplicate index
with the same hash is a no-op. A different hash is a fork refusal.
Reassembly then parses one PacketEnvelope.

Quotas, per authenticated peer unless noted: 4 connections per source
address, 30 messages per 60 seconds, 8 in flight, queue bounds above,
reassembly cap 262144 bytes. Excess is `QNS-LAN-QUOTA` and closes.
Quotas do not delete receipt history.

Inner envelope sequence advances only after the previous packet for
that sender is `stored` or permanently refused. A gap is `FED-GAP`
and is not stored. At-least-once plus idempotent `packet_id`. Not
exactly-once. Not a global order.

Relay URLs are not read and not contacted. `upstream` flags on the
HTTP daemon are not an enable switch for this socket.

## 5. Tests that freeze the contract

`tests/test_contract_freeze.py` pins the goldens in §1. It does not
open a LAN socket and does not change runtime behavior. Existing
`tests/test_qnsd.py` remains the walker law.

## Cite

Eliab, Aziel. (2026). PACKET-ADAPTER-1.0
[Software]. Apache-2.0. https://github.com/AzielEliab/qnm-node

Apache-2.0. Forks are welcome and always allowed.
