# LAN-TWO-HOST-1.0 — two physical machines

**Author:** Aziel Eliab only
**Date:** 2026-10-24
**Status:** **planned** as an operator run. The software behind it is **partial**. This file is the procedure. It is not a result.
**Contract:** [PACKET-ADAPTER-1.0](PACKET-ADAPTER-1.0.md) · [THREAT-MODEL-1.0](THREAT-MODEL-1.0.md)
**License:** Apache-2.0

Phase 1 is **not done** until Aziel runs this on two independent
physical machines. CI cannot show that. A loopback session cannot
show that. The adapter keeps `live` false and `cross_host_proven`
false even after a real exchange. Those fields are not a stamp you
flip. The evidence is this procedure's receipts.

Do not bind `0.0.0.0`. Do not use the HTTP port 8891 for this. Do not
point the nodes at the same data directory. Do not call a relay.

## What you need

- Two machines on the same LAN. Different OS users are not enough if they share one kernel and one disk.
- This repo at the same commit on both. Record `git rev-parse HEAD`.
- Python 3.10+ and `pip install -e ".[dev]"`.
- Each machine's own data directory, empty at the start.
- An interface address you choose, for example `192.168.1.10` on A and `192.168.1.20` on B. Not `0.0.0.0`. Not a public address. Not `192.0.2.0/24` and not `198.18.0.0/15`.
- Linux for a non-loopback bind. The assigned-address check reads `/sys/class/net` and `SIOCGIFADDR`. macOS and Windows fail closed and can bind only with the explicit loopback opt-in, which is still not a two-host proof and still leaves `live` false.

The CLI is `python scripts/qns_lan.py`. It imports `qnm` before
`qnsd`. `python -m qnsd.lan` hits a pre-existing import cycle and is
not the entry point.

## Steps

1. **Distinct roots.** On each machine:

```bash
git rev-parse HEAD
python scripts/qns_lan.py --data-dir "$HOME/qns-lan" init
python scripts/qns_lan.py --data-dir "$HOME/qns-lan" show > "$HOME/qns-public.json"
```

`show` prints the public card, the certificate PEM, and the cert sha256.
It does not print the private key. Confirm the two handles differ.
Copy `qns-public.json` to the other machine (USB or an already trusted
channel). Record both handles, both `cert_sha256` values, and both
commit ids in your notes.

2. **Pin, then listen.** On B, bind only B's LAN address:

```bash
python scripts/qns_lan.py --data-dir "$HOME/qns-lan" peer-add \
  --card-file /path/to/a-public.json --address 192.168.1.10:9
python scripts/qns_lan.py --data-dir "$HOME/qns-lan" listen \
  --bind 192.168.1.20 --port 8894
```

The `9` on A's address is only the approved source host. The match is
the IP, not that port. On A:

```bash
python scripts/qns_lan.py --data-dir "$HOME/qns-lan" peer-add \
  --card-file /path/to/b-public.json --address 192.168.1.20:8894
```

3. **Small packet.** On A:

```bash
python scripts/qns_lan.py --data-dir "$HOME/qns-lan" send \
  --to 'HANDLE_OF_B' --text 'two-host-small'
python scripts/qns_lan.py --data-dir "$HOME/qns-lan" verify
```

On B, `verify` must say `"ok": true` and `"live": false`. Open the
one inbox file under `data/lan/inbox/` and check `packet_id` equals
the photon's `photon_id`, `payload_hash` matches the send result, and
the hop receipt's `prev` is 64 zeroes for the first receipt. `verify`
checks the receipt hash, the predecessor, and the signature.

4. **Larger than one fragment.** Stop B's listener. Start a sender
that uses a small fragment cap (the CLI default is 4096; a reviewer
can call `LanNode(..., max_fragment_bytes=300)` as
`tests/test_lan_transport.py` does) and send a payload over 300 bytes.
B's send log line `fragment_count` must be greater than 1. Inbox
bytes must match. Logs must not contain the payload text.

5. **Relay off.** On both machines, before the next send:

```bash
python - << 'PY'
import os
import qnm
from qnsd.lan.node import LanNode
node = LanNode(os.path.expanduser("~/qns-lan"), enabled=True)
assert node.relay_contacts == 0
assert node.relay_urls == ()
print({"relay_contacts": 0, "live": False})
PY
```

Send another small packet. It must still store. No relay URL is contacted.

6. **Disconnect, queue, restart.** Stop B's listener. On A, send two
texts. Both results are `temporary` / `QNS-LAN-UNAVAILABLE`. Stop the
A process. Start it again with the same `--data-dir`. Start B's
listener on the same address. On A:

```bash
python scripts/qns_lan.py --data-dir "$HOME/qns-lan" flush
```

Both results must be `ack_level` `stored` and `live` false. B's inbox
has both packet ids. Receipts still verify.

7. **Replay, reorder, tamper, duplicate, expire, fork.** Use the same
data roots. Expected outcomes, which CI already checks on loopback
and which this step repeats on the LAN:

| Case | Expected |
| --- | --- |
| Same payload again | `stored`, same `packet_id`, no second seq, no second inbox file |
| Second packet delivered before the first | `FED-GAP`, temporary, not stored. After the first is stored, the second stores |
| Earlier packet already sealed, then permanently refused | The later packet keeps that `prev`. Each attempt is `FED-GAP` (temporary) until the retry budget becomes `QNS-LAN-RETRY`. The first refusal does not drop the later packet, and it does not rewrite `prev` |
| Flipped signature | `QNS-LAN-REFUSED`, security, empty inbox |
| `expiry_utc` in the past, re-signed | `QNS-LAN-EXPIRED`, permanent, security |
| Same `packet_id`, different `payload_hash` | `QNS-LAN-FORK`, security |
| Peer pin revoked | `QNS-LAN-REVOKED`, security. No lower route |

8. **Export.** On each machine:

```bash
python scripts/qns_lan.py --data-dir "$HOME/qns-lan" verify > verify.json
sha256sum data/lan/receipts.jsonl data/lan/seq.jsonl verify.json
```

Run that from the data directory, or pass full paths. Copy `verify.json`
and the hashes into the notes. Confirm `"live": false` on every line.
Confirm the payload text is absent from `data/lan/log.jsonl` and from
`data/lan/receipts.jsonl`. Repeat from a clean checkout at the same
commit if you are the second reviewer.

## Optional pytest hook

On the sender, with B already listening and the peer file in place:

```bash
export QNS_LAN_TWO_HOST=1
export QNS_LAN_DATA="$HOME/qns-lan"
export QNS_LAN_PEER_FILE=/path/to/b-public.json
export QNS_LAN_PEER_ADDRESS=192.168.1.20:8894
python -m pytest -o addopts= -q tests/test_lan_two_host.py
```

Leave `QNS_LAN_TWO_HOST` unset in CI. The test skips. A pass still
does not set `live`.

## Not this procedure

BLE, NAT traversal, optical links, adaptive multipath, and RF bands
are out of this phase. Do not treat a green CI run as this procedure.
