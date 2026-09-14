# RADIO-PHY-1.0

Author: **Aziel Eliab** only.

LIVE OS radio bindings for local `qnm-node` / `qnsd`. Labels are
**LIVE | ABSENT | REFUSED**. No mock chatter. Fabric enable does not
invent PRESENT. `GET /v1/mesh` never enables radios. Plane C
attest-before-LIVE: a LIVE adapter fact is not a fielded suite-LIVE
claim.

## Bindings

| PHY | Tools | Packages | Permissions | Refuse |
| --- | --- | --- | --- | --- |
| Cellular LTE/5G | `mmcli -L` / `mmcli -m N` | `modemmanager` | `dialout`/`plugdev`; D-Bus `org.freedesktop.ModemManager1` | `RADIO-NO-MODEM` |
| Wi-Fi 2.4/5/6 GHz | sysfs wireless, `iw dev`, `nmcli` | `iw`, `network-manager` | `netdev` or `CAP_NET_ADMIN`; D-Bus NetworkManager | `RADIO-NO-WIFI` |
| Bluetooth | `/sys/class/bluetooth`, `bluetoothctl list` | `bluez` | `bluetooth` group; D-Bus `org.bluez` | `RADIO-NO-BT` |
| GNSS (RX only) | `gpspipe -w`, gpsd `127.0.0.1:2947` | `gpsd`, `gpsd-clients` | `dialout`; gpsd socket | `RADIO-NO-GNSS` / `RADIO-GNSS-RX-ONLY` |
| NFC | `nfc-list`, `pcsc_scan` | `libnfc-bin`, `pcscd`, `pcsc-tools` | `plugdev`; `pcscd` | `RADIO-NO-NFC` |

CI hosts without hardware must **PASS** the ABSENT / REFUSED path.
`HOOK-PENDING` is only for a binding that cannot compile/link. These
bindings are stdlib `subprocess` + sysfs.

## Law

- Never invent tower chatter, pairing, a GNSS fix, or an NFC tap.
- LIVE emit confirms the adapter (`transmitted=false`).
- Persist may use Wi-Fi/BT when LIVE; otherwise ABSENT.
- Bitmesh geo binds only from a LIVE GNSS fix.
- Architecture score ≠ fielded score. Hubs must not publish 100.
- AZ Generator is not called from qnm.

`GET /local/phy` and `GET /local/channels` expose the cards.
