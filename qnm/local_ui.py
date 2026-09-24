"""Local operator HTML on the existing loopback door.

Machine clients keep application/json. A browser Accept that prefers
text/html gets a calm status page. Nothing here enables mesh, radios,
or fabric. No second listen. No secrets in the page.

Author: Aziel Eliab only.
"""

from __future__ import annotations

from html import escape
from typing import Any

HTML_DASHBOARD_ROUTES = frozenset({"/local", "/local/ui"})

HTML_SECURITY_HEADERS = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; script-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
    ("Cache-Control", "no-store"),
)

_EMPTY_TIP = "0" * 64

_STATE_PLAIN = {
    "COLD": "This process has not booted an install yet.",
    "LOCAL": "Installed on this machine. The operator bearer is off.",
    "LIVE": "The operator bearer is on.",
    "DEGRADED": "The operator bearer was dropped. The state does not step backward on its own.",
    "ISOLATED": "Tamper isolation is on. Pair edges are cut.",
    "PHOENIX_LOCK": "Waiting on this machine after poison or isolation.",
    "SCORCHED": "This install is scorched. It stays scorched.",
}

_BEARER_ORDER = ("local", "operator", "lan", "wifi", "bt", "radio", "remote")
_BEARER_NAMES = {
    "local": "Local",
    "operator": "Operator",
    "lan": "LAN",
    "wifi": "Wi-Fi",
    "bt": "Bluetooth",
    "radio": "Radio",
    "remote": "Remote",
}

_CHANNEL_NAMES = {
    "lan": "LAN",
    "wifi": "Wi-Fi",
    "plc": "Power line",
    "bt": "Bluetooth",
    "rf": "Cellular",
    "cellular": "Cellular",
    "gps": "GNSS",
    "nfc": "NFC",
    "light": "Light",
    "qns": "QNS",
    "operator": "Operator",
    "local": "Local",
    "photon": "Photon",
}

_FIELDING_PLAIN = {
    "REAL": "software is present",
    "LIVE": "an adapter is present",
    "ABSENT": "no adapter on this machine",
    "REFUSED": "emit refused",
    "OFF": "software path is off",
    "HOOK-PENDING": "hook pending",
}

_REFUSE_PLAIN = {
    "QNM-LOOPBACK-ONLY": "This door listens on 127.0.0.1. That path or bind was refused.",
    "QNM-NO-PLAINTEXT-REMOTE": "Remote plaintext was refused.",
    "QNM-AUTH": "The operator token did not match.",
    "QNM-MESH-NEVER-ENABLES": "This mesh read leaves radios and mesh off.",
    "QNM-RADIO-OFF": "Radio, Wi-Fi, and Bluetooth bearers stay off until the fabric software path is enabled.",
    "QNM-BEARER-OFF": "That bearer change was refused.",
    "QNM-STATE-LOCKED": "The node is not in a state that accepts this action.",
    "QNM-SCORCHED": "This install is scorched.",
    "QNM-NO-ACCOUNT": "A scorched lock stays scorched. There is no account to resume.",
    "QNM-NO-AUTO-HEAL": "The node does not change state on its own for this request.",
    "QNM-NO-LIVE-FROM-PING": "A site ping leaves the state where it is.",
    "QNM-NO-REWRITE": "Receipts and the published tip stay append-only.",
    "QNM-NO-REWRITE-KEY": "There is no rewrite key.",
    "QNM-NO-LIE-TO-LIVE": "The node will not report a false state to stay up.",
    "QNM-VERIFY-WITHOUT-VOICE": "Verify runs without a voice confirmation.",
    "QNM-NO-ONE-TUNNEL": "Copies stay off a single tunnel.",
    "QNM-APG-POISON": "The payload was refused before it was interpreted.",
    "QNM-SCORE-NO-VIEWS": "Views are not an input here.",
    "QNM-ANON-NO-PUBLISH": "The outbox is a local queue.",
    "QNM-OUTBOX-CUT": "That outbox id is not in the queue.",
    "QNM-COLD-MISSING": "The cold copy this action needs is not on disk.",
    "QNM-COLD-NAMED-HOSTS": "Cold copies use named hosts.",
    "QNM-COLD-NO-VPN": "VPN concealment is refused.",
    "QNM-COLD-PIN": "Only an already-public tip or receipt hash can be pinned.",
    "QNM-TAMPER-ISOLATE": "Tamper isolation refused that transition.",
    "QNM-RESUME-LOCK-ONLY": "A lock is already on disk. Resume that lock.",
    "QNM-SURVIVE-OFFLINE": "Local verify and append stay available offline.",
    "QNM-WIRES-FAIL-CLOSED": "The wire check failed closed.",
    "QNM-WIRES-TICK-SIZE": "A tick is fixed-size.",
    "QNM-WIRES-TICK-PLANE": "The tick plane carries presence and a tip hash.",
    "QNM-WIRES-PULL-ONLY": "Payload is pulled.",
    "QNM-WIRES-TWO-CLOCKS": "Tick and dwell use separate sockets.",
    "QNM-WIRES-THREE-CLOCKS": "The claim clock stays off the local tick and dwell sockets.",
    "QNM-WIRES-CLOCK-DESYNC": "A clock desync is not a yes.",
    "QNM-WIRES-DWELL-CITE": "Dwell follows a valid cite.",
    "QNM-WIRES-AMBIGUOUS": "An ambiguous tip does not merge.",
    "QNM-WIRES-EQUIVOCATION": "That peer is already locked.",
    "QNM-WIRES-HASH-ABSOLUTE": "The cite has to be hash-absolute.",
    "QNM-WIRES-EMIT-LAST": "A tip is announced after local verify.",
    "QNM-WIRES-NO-UNSEND": "There is no unsend.",
    "QNM-WIRES-NO-SPLICE": "A split does not splice itself back together.",
    "QNM-WIRES-REJOIN-CITE": "Rejoin needs a cite.",
    "QNM-WIRES-HEARTBEAT": "A missed heartbeat is not poison and not an apply.",
    "QNM-PHOENIX-LOCAL-WAIT": "Phoenix waits on this machine.",
    "QNM-NO-AZ-GENERATOR": "AZ Generator is not called from this process.",
    "QNM-NO-NODE-GATE": "Node Gate is outside this process.",
    "QNM-NO-QNSD-PROXY": "This process does not proxy qnsd.",
    "QNM-NO-PUBLIC-GEO": "Public receipts stay without a position.",
    "QNM-BITMESH-GEO": "That position is out of range.",
    "QNM-SHELF-NO-KEY": "No shelf key is set in the environment.",
    "QNM-TIP-UNSIGNED": "An unsigned tip restore was refused.",
    "QNM-ARCHIVE-BYTES": "That archive action is unknown.",
    "QNM-TETHER-CLEAN": "The tether was refused.",
    "QNM-RECEIPT-HASH": "A receipt hash did not verify.",
    "AIH-HANDSHAKE": "The pair handshake was refused.",
    "AIH-NO-EDGES": "There is no pair edge for that hop.",
    "AIH-PAIR-CUT": "That pair is not in this memorial.",
    "AIH-NOT-BELL": "The pair-id is a hash of the two roots and nonces.",
    "FED-ROLE": "This role cannot call that path.",
    "FED-POLICY": "Policy refused this request.",
    "FED-PROFILE": "That profile name was refused.",
    "FED-TOR-OFF": "Tor transport is off.",
    "FED-TOR-ABSENT": "The Tor proxy is not available for this send.",
    "FED-QUOTA": "The quota refused this request.",
    "FED-NO-ROUTE": "No route was available.",
    "FED-SLOT": "That design slot was refused.",
    "FED-TAMPER": "The statement was refused.",
    "FED-PASSPHRASE": "Design mode needs a fresh challenge.",
    "FED-WRONG-KEY": "The unlock key does not match the handle.",
    "FED-FETCH": "That object is not in the airlock.",
    "FG-GATE-REFUSE": "The gate refused this request.",
    "QNS-HOP-MAX": "The hop limit dropped the frame.",
    "QNS-LOOP-DROP": "The frame was already seen on this walk.",
    "QNS-STICKY-VIA": "A sticky via was refused.",
    "QNS-VIA-SANITIZE": "That via field was refused.",
    "QNS-RADIO-NOT-LIVE": "Emit needs a live adapter.",
    "QNS-HOOK-PENDING": "That hook is pending.",
}


def prefers_html(accept: str | None) -> bool:
    """True only when text/html outranks application/json.

    A missing Accept, ``*/*``, or a tie stays JSON so machine clients
    keep the existing body.
    """
    html_q = _effective_q(accept, "text/html")
    json_q = _effective_q(accept, "application/json")
    if html_q is None:
        return False
    if json_q is None:
        return html_q > 0
    return html_q > json_q


def explain_refuse(code: str, detail: str = "") -> str:
    """Plain words for a QNMRefuse code. Unknown codes use the detail."""
    gloss = _REFUSE_PLAIN.get(str(code or "").strip(), "")
    extra = str(detail or "").strip()
    if gloss and extra and extra.lower() not in gloss.lower():
        return f"{gloss} {extra}"
    if gloss:
        return gloss
    if extra:
        return extra
    return "The door refused this request."


def render_dashboard(node: Any, local_url: str = "") -> str:
    """Read-only status page. Does not boot, enable, or write."""
    snap = node.snapshot()
    receipts = list(node.receipts())
    return _page(
        title="Local node",
        heading="Local node",
        active="/local/ui",
        body=_dashboard_body(snap, receipts),
        author=str(snap.get("author") or ""),
        spec=str(snap.get("spec") or ""),
        local_url=local_url,
        intro="This page reads the local node on this machine.",
    )


def render_response(
    route: str,
    code: int,
    payload: dict[str, Any],
    node: Any | None = None,
    local_url: str = "",
) -> str:
    """Human page for one door response. JSON payload is not rewritten."""
    body = payload if isinstance(payload, dict) else {}
    if body.get("refused") is True or (code >= 400 and body.get("code")):
        return render_refusal(body, route=route, local_url=local_url)
    path = route or ""
    if path in HTML_DASHBOARD_ROUTES or path == "/local/state":
        if node is not None:
            return render_dashboard(node, local_url=local_url)
        return _page(
            title="Local node",
            heading="Local node",
            active="/local/ui",
            body=_dashboard_body(body, []),
            author=str(body.get("author") or ""),
            spec=str(body.get("spec") or ""),
            local_url=local_url,
            intro="This page reads the local node on this machine.",
        )
    if path == "/local/receipts":
        rows = body.get("receipts") if isinstance(body.get("receipts"), list) else []
        return _page(
            title="Receipts",
            heading="Receipts",
            active=path,
            body=_receipts_body(rows),
            author=str(body.get("author") or ""),
            spec=str(body.get("spec") or ""),
            local_url=local_url,
        )
    if path in ("/local/fabric", "/local/channels"):
        heading = "Channels" if path == "/local/channels" else "Fabric"
        return _page(
            title=heading,
            heading=heading,
            active=path,
            body=_fabric_body(body),
            author=str(body.get("author") or ""),
            spec=str(body.get("spec") or ""),
            local_url=local_url,
        )
    if path == "/local/phy":
        return _page(
            title="Radios",
            heading="Radios",
            active=path,
            body=_phy_body(body),
            author=str(body.get("author") or ""),
            spec=str(body.get("spec") or ""),
            local_url=local_url,
        )
    if path == "/local/outbox":
        items = body.get("outbox") if isinstance(body.get("outbox"), list) else []
        return _page(
            title="Outbox",
            heading="Outbox",
            active=path,
            body=_outbox_body(items),
            author="",
            spec="",
            local_url=local_url,
        )
    if path == "/local/pairs":
        items = body.get("pairs") if isinstance(body.get("pairs"), list) else []
        return _page(
            title="Pairs",
            heading="Pairs",
            active=path,
            body=_pairs_body(items),
            author=str(body.get("author") or ""),
            spec=str(body.get("spec") or ""),
            local_url=local_url,
        )
    return _page(
        title="Local status",
        heading=_heading_for(path),
        active=path,
        body=_focused_body(path, body),
        author=str(body.get("author") or ""),
        spec=str(body.get("spec") or ""),
        local_url=local_url,
    )


def render_refusal(payload: dict[str, Any], route: str = "", local_url: str = "") -> str:
    code = str(payload.get("code") or "")
    detail = str(payload.get("detail") or "")
    reason = explain_refuse(code, detail)
    inner = (
        f"<p class=\"code\">{_esc(code or 'refused')}</p>"
        f"<p class=\"lead\">{_esc(reason)}</p>"
    )
    if route:
        inner += f"<p class=\"quiet\">{_esc(route)}</p>"
    return _page(
        title="Refused",
        heading="Refused",
        active="",
        body=inner,
        author=str(payload.get("author") or ""),
        spec=str(payload.get("spec") or ""),
        local_url=local_url,
    )


def _effective_q(accept: str | None, media: str) -> float | None:
    if accept is None or not str(accept).strip():
        return None
    want_type, want_sub = media.lower().split("/", 1)
    best_q: float | None = None
    best_spec = -1
    for part in str(accept).split(","):
        bits = [bit.strip() for bit in part.split(";") if bit.strip()]
        if not bits or "/" not in bits[0]:
            continue
        mime = bits[0].lower()
        q = 1.0
        for param in bits[1:]:
            if param.lower().startswith("q="):
                try:
                    q = float(param.split("=", 1)[1])
                except ValueError:
                    q = 0.0
        got_type, got_sub = mime.split("/", 1)
        spec = -1
        if got_type == want_type and got_sub == want_sub:
            spec = 3
        elif got_type == want_type and got_sub == "*":
            spec = 2
        elif got_type == "*" and got_sub == "*":
            spec = 1
        if spec < 0:
            continue
        if spec > best_spec or (spec == best_spec and (best_q is None or q > best_q)):
            best_spec = spec
            best_q = q
    return best_q


def _esc(value: Any) -> str:
    return escape(str(value), quote=True)


def _on_off(flag: Any) -> str:
    return "On" if flag else "Off"


def _is_empty_tip(tip: Any) -> bool:
    text = str(tip or "").strip().lower()
    return text == "" or text == _EMPTY_TIP


def _bearer_name(name: str) -> str:
    return _BEARER_NAMES.get(name, name.replace("_", " ").strip().title() or name)


def _channel_name(name: str) -> str:
    return _CHANNEL_NAMES.get(name, name.replace("_", " ").strip().title() or name)


def _fielding_words(label: Any) -> str:
    text = str(label or "").strip()
    if not text:
        return "no stamp"
    gloss = _FIELDING_PLAIN.get(text)
    if gloss:
        return f"{text} · {gloss}"
    return text


def _rows(items: list[tuple[str, str]]) -> str:
    if not items:
        return "<p class=\"empty\">Nothing further to show.</p>"
    lines = ["<ul>"]
    for label, value in items:
        lines.append(
            f"<li><span>{_esc(label)}</span><span class=\"meta\">{_esc(value)}</span></li>"
        )
    lines.append("</ul>")
    return "".join(lines)


def _empty(text: str) -> str:
    return f"<p class=\"empty\">{_esc(text)}</p>"


def _section(title: str, inner: str) -> str:
    return f"<section><h2>{_esc(title)}</h2>{inner}</section>"


def _dashboard_body(snap: dict[str, Any], receipts: list[dict[str, Any]]) -> str:
    state = str(snap.get("state") or "")
    sentence = _STATE_PLAIN.get(state, f"Recorded state is {state}." if state else "No state recorded.")
    install = str(snap.get("install_root") or "").strip()
    bearers = snap.get("bearers") if isinstance(snap.get("bearers"), dict) else {}
    chain = snap.get("chain") if isinstance(snap.get("chain"), dict) else {}
    fabric = snap.get("fabric") if isinstance(snap.get("fabric"), dict) else {}
    channels = snap.get("channels") if isinstance(snap.get("channels"), dict) else {}
    handle = str(snap.get("mesh_handle") or "").strip()
    state_rows: list[tuple[str, str]] = [("State", state or "unknown")]
    if handle:
        state_rows.append(("Handle", handle))
    state_rows.append(("Bind", str(snap.get("bind") or "127.0.0.1")))
    parts = [
        f"<p class=\"state\">{_esc(state or 'unknown')}</p>",
        f"<p class=\"lead\">{_esc(sentence)}</p>",
    ]
    if not install:
        parts.append(_section("Boot", _empty("No install yet.")))
    parts.append(_section("Status", _rows(state_rows)))
    parts.append(_section("Receipts", _receipt_summary(chain, receipts)))
    parts.append(_section("Fabric", _fabric_lead(fabric)))
    parts.append(_advanced_overview(snap, receipts, bearers, chain, channels))
    return "".join(parts)


def _receipt_summary(chain: dict[str, Any], receipts: list[dict[str, Any]]) -> str:
    length = int(chain.get("length") or 0)
    tip = chain.get("tip")
    parts: list[str] = []
    if length <= 0 or _is_empty_tip(tip):
        parts.append(_empty("No receipt tip yet."))
    else:
        verify = "passed" if chain.get("ok") else "did not pass"
        parts.append(_rows([("Chain length", str(length)), ("Chain verify", verify)]))
    if not receipts:
        parts.append(_empty("No receipts on disk yet."))
    else:
        last = receipts[-1] if isinstance(receipts[-1], dict) else {}
        parts.append(
            _rows(
                [
                    ("Receipts on disk", str(len(receipts))),
                    ("Latest", str(last.get("kind") or "receipt")),
                ]
            )
        )
    return "".join(parts)


def _fabric_lead(fabric: dict[str, Any]) -> str:
    enabled = bool(fabric.get("enabled"))
    if enabled:
        lead = "The fabric software path is on. OS radio stamps come from adapters on this machine."
    else:
        lead = "The fabric software path is off."
    return f"<p class=\"lead\">{_esc(lead)}</p>{_rows([('Software path', _on_off(enabled))])}"


def _advanced_overview(
    snap: dict[str, Any],
    receipts: list[dict[str, Any]],
    bearers: dict[str, Any],
    chain: dict[str, Any],
    channels: dict[str, Any],
) -> str:
    blocks: list[str] = []
    hash_rows: list[tuple[str, str]] = []
    install = str(snap.get("install_root") or "").strip()
    if install:
        hash_rows.append(("Install root", install))
    length = int(chain.get("length") or 0)
    tip = chain.get("tip")
    if length > 0 and not _is_empty_tip(tip):
        hash_rows.append(("Receipt tip", str(tip)))
    if receipts and isinstance(receipts[-1], dict):
        last = receipts[-1]
        digest = str(last.get("hash") or last.get("receipt_hash") or "").strip()
        if digest:
            hash_rows.append(("Latest hash", digest))
    if hash_rows:
        blocks.append(_section("Hashes", _rows(hash_rows)))
    blocks.append(_section("Bearers", _bearers_body(bearers)))
    radios = str(snap.get("radios_status") or "").strip()
    radio_bits = []
    if radios:
        radio_bits.append(_rows([("Radios", _fielding_words(radios))]))
    radio_bits.append(_channel_rows(channels))
    blocks.append(_section("Radios and channels", "".join(radio_bits)))
    return _details("Advanced", "".join(blocks))


def _details(summary: str, inner: str) -> str:
    if not str(inner or "").strip():
        return ""
    return f"<details><summary>{_esc(summary)}</summary>{inner}</details>"


def _bearers_body(bearers: dict[str, Any]) -> str:
    if not bearers:
        return _empty("No bearers are recorded.")
    ordered = [name for name in _BEARER_ORDER if name in bearers]
    ordered.extend(sorted(name for name in bearers if name not in ordered))
    rows = [(_bearer_name(name), _on_off(bearers.get(name))) for name in ordered]
    return _rows(rows)


def _receipts_body(receipts: list[Any]) -> str:
    rows = [row for row in receipts if isinstance(row, dict)]
    if not rows:
        return _section("On disk", _empty("No receipts on disk yet."))
    shown = rows[-20:]
    items = []
    for row in reversed(shown):
        kind = str(row.get("kind") or "receipt")
        seq = row.get("seq")
        digest = str(row.get("hash") or row.get("receipt_hash") or "")
        label = f"{kind}" if seq is None else f"{kind} · {seq}"
        items.append((label, digest or "hash missing"))
    note = ""
    if len(rows) > len(shown):
        note = f"<p class=\"quiet\">Showing the latest {len(shown)} of {len(rows)}.</p>"
    return note + _section("On disk", _rows(items))


def _fabric_section(fabric: dict[str, Any], channels: dict[str, Any], snap: dict[str, Any]) -> str:
    enabled = bool(fabric.get("enabled"))
    if enabled:
        lead = "The fabric software path is on. OS radio stamps come from adapters on this machine."
    else:
        lead = "The fabric software path is off."
    radios = str(snap.get("radios_status") or fabric.get("radios_status") or "").strip()
    rows: list[tuple[str, str]] = [("Software path", _on_off(enabled))]
    if radios:
        rows.append(("Radios", _fielding_words(radios)))
    channel_html = _channel_rows(channels)
    return f"<p class=\"lead\">{_esc(lead)}</p>{_rows(rows)}{channel_html}"


def _channel_rows(channels: dict[str, Any]) -> str:
    raw = channels.get("channels")
    rows: list[tuple[str, str]] = []
    if isinstance(raw, list):
        for row in raw:
            if not isinstance(row, dict):
                continue
            name = str(row.get("name") or "")
            if not name:
                continue
            rows.append((_channel_name(name), _fielding_words(row.get("fielding"))))
    elif isinstance(channels.get("labels"), dict):
        for name, label in channels["labels"].items():
            rows.append((_channel_name(str(name)), _fielding_words(label)))
    photon = channels.get("photon")
    if not any(label == "Photon" for label, _value in rows):
        if isinstance(photon, dict):
            rows.append(("Photon", _fielding_words(photon.get("fielding") or "REAL")))
        elif isinstance(photon, str) and photon.strip():
            rows.append(("Photon", _fielding_words(photon)))
    if not rows:
        return _empty("No channel stamp yet.")
    return _rows(rows)


def _fabric_body(payload: dict[str, Any]) -> str:
    enabled = payload.get("enabled")
    if "channels" in payload and isinstance(payload.get("channels"), list):
        channels = payload
        fabric = {"enabled": enabled if enabled is not None else payload.get("all_channels_on")}
    else:
        fabric = payload
        channels = {
            "channels": payload.get("channels") if isinstance(payload.get("channels"), list) else [],
            "labels": payload.get("channel_labels") or payload.get("labels") or {},
            "photon": payload.get("photon") if isinstance(payload.get("photon"), dict) else {},
        }
        if isinstance(payload.get("os_phy"), dict) and not channels["channels"]:
            channels = {"labels": payload.get("os_phy"), "channels": []}
    snap = {
        "radios_status": payload.get("radios_status") or "",
    }
    if not snap["radios_status"] and isinstance(payload.get("radios"), str):
        snap["radios_status"] = payload.get("radios")
    return _fabric_section(fabric if isinstance(fabric, dict) else {}, channels, snap)


def _phy_body(payload: dict[str, Any]) -> str:
    radios = payload.get("radios") if isinstance(payload.get("radios"), dict) else {}
    live = payload.get("live") if isinstance(payload.get("live"), list) else []
    if not radios:
        return _empty("No radio probe yet.")
    if not live:
        lead = "<p class=\"lead\">No radio adapter is marked live on this machine.</p>"
    else:
        lead = "<p class=\"lead\">At least one adapter is marked live on this machine.</p>"
    rows = []
    for name, card in radios.items():
        if isinstance(card, dict):
            rows.append((_channel_name(str(name)), _fielding_words(card.get("label"))))
        else:
            rows.append((_channel_name(str(name)), _fielding_words(card)))
    return lead + _rows(rows)


def _outbox_body(items: list[Any]) -> str:
    rows = [row for row in items if isinstance(row, dict)]
    if not rows:
        return _empty("The outbox is empty.")
    pairs = []
    for row in rows[:20]:
        kind = str(row.get("kind") or "item")
        item_id = str(row.get("id") or "")
        pairs.append((kind, item_id or "queued"))
    note = ""
    if len(rows) > 20:
        note = f"<p class=\"quiet\">Showing 20 of {len(rows)}.</p>"
    return note + _rows(pairs)


def _pairs_body(items: list[Any]) -> str:
    rows = [row for row in items if isinstance(row, dict)]
    if not rows:
        return _empty("No living pair-ids in this memorial.")
    pairs = []
    for row in rows[:20]:
        phase = str(row.get("phase") or "pair")
        pair_id = str(row.get("pair_id") or "")
        pairs.append((phase, pair_id or "recorded"))
    note = ""
    if len(rows) > 20:
        note = f"<p class=\"quiet\">Showing 20 of {len(rows)}.</p>"
    return note + _rows(pairs)


def _heading_for(route: str) -> str:
    names = {
        "/local/wires": "Wires",
        "/local/vault": "Cold copies",
        "/local/nolie": "Receipts law",
        "/local/bitmesh": "Bitmesh",
        "/local/planes": "Planes",
        "/local/surface": "Door",
        "/local/redline": "Redline",
        "/local/fedmesh": "Local mesh",
        "/local/design": "Design",
        "/local/unkillability": "Copies",
    }
    return names.get(route, "Local status")


def _focused_body(route: str, payload: dict[str, Any]) -> str:
    if route == "/local/wires":
        planes = payload.get("planes") if isinstance(payload.get("planes"), dict) else {}
        rows = []
        if "tick" in planes:
            rows.append(("Tick plane", "presence and tip hash"))
        if "payload" in planes:
            rows.append(("Payload plane", "pull"))
        if not rows:
            return _empty("No wire status yet.")
        return _rows(rows)
    if route == "/local/vault":
        objects = int(payload.get("objects") or 0)
        replicas = int(payload.get("replicas") or 0)
        if objects == 0 and replicas == 0:
            return _empty("No cold objects yet.")
        return _rows([("Cold objects", str(objects)), ("Replicas", str(replicas))])
    if route == "/local/nolie":
        published = payload.get("published") if isinstance(payload.get("published"), list) else []
        if not published:
            return _empty("No published tip yet.")
        return _rows([("Published tips", str(len(published))), ("Latest", str(published[-1]))])
    if route == "/local/bitmesh":
        binds = int(payload.get("binds") or 0)
        fielding = str(payload.get("fielding") or payload.get("channel") or "")
        if binds == 0:
            lead = _empty("No internal binds yet.")
        else:
            lead = _rows([("Binds", str(binds))])
        if fielding:
            return lead + _rows([("GNSS stamp", _fielding_words(fielding))])
        return lead
    if route == "/local/fedmesh":
        seq = int(payload.get("receipt_seq") or 0)
        rows = [
            ("Relay listen", _on_off(payload.get("relay_listen"))),
            ("Direct inbox", _on_off(payload.get("direct_inbox"))),
            ("LAN discovery", _on_off(payload.get("lan_discovery"))),
            ("Edge compute", _on_off(payload.get("edge_compute"))),
        ]
        handle = str(payload.get("handle") or "").strip()
        if handle:
            rows.insert(0, ("Handle", handle))
        tip = payload.get("receipt_tip")
        if seq > 0 and not _is_empty_tip(tip):
            rows.append(("Receipt tip", str(tip)))
        else:
            return _rows(rows) + _empty("No mesh receipt tip yet.")
        return _rows(rows)
    if route == "/local/design":
        if payload.get("unlocked") is True:
            return "<p class=\"lead\">Design mode is open on this machine.</p>"
        return _empty("Design mode is closed.")
    if route == "/local/surface":
        listens = payload.get("listens") if isinstance(payload.get("listens"), list) else []
        bind = "127.0.0.1"
        if listens and isinstance(listens[0], dict) and listens[0].get("bind"):
            bind = str(listens[0].get("bind"))
        public = payload.get("public_api") if isinstance(payload.get("public_api"), list) else []
        rows = [("Bind", bind), ("Public API entries", str(len(public)))]
        return _rows(rows)
    if route == "/local/redline":
        items = payload.get("items") if isinstance(payload.get("items"), list) else []
        if not items:
            return _empty("No redline items yet.")
        passed = sum(1 for row in items if isinstance(row, dict) and row.get("pass") is True)
        return _rows([("Checks recorded", str(len(items))), ("Passing", str(passed))])
    if route == "/local/planes":
        gates = payload.get("gates") if isinstance(payload.get("gates"), dict) else {}
        return _rows(
            [
                ("Plane B shelf", "verified" if gates.get("plane_b_verified") else "not verified"),
                ("Plane C offline verify", "recorded" if gates.get("plane_c_offline_verify") else "not recorded"),
            ]
        )
    if route == "/local/unkillability":
        replicas = payload.get("replicas")
        radios = payload.get("radios_status")
        rows = []
        if replicas is not None:
            rows.append(("Replicas", str(replicas)))
        if radios:
            rows.append(("Radios", _fielding_words(radios)))
        if not rows:
            return _empty("Copy status has no extra fields to show here.")
        return _rows(rows)
    if payload.get("ok") is True:
        return "<p class=\"lead\">Status recorded on this loopback door.</p>"
    return _empty("Nothing further to show on this path.")


def open_hint(port: int) -> str:
    """One next step: start the loopback door, then open the local page."""
    if int(port) == 8891:
        return "Run qnm-node serve, then open http://127.0.0.1:8891/local/ui"
    return f"Run qnm-node serve --port {int(port)}, then open http://127.0.0.1:{int(port)}/local/ui"


def cli_status(snap: dict[str, Any], *, port: int) -> str:
    """Short human status. The snapshot dict itself stays on --json."""
    state = str(snap.get("state") or "")
    sentence = _STATE_PLAIN.get(state, f"Recorded state is {state}." if state else "No state recorded.")
    bearers = snap.get("bearers") if isinstance(snap.get("bearers"), dict) else {}
    fabric = snap.get("fabric") if isinstance(snap.get("fabric"), dict) else {}
    chain = snap.get("chain") if isinstance(snap.get("chain"), dict) else {}
    length = int(chain.get("length") or 0)
    if length <= 0 or _is_empty_tip(chain.get("tip")):
        receipts = "none yet"
    else:
        receipts = str(length)
    lines = [
        "Local node",
        f"State: {state or 'unknown'}",
        sentence,
        f"Bind: {snap.get('bind') or '127.0.0.1'}",
        f"Operator bearer: {_on_off(bearers.get('operator')).lower()}",
        f"Fabric software path: {_on_off(fabric.get('enabled')).lower()}",
        f"Receipts: {receipts}",
        "",
        open_hint(port),
    ]
    return "\n".join(lines) + "\n"


def cli_doctor(report: dict[str, Any], *, port: int) -> str:
    """Plain pass or fail. The doctor dict itself stays on --json."""
    ok = report.get("ok") is True
    radios = str(report.get("radios_status") or "").strip() or "unrecorded"
    lines = [
        "Doctor",
        "Pass — local checks recorded." if ok else "Fail — local checks did not pass.",
        f"Author: {report.get('author') or ''}".rstrip(),
        f"Bind: {report.get('bind') or '127.0.0.1'}",
        f"Radios: {radios}",
        f"Relay listen: {'on' if report.get('relay_listen') else 'off'}",
        f"Mesh enable: {'on' if report.get('mesh_enable') else 'off'}",
    ]
    handle = str(report.get("mesh_handle") or "").strip()
    if handle:
        lines.insert(3, f"Handle: {handle}")
    lines.extend(["", open_hint(port)])
    return "\n".join(lines) + "\n"


def cli_score(report: dict[str, Any]) -> str:
    """Human posture lines. The numeric report stays on --json."""
    posture = str(report.get("posture") or "").strip() or "unrecorded"
    inputs = report.get("inputs") if isinstance(report.get("inputs"), dict) else {}
    length = inputs.get("chain_length")
    length_line = f"Chain length: {length}" if length is not None else "Chain length: unrecorded"
    return (
        "Local posture\n"
        f"Posture: {posture}\n"
        f"{length_line}\n"
        "This report uses the local chain and posture.\n"
        "\n"
        "Run: qnm-node score --json\n"
    )


def serve_line(port: int) -> str:
    return f"Open http://127.0.0.1:{int(port)}/local/ui\n"


def _page(
    *,
    title: str,
    heading: str,
    active: str,
    body: str,
    author: str,
    spec: str,
    local_url: str = "",
    intro: str = "",
) -> str:
    foot_bits = ["127.0.0.1 loopback door"]
    if spec:
        foot_bits.append(spec)
    if author:
        foot_bits.append(author)
    footer = " · ".join(_esc(bit) for bit in foot_bits)
    lead = f"<p class=\"lead\">{_esc(intro)}</p>" if intro else ""
    url = ""
    if local_url:
        url = f"<p class=\"quiet url-line\">Local page <span class=\"url\">{_esc(local_url)}</span></p>"
    return (
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        f"<title>{_esc(title)}</title>\n"
        f"<style>{_CSS}</style>\n"
        "</head>\n"
        "<body>\n"
        "<main>\n"
        f"{_header(active)}\n"
        f"<h1>{_esc(heading)}</h1>\n"
        f"{lead}\n"
        f"{url}\n"
        f"{body}\n"
        f"<footer>{footer}</footer>\n"
        "</main>\n"
        "</body>\n"
        "</html>\n"
    )


def _header(active: str) -> str:
    on_overview = active in ("/local", "/local/ui")
    current = " aria-current=\"page\"" if on_overview else ""
    links = (
        ("/local/receipts", "Receipts"),
        ("/local/fabric", "Fabric"),
        ("/local/channels", "Channels"),
        ("/local/phy", "Radios"),
    )
    parts = [
        "<header>",
        f"<a class=\"primary\" href=\"/local/ui\"{current}>Open overview</a>",
        "<details class=\"more\"><summary>More</summary><nav>",
    ]
    for href, label in links:
        here = " aria-current=\"page\"" if href == active else ""
        parts.append(f"<a href=\"{_esc(href)}\"{here}>{_esc(label)}</a>")
    parts.append("</nav></details></header>")
    return "".join(parts)


_CSS = """
:root {
  color-scheme: light dark;
  --bg: #f4f1ea;
  --ink: #1c1915;
  --muted: #4a453c;
  --line: #e2dcd2;
  --accent: #1f4d45;
  --gold: #c9a227;
  --primary: #1f4d45;
  --on-primary: #f7f4ee;
  --focus-edge: #1c1915;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #12110f;
    --ink: #f3efe6;
    --muted: #c8c0b4;
    --line: #2e2a24;
    --accent: #e4d7a8;
    --gold: #c9a227;
    --primary: #c9a227;
    --on-primary: #1a160f;
    --focus-edge: #f3efe6;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font: 17px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
main { max-width: 40rem; margin: 0 auto; padding: 2.25rem 1.25rem 3.5rem; }
header { display: flex; flex-wrap: wrap; align-items: center; gap: 0.75rem 1.25rem; margin: 0 0 1.5rem; }
a.primary {
  display: inline-block;
  background: var(--primary);
  color: var(--on-primary);
  text-decoration: none;
  font-weight: 600;
  padding: 0.7rem 1.15rem;
  border-radius: 999px;
}
a:focus-visible, summary:focus-visible {
  outline: 2px solid var(--gold);
  outline-offset: 3px;
  box-shadow: 0 0 0 3px var(--focus-edge);
}
details.more summary {
  cursor: pointer;
  color: var(--accent);
  font-weight: 600;
  padding: 0.35rem 0.1rem;
}
details.more nav { display: flex; flex-direction: column; gap: 0.35rem; padding: 0.55rem 0 0.2rem; }
details.more nav a { color: var(--accent); text-decoration: none; }
details.more nav a[aria-current="page"] { text-decoration: underline; text-underline-offset: 0.2em; }
h1 { font-size: 1.85rem; font-weight: 600; letter-spacing: -0.02em; margin: 0 0 0.75rem; }
h2 { font-size: 0.78rem; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase; color: var(--muted); margin: 0 0 0.45rem; }
section { margin: 0 0 1.6rem; }
p { margin: 0 0 0.75rem; }
.state { color: var(--accent); font-size: 1.2rem; font-weight: 600; margin: 0 0 0.35rem; }
.lead { color: var(--ink); }
.quiet, footer { color: var(--muted); font-size: 0.92rem; }
.url { overflow-wrap: anywhere; }
.code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.95rem; color: var(--accent); }
ul { list-style: none; padding: 0; margin: 0 0 0.75rem; }
li { display: flex; justify-content: space-between; gap: 1rem; padding: 0.55rem 0; border-top: 1px solid var(--line); }
li .meta { color: var(--muted); text-align: right; overflow-wrap: anywhere; font-variant-numeric: tabular-nums; }
.empty { color: var(--muted); margin: 0; padding: 0.7rem 0; border-top: 1px solid var(--line); }
details { margin: 0.4rem 0 1.2rem; }
details summary { cursor: pointer; color: var(--accent); font-weight: 600; padding: 0.35rem 0; }
footer { margin-top: 2rem; }
@media (max-width: 420px) {
  main { padding: 1.35rem 1rem 2.5rem; }
  h1 { font-size: 1.55rem; }
  header { flex-direction: column; align-items: stretch; }
  a.primary { text-align: center; }
  li { flex-direction: column; gap: 0.15rem; }
  li .meta { text-align: left; }
}
"""
