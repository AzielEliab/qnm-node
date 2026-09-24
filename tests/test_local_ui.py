"""Local HTML on the loopback door. JSON stays the machine response."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from qnm.boot import QNMRefuse
from qnm.local_ui import explain_refuse, prefers_html, render_dashboard
from qnm.node import Node, serve
from qnm.surface import SECURITY_HEADERS


BROWSER = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"


class Running:
    def __init__(self) -> None:
        self.servers = []

    def up(self, root: Path) -> tuple[Node, str]:
        node = Node(root)
        server = serve(node, "127.0.0.1", 0)
        port = server.server_address[1]
        url = f"http://127.0.0.1:{port}"
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.servers.append(server)
        return node, url

    def close(self) -> None:
        for server in self.servers:
            server.shutdown()
            server.server_close()
        self.servers.clear()


def _get(url: str, accept: str) -> tuple[int, str, bytes]:
    import urllib.error
    import urllib.request

    req = urllib.request.Request(url, method="GET")
    req.add_header("Accept", accept)
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            return res.status, res.headers.get("Content-Type", ""), res.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Content-Type", ""), exc.read()


def test_prefers_html_only_when_html_outranks_json() -> None:
    assert prefers_html(BROWSER) is True
    assert prefers_html("text/html") is True
    assert prefers_html("text/html, application/json;q=0.9") is True
    assert prefers_html("application/json") is False
    assert prefers_html("text/html, application/json") is False
    assert prefers_html("*/*") is False
    assert prefers_html("") is False
    assert prefers_html(None) is False
    assert prefers_html("application/json, text/html;q=0.8") is False


def test_refuse_codes_use_human_words() -> None:
    mesh = explain_refuse("QNM-MESH-NEVER-ENABLES", "GET /v1/mesh never enables radios")
    assert "QNM-MESH-NEVER-ENABLES" not in mesh
    assert "radios" in mesh and "mesh" in mesh
    radio = explain_refuse("QNM-RADIO-OFF", "radios stay off until fabric enable")
    assert "fabric software path" in radio
    unknown = explain_refuse("QNM-NOT-A-REAL-CODE", "operator detail")
    assert unknown == "operator detail"
    bare = explain_refuse("", "")
    assert "refused" in bare


def test_json_body_unchanged_and_html_is_separate(tmp_path: Path) -> None:
    running = Running()
    try:
        node, url = running.up(tmp_path)
        node.boot(entropy=b"e", nonce=b"n")
        code, payload = node.handle("GET", "/local/state", b"")
        assert code == 200
        expected = json.dumps(payload, sort_keys=True).encode("utf-8")
        status, ctype, body = _get(url + "/local/state", "application/json")
        assert status == 200
        assert ctype == "application/json"
        assert body == expected
        status, ctype, body = _get(url + "/local/state", "*/*")
        assert status == 200
        assert ctype == "application/json"
        assert body == expected
        status, ctype, page = _get(url + "/local/ui", "application/json")
        assert status == 404
        assert ctype == "application/json"
        missing = json.dumps(
            QNMRefuse("QNM-LOOPBACK-ONLY", "unknown local path").as_dict(),
            sort_keys=True,
        ).encode("utf-8")
        assert page == missing
        status, ctype, html = _get(url + "/local/ui", BROWSER)
        assert status == 200
        assert ctype.startswith("text/html")
        text = html.decode("utf-8")
        assert "LOCAL" in text
        assert "No install yet" not in text
        assert "architecture_score" not in text
        assert "fielded_score" not in text
        assert "<script" not in text.lower()
        assert "sign_private" not in text
        assert node.fabric.enabled is False
        assert node.snapshot()["mesh_enable"] is False
    finally:
        running.close()


def test_browser_dashboard_is_read_only(tmp_path: Path) -> None:
    running = Running()
    try:
        node, url = running.up(tmp_path)
        before_bearers = dict(node.bearers.snapshot())
        receipt_log = node._receipt_log.read_text(encoding="utf-8")
        status, ctype, html = _get(url + "/local/", BROWSER)
        assert status == 200
        assert ctype.startswith("text/html")
        text = html.decode("utf-8")
        assert "COLD" in text
        assert "No install yet." in text
        assert "No receipt tip yet." in text
        assert "No receipts on disk yet." in text
        assert "The fabric software path is off." in text
        assert "0" * 64 not in text
        assert node.state == "COLD"
        assert node.bearers.snapshot() == before_bearers
        assert node.fabric.enabled is False
        assert node.fed.relay_on is False
        assert node._receipt_log.read_text(encoding="utf-8") == receipt_log
        mesh_status, mesh_type, mesh_body = _get(url + "/v1/mesh", BROWSER)
        assert mesh_status == 403
        assert mesh_type.startswith("text/html")
        mesh_text = mesh_body.decode("utf-8")
        assert "QNM-MESH-NEVER-ENABLES" in mesh_text
        assert "leaves radios and mesh off" in mesh_text
        assert node.bearers.snapshot() == before_bearers
        assert node.snapshot()["mesh_enable"] is False
        json_status, json_type, json_body = _get(url + "/v1/mesh", "application/json")
        assert json_status == 403
        assert json_type == "application/json"
        expected = json.dumps(
            QNMRefuse("QNM-MESH-NEVER-ENABLES", "GET /v1/mesh never enables radios").as_dict(),
            sort_keys=True,
        ).encode("utf-8")
        assert json_body == expected
    finally:
        running.close()


def test_html_security_headers_do_not_replace_json_headers(tmp_path: Path) -> None:
    running = Running()
    try:
        _node, url = running.up(tmp_path)
        import urllib.request

        req = urllib.request.Request(url + "/local/state", method="GET")
        req.add_header("Accept", "application/json")
        with urllib.request.urlopen(req, timeout=5) as res:
            assert res.headers["Content-Type"] == "application/json"
            assert res.headers["Content-Security-Policy"] == "default-src 'none'"
            for name, value in SECURITY_HEADERS:
                assert res.headers[name] == value
        req = urllib.request.Request(url + "/local/ui", method="GET")
        req.add_header("Accept", BROWSER)
        with urllib.request.urlopen(req, timeout=5) as res:
            policy = res.headers["Content-Security-Policy"]
            assert "script-src 'none'" in policy
            assert "style-src 'unsafe-inline'" in policy
            assert res.headers["Cache-Control"] == "no-store"
            assert res.headers["X-Frame-Options"] == "DENY"
    finally:
        running.close()


def test_dashboard_render_has_empty_and_booted_states(tmp_path: Path) -> None:
    node = Node(tmp_path)
    cold = render_dashboard(node)
    assert "No install yet." in cold
    assert "No receipts on disk yet." in cold
    assert "<script" not in cold.lower()
    node.boot(entropy=b"e", nonce=b"n")
    page = render_dashboard(node)
    assert node.install_root in page
    assert "Receipt tip" in page
    assert "boot" in page
    assert "architecture_score" not in page
    assert "fielded_score" not in page
    assert node.fabric.enabled is False


def test_wan_bind_still_refused(tmp_path: Path) -> None:
    node = Node(tmp_path)
    with pytest.raises(QNMRefuse) as exc:
        serve(node, host="0.0.0.0", port=0)
    assert exc.value.code == "QNM-LOOPBACK-ONLY"
