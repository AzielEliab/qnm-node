"""Human CLI is the default. --json keeps the machine bodies."""

from __future__ import annotations

import contextlib
import json
from io import StringIO
from pathlib import Path

from qnm.node import Node, main


def _run(argv: list[str]) -> tuple[int, str, str]:
    out = StringIO()
    err = StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(argv)
        except SystemExit as exc:
            code = int(exc.code) if exc.code is not None else 0
    return code, out.getvalue(), err.getvalue()


def test_bare_command_is_plain_status(tmp_path: Path) -> None:
    code, out, err = _run(["--root", str(tmp_path)])
    assert code == 0
    assert err == ""
    assert not out.lstrip().startswith("{")
    assert "Local node" in out
    assert "State: COLD" in out
    assert "Run qnm-node serve, then open http://127.0.0.1:8891/local/ui" in out
    assert "sign_private" not in out


def test_json_state_matches_snapshot(tmp_path: Path) -> None:
    code, out, err = _run(["state", "--json", "--root", str(tmp_path)])
    assert code == 0
    assert err == ""
    payload = json.loads(out)
    assert payload == Node(tmp_path).snapshot()
    assert payload["author"] == "Aziel Eliab"
    assert payload["bind"] == "127.0.0.1"
    assert payload["mesh_enable"] is False


def test_doctor_human_and_json(tmp_path: Path) -> None:
    code, out, err = _run(["doctor", "--root", str(tmp_path)])
    assert code == 0
    assert err == ""
    assert out.startswith("Doctor\n")
    assert "Pass — local checks recorded." in out
    assert "Author: Aziel Eliab" in out
    assert "Mesh enable: off" in out
    assert not out.lstrip().startswith("{")
    code, raw, err = _run(["doctor", "--json", "--root", str(tmp_path)])
    assert code == 0
    assert err == ""
    report = json.loads(raw)
    assert report["ok"] is True
    assert report["author"] == "Aziel Eliab"
    assert report["mesh_enable"] is False
    assert report["relay_listen"] is False
    assert "channels" in report


def test_help_lists_commands_and_examples() -> None:
    code, out, err = _run(["--help"])
    assert code == 0
    assert "serve" in out
    assert "doctor" in out
    assert "examples:" in out
    assert "qnm-node state --json" in out
    assert "Author: Aziel Eliab" in out
    assert "changelog" not in out.lower()
    assert err == ""


def test_unknown_flag_explains_the_next_step() -> None:
    code, out, err = _run(["--not-a-real-flag-xyz"])
    assert code == 2
    assert out == ""
    assert "Unknown argument --not-a-real-flag-xyz." in err
    assert "Try: qnm-node --help" in err
    assert "Traceback" not in err


def test_unknown_command_explains_the_next_step(tmp_path: Path) -> None:
    code, out, err = _run(["bogus", "--root", str(tmp_path)])
    assert code == 2
    assert out == ""
    assert 'Unknown command "bogus".' in err
    assert "qnm-node serve" in err
    assert "qnm-node --help" in err
    assert "Traceback" not in err


def test_score_human_omits_the_number(tmp_path: Path) -> None:
    code, out, err = _run(["score", "--root", str(tmp_path)])
    assert code == 0
    assert err == ""
    assert "Local posture" in out
    assert "qnm-node score --json" in out
    assert '"score"' not in out
    code, raw, err = _run(["score", "--json", "--root", str(tmp_path)])
    assert code == 0
    assert err == ""
    payload = json.loads(raw)
    assert payload["views_read"] is False
    assert "score" in payload
    assert payload["author"] == "Aziel Eliab"


def test_custom_port_hint(tmp_path: Path) -> None:
    code, out, _err = _run(["--root", str(tmp_path), "--port", "9000"])
    assert code == 0
    assert "Run qnm-node serve --port 9000, then open http://127.0.0.1:9000/local/ui" in out


def test_profile_mismatch_is_plain(tmp_path: Path) -> None:
    code, out, err = _run(
        ["--root", str(tmp_path / "one"), "--data-dir", str(tmp_path / "other")]
    )
    assert code == 2
    assert out == ""
    assert "refused" in err.lower()
    assert "Try: qnm-node --help" in err
    assert "Traceback" not in err
    code, out, err = _run(
        ["--json", "--root", str(tmp_path / "one"), "--data-dir", str(tmp_path / "two")]
    )
    assert code == 2
    payload = json.loads(err)
    assert payload["code"] == "FED-PROFILE"
    assert payload["author"] == "Aziel Eliab"
