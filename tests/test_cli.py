import json

import pytest

from compliancedrift.cli import EXIT_DRIFT, EXIT_ERROR, EXIT_OK, main


def _write(path, obj):
    path.write_text(json.dumps(obj), encoding="utf-8")
    return str(path)


def test_baseline_then_verify_roundtrip(tmp_path, capsys):
    cfg = _write(tmp_path / "cfg.json", {"a": 1, "b": {"c": 2}})
    out = tmp_path / "baseline.json"
    rc = main(["baseline", cfg, "-o", str(out)])
    assert rc == EXIT_OK
    env = json.loads(out.read_text())
    assert env["compliancedrift_baseline"] == "1"

    rc = main(["verify", str(out)])
    assert rc == EXIT_OK
    assert "intact" in capsys.readouterr().out


def test_verify_detects_tamper(tmp_path, capsys):
    cfg = _write(tmp_path / "cfg.json", {"mfa": True})
    out = tmp_path / "baseline.json"
    main(["baseline", cfg, "-o", str(out)])
    env = json.loads(out.read_text())
    env["config"]["mfa"] = False
    out.write_text(json.dumps(env))

    rc = main(["verify", str(out)])
    assert rc == EXIT_DRIFT
    assert "FAIL" in capsys.readouterr().out


def test_diff_reports_drift_table(tmp_path, capsys):
    base = _write(tmp_path / "b.json", {"x": 1, "y": 2})
    cur = _write(tmp_path / "c.json", {"x": 9, "z": 3})
    rc = main(["diff", base, cur])
    assert rc == EXIT_OK  # no --fail-on-drift
    out = capsys.readouterr().out
    assert "DRIFT" in out
    assert "x" in out and "y" in out and "z" in out


def test_diff_fail_on_drift_gate(tmp_path):
    base = _write(tmp_path / "b.json", {"x": 1})
    cur = _write(tmp_path / "c.json", {"x": 2})
    rc = main(["diff", base, cur, "--fail-on-drift"])
    assert rc == EXIT_DRIFT


def test_diff_no_drift_gate_passes(tmp_path):
    base = _write(tmp_path / "b.json", {"x": 1})
    cur = _write(tmp_path / "c.json", {"x": 1})
    rc = main(["diff", base, cur, "--fail-on-drift"])
    assert rc == EXIT_OK


def test_diff_json_output(tmp_path, capsys):
    base = _write(tmp_path / "b.json", {"x": 1})
    cur = _write(tmp_path / "c.json", {"x": 2})
    rc = main(["diff", base, cur, "--json"])
    assert rc == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["has_drift"] is True
    assert payload["summary"]["changed"] == 1


def test_diff_with_ignore_pattern(tmp_path, capsys):
    base = _write(tmp_path / "b.json", {"meta": {"ts": 1}, "p": 8})
    cur = _write(tmp_path / "c.json", {"meta": {"ts": 9}, "p": 8})
    rc = main(["diff", base, cur, "-i", "meta", "--fail-on-drift"])
    assert rc == EXIT_OK
    assert "No drift" in capsys.readouterr().out


def test_diff_with_ignore_file(tmp_path):
    base = _write(tmp_path / "b.json", {"meta": {"ts": 1}, "p": 8})
    cur = _write(tmp_path / "c.json", {"meta": {"ts": 9}, "p": 8})
    ig = tmp_path / "ig.txt"
    ig.write_text("meta.*\n")
    rc = main(["diff", base, cur, "--ignore-file", str(ig), "--fail-on-drift"])
    assert rc == EXIT_OK


def test_diff_against_signed_baseline(tmp_path):
    cfg = _write(tmp_path / "cfg.json", {"x": 1})
    bl = tmp_path / "baseline.json"
    main(["baseline", cfg, "-o", str(bl)])
    cur = _write(tmp_path / "cur.json", {"x": 2})
    rc = main(["diff", str(bl), cur, "--fail-on-drift"])
    assert rc == EXIT_DRIFT


def test_diff_refuses_tampered_baseline(tmp_path, capsys):
    cfg = _write(tmp_path / "cfg.json", {"x": 1})
    bl = tmp_path / "baseline.json"
    main(["baseline", cfg, "-o", str(bl)])
    env = json.loads(bl.read_text())
    env["config"]["x"] = 5  # tamper
    bl.write_text(json.dumps(env))
    cur = _write(tmp_path / "cur.json", {"x": 1})
    rc = main(["diff", str(bl), cur])
    assert rc == EXIT_ERROR
    assert "integrity" in capsys.readouterr().err


def test_diff_no_verify_allows_tampered_baseline(tmp_path):
    cfg = _write(tmp_path / "cfg.json", {"x": 1})
    bl = tmp_path / "baseline.json"
    main(["baseline", cfg, "-o", str(bl)])
    env = json.loads(bl.read_text())
    env["config"]["x"] = 5
    bl.write_text(json.dumps(env))
    cur = _write(tmp_path / "cur.json", {"x": 5})
    rc = main(["diff", str(bl), cur, "--no-verify", "--fail-on-drift"])
    assert rc == EXIT_OK


def test_missing_file_errors(tmp_path):
    rc = main(["verify", str(tmp_path / "nope.json")])
    assert rc == EXIT_ERROR
