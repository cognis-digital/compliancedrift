import json

from compliancedrift.cli import EXIT_OK, main
from compliancedrift.diff import diff_configs
from compliancedrift.sarif import build_sarif, to_sarif_json


def _report(base, current):
    return diff_configs(base, current)


def test_sarif_top_level_shape():
    rep = _report({"x": 1}, {"x": 2})
    doc = build_sarif(rep)
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert isinstance(doc["runs"], list) and len(doc["runs"]) == 1
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "compliancedrift"
    assert len(run["tool"]["driver"]["rules"]) == 3


def test_sarif_one_result_per_change():
    rep = _report(
        {"a": 1, "gone": True, "logging": {"level": "info"}},
        {"a": 2, "logging": {"level": "info"}, "new_key": 5},
    )
    doc = build_sarif(rep)
    results = doc["runs"][0]["results"]
    assert len(results) == len(rep.changes) == 3
    rule_ids = {r["ruleId"] for r in results}
    assert rule_ids == {"drift-added", "drift-removed", "drift-changed"}


def test_sarif_security_path_is_error_level():
    rep = _report(
        {"security": {"auth": {"mfa_required": True}}},
        {"security": {"auth": {"mfa_required": False}}},
    )
    doc = build_sarif(rep)
    res = doc["runs"][0]["results"][0]
    assert res["level"] == "error"
    assert res["properties"]["path"] == "security.auth.mfa_required"


def test_sarif_non_security_change_is_warning():
    rep = _report({"service": {"version": "1.0"}}, {"service": {"version": "2.0"}})
    res = build_sarif(rep)["runs"][0]["results"][0]
    assert res["level"] == "warning"


def test_sarif_removed_non_security_is_note():
    rep = _report({"logging": {"old_field": 1}}, {"logging": {}})
    res = build_sarif(rep)["runs"][0]["results"][0]
    assert res["ruleId"] == "drift-removed"
    assert res["level"] == "note"


def test_sarif_logical_location_carries_path():
    rep = _report({"network": {"egress_default": "deny"}}, {"network": {"egress_default": "allow"}})
    res = build_sarif(rep)["runs"][0]["results"][0]
    loc = res["locations"][0]["logicalLocations"][0]
    assert loc["fullyQualifiedName"] == "network.egress_default"
    # egress_default is security-sensitive
    assert res["level"] == "error"


def test_sarif_artifacts_use_uris():
    rep = _report({"x": 1}, {"x": 2})
    doc = build_sarif(rep, baseline_uri="base/b.json", current_uri="live/c.json")
    uris = {a["location"]["uri"] for a in doc["runs"][0]["artifacts"]}
    assert uris == {"base/b.json", "live/c.json"}
    assert doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"] == "live/c.json"


def test_sarif_no_drift_has_empty_results():
    rep = _report({"x": 1}, {"x": 1})
    doc = build_sarif(rep)
    assert doc["runs"][0]["results"] == []


def test_to_sarif_json_is_valid_json():
    rep = _report({"x": 1}, {"x": 2})
    parsed = json.loads(to_sarif_json(rep))
    assert parsed["version"] == "2.1.0"


def test_cli_sarif_flag(tmp_path, capsys):
    base = tmp_path / "b.json"
    cur = tmp_path / "c.json"
    base.write_text(json.dumps({"security": {"tls": {"min_version": "1.2"}}}), encoding="utf-8")
    cur.write_text(json.dumps({"security": {"tls": {"min_version": "1.0"}}}), encoding="utf-8")
    rc = main(["diff", str(base), str(cur), "--sarif"])
    assert rc == EXIT_OK
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"
    res = doc["runs"][0]["results"][0]
    assert res["level"] == "error"
    assert res["ruleId"] == "drift-changed"


def test_cli_sarif_with_fail_on_drift(tmp_path):
    from compliancedrift.cli import EXIT_DRIFT

    base = tmp_path / "b.json"
    cur = tmp_path / "c.json"
    base.write_text(json.dumps({"x": 1}), encoding="utf-8")
    cur.write_text(json.dumps({"x": 2}), encoding="utf-8")
    rc = main(["diff", str(base), str(cur), "--sarif", "--fail-on-drift"])
    assert rc == EXIT_DRIFT
