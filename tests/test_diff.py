from compliancedrift.diff import ADDED, CHANGED, REMOVED, diff_configs
from compliancedrift.ignore import IgnoreList


def _kinds(report):
    return {(c.kind, c.path) for c in report.changes}


def test_no_drift_identical():
    cfg = {"a": 1, "b": {"c": 2}}
    report = diff_configs(cfg, cfg)
    assert not report.has_drift
    assert report.changes == []


def test_added_key():
    base = {"a": 1}
    cur = {"a": 1, "b": 2}
    report = diff_configs(base, cur)
    assert (ADDED, "b") in _kinds(report)
    assert len(report.added) == 1
    assert report.added[0].new == 2


def test_removed_key():
    base = {"a": 1, "b": 2}
    cur = {"a": 1}
    report = diff_configs(base, cur)
    assert (REMOVED, "b") in _kinds(report)
    assert report.removed[0].old == 2


def test_changed_value_records_old_and_new():
    base = {"a": 1}
    cur = {"a": 5}
    report = diff_configs(base, cur)
    chg = report.changed[0]
    assert chg.kind == CHANGED
    assert chg.path == "a"
    assert chg.old == 1
    assert chg.new == 5


def test_nested_dotted_paths():
    base = {"security": {"tls": {"min_version": "1.2"}}}
    cur = {"security": {"tls": {"min_version": "1.0"}}}
    report = diff_configs(base, cur)
    assert _kinds(report) == {(CHANGED, "security.tls.min_version")}


def test_deeply_nested_add_remove_change():
    base = {"x": {"y": {"keep": 1, "drop": 2, "mod": 3}}}
    cur = {"x": {"y": {"keep": 1, "mod": 99, "new": 4}}}
    report = diff_configs(base, cur)
    assert _kinds(report) == {
        (REMOVED, "x.y.drop"),
        (CHANGED, "x.y.mod"),
        (ADDED, "x.y.new"),
    }


def test_list_index_change():
    base = {"cidrs": ["10.0.0.0/8", "172.16.0.0/12"]}
    cur = {"cidrs": ["10.0.0.0/8", "0.0.0.0/0"]}
    report = diff_configs(base, cur)
    assert _kinds(report) == {(CHANGED, "cidrs.1")}


def test_list_added_element():
    base = {"items": [1, 2]}
    cur = {"items": [1, 2, 3]}
    report = diff_configs(base, cur)
    assert _kinds(report) == {(ADDED, "items.2")}


def test_list_removed_element():
    base = {"items": [1, 2, 3]}
    cur = {"items": [1, 2]}
    report = diff_configs(base, cur)
    assert _kinds(report) == {(REMOVED, "items.2")}


def test_list_of_dicts_nested_paths():
    base = {"servers": [{"host": "a", "port": 80}]}
    cur = {"servers": [{"host": "a", "port": 443}]}
    report = diff_configs(base, cur)
    assert _kinds(report) == {(CHANGED, "servers.0.port")}


def test_type_change_dict_to_scalar():
    base = {"a": {"b": 1}}
    cur = {"a": 5}
    report = diff_configs(base, cur)
    # The whole subtree collapses to a single CHANGED at the parent path.
    assert _kinds(report) == {(CHANGED, "a")}


def test_changes_are_sorted_by_path():
    base = {"z": 1, "a": 1, "m": 1}
    cur = {"z": 2, "a": 2, "m": 2}
    report = diff_configs(base, cur)
    paths = [c.path for c in report.changes]
    assert paths == sorted(paths)


def test_summary_counts():
    base = {"keep": 1, "drop": 2, "mod": 3}
    cur = {"keep": 1, "mod": 9, "add": 4}
    report = diff_configs(base, cur)
    d = report.to_dict()
    assert d["summary"] == {"added": 1, "removed": 1, "changed": 1}
    assert d["has_drift"] is True
