from compliancedrift.diff import diff_configs
from compliancedrift.ignore import IgnoreList


def test_exact_path_ignored():
    il = IgnoreList(["a.b"])
    assert il.is_ignored("a.b")
    assert not il.is_ignored("a.c")


def test_prefix_ignore_covers_nested():
    il = IgnoreList(["metadata"])
    assert il.is_ignored("metadata")
    assert il.is_ignored("metadata.timestamp")
    assert il.is_ignored("metadata.deep.nested.key")
    assert not il.is_ignored("metadatax")


def test_single_segment_wildcard():
    il = IgnoreList(["servers.*.last_seen"])
    assert il.is_ignored("servers.0.last_seen")
    assert il.is_ignored("servers.web.last_seen")
    assert not il.is_ignored("servers.0.host")


def test_single_wildcard_covers_deeper():
    il = IgnoreList(["servers.*"])
    assert il.is_ignored("servers.0")
    assert il.is_ignored("servers.0.host")
    assert not il.is_ignored("clusters.0")


def test_star_does_not_cross_segment():
    il = IgnoreList(["a.*"])
    # 'a.*' matches a.b and a.b.c (nested) but pattern itself is one segment.
    assert il.is_ignored("a.b")
    assert il.is_ignored("a.b.c")
    assert not il.is_ignored("ax")


def test_double_star_crosses_segments():
    il = IgnoreList(["**.timestamp"])
    assert il.is_ignored("timestamp")
    assert il.is_ignored("a.timestamp")
    assert il.is_ignored("a.b.c.timestamp")
    assert not il.is_ignored("a.timestamped")


def test_double_star_middle():
    il = IgnoreList(["audit.**.id"])
    assert il.is_ignored("audit.id")
    assert il.is_ignored("audit.events.0.id")
    assert not il.is_ignored("audit.events.0.name")


def test_question_mark():
    il = IgnoreList(["v?"])
    assert il.is_ignored("v1")
    assert il.is_ignored("v9")
    assert not il.is_ignored("v10")


def test_from_file_skips_comments_and_blanks(tmp_path):
    p = tmp_path / "ignore.txt"
    p.write_text("# comment\n\nmetadata.*\n  logging.level  # inline\n")
    with p.open() as fp:
        il = IgnoreList.from_file(fp)
    assert len(il) == 2
    assert il.is_ignored("metadata.captured_at")
    assert il.is_ignored("logging.level")


def test_ignore_filters_drift():
    base = {"metadata": {"ts": 1}, "policy": {"len": 8}}
    cur = {"metadata": {"ts": 999}, "policy": {"len": 4}}
    il = IgnoreList(["metadata.*"])
    report = diff_configs(base, cur, il)
    paths = {c.path for c in report.changes}
    assert paths == {"policy.len"}


def test_ignore_added_and_removed():
    base = {"a": 1, "vol": {"x": 1}}
    cur = {"a": 1, "vol": {"y": 2}}
    il = IgnoreList(["vol"])
    report = diff_configs(base, cur, il)
    assert not report.has_drift
