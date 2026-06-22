"""Regression guard for the bundled demos/ corpus.

Every demo must: ship a signed baseline whose integrity verifies, and produce
real drift when diffed against its current.json. This keeps the demos honest as
the code evolves.
"""

import json
from pathlib import Path

import pytest

from compliancedrift.baseline import is_baseline, verify_baseline
from compliancedrift.cli import EXIT_DRIFT, EXIT_OK, main
from compliancedrift.diff import diff_configs
from compliancedrift.ignore import IgnoreList
from compliancedrift.sarif import build_sarif

DEMOS_DIR = Path(__file__).resolve().parent.parent / "demos"


def _demo_dirs():
    return sorted(p for p in DEMOS_DIR.iterdir() if p.is_dir())


def test_demos_directory_exists_and_is_populated():
    dirs = _demo_dirs()
    assert len(dirs) >= 8, "expected at least 8 demos"


@pytest.mark.parametrize("demo", _demo_dirs(), ids=lambda p: p.name)
def test_demo_has_required_files(demo):
    assert (demo / "baseline.signed.json").exists()
    assert (demo / "current.json").exists()
    assert (demo / "SCENARIO.md").exists()


@pytest.mark.parametrize("demo", _demo_dirs(), ids=lambda p: p.name)
def test_demo_signed_baseline_verifies(demo):
    doc = json.loads((demo / "baseline.signed.json").read_text(encoding="utf-8"))
    assert is_baseline(doc), f"{demo.name}: baseline.signed.json is not an envelope"
    ok, expected, actual = verify_baseline(doc)
    assert ok, f"{demo.name}: integrity check failed ({expected} != {actual})"


@pytest.mark.parametrize("demo", _demo_dirs(), ids=lambda p: p.name)
def test_demo_produces_drift(demo):
    base_doc = json.loads((demo / "baseline.signed.json").read_text(encoding="utf-8"))
    current = json.loads((demo / "current.json").read_text(encoding="utf-8"))
    base = base_doc["config"]

    ignore = IgnoreList()
    ig_file = demo / "ignore.txt"
    if ig_file.exists():
        with ig_file.open(encoding="utf-8") as fp:
            for p in IgnoreList.from_file(fp).patterns:
                ignore.add(p)

    report = diff_configs(base, current, ignore)
    assert report.has_drift, f"{demo.name}: expected drift after ignores, found none"


@pytest.mark.parametrize("demo", _demo_dirs(), ids=lambda p: p.name)
def test_demo_cli_diff_runs(demo):
    base = str(demo / "baseline.signed.json")
    current = str(demo / "current.json")
    argv = ["diff", base, current, "--fail-on-drift"]
    ig_file = demo / "ignore.txt"
    if ig_file.exists():
        argv += ["--ignore-file", str(ig_file)]
    rc = main(argv)
    assert rc in (EXIT_OK, EXIT_DRIFT)
    # Every demo with non-ignored drift gates to EXIT_DRIFT; the curated set does.
    assert rc == EXIT_DRIFT, f"{demo.name}: expected the CI gate to fire"


@pytest.mark.parametrize("demo", _demo_dirs(), ids=lambda p: p.name)
def test_demo_sarif_is_wellformed(demo):
    base_doc = json.loads((demo / "baseline.signed.json").read_text(encoding="utf-8"))
    current = json.loads((demo / "current.json").read_text(encoding="utf-8"))
    report = diff_configs(base_doc["config"], current)
    sarif = build_sarif(report)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == len(report.changes)
