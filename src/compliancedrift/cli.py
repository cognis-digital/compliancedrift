"""Command-line interface for compliancedrift.

Subcommands:
    baseline   capture a config + embed a sha256 digest
    verify     check an embedded digest (tamper detection)
    diff       report drift of a current config against a baseline
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, List, Optional

from . import __version__
from .baseline import build_baseline, extract_config, is_baseline, verify_baseline
from .diff import ADDED, CHANGED, REMOVED, DriftReport, diff_configs
from .ignore import IgnoreList

EXIT_OK = 0
EXIT_DRIFT = 1
EXIT_ERROR = 2

_SYMBOL = {ADDED: "+", REMOVED: "-", CHANGED: "~"}


def _load_json(path: str) -> Any:
    if path == "-":
        return json.load(sys.stdin)
    with open(path, "r", encoding="utf-8") as fp:
        return json.load(fp)


def _fmt_value(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    if len(text) > 80:
        text = text[:77] + "..."
    return text


def _collect_ignore(args: argparse.Namespace) -> IgnoreList:
    ignore = IgnoreList()
    for pattern in args.ignore or []:
        ignore.add(pattern)
    for path in args.ignore_file or []:
        with open(path, "r", encoding="utf-8") as fp:
            for p in IgnoreList.from_file(fp).patterns:
                ignore.add(p)
    return ignore


def _render_table(report: DriftReport) -> str:
    lines: List[str] = []
    if not report.has_drift:
        return "No drift detected."
    lines.append(
        "DRIFT: {added} added, {removed} removed, {changed} changed".format(
            added=len(report.added),
            removed=len(report.removed),
            changed=len(report.changed),
        )
    )
    lines.append("")
    width = max((len(c.path) for c in report.changes), default=4)
    width = max(width, len("PATH"))
    lines.append(f"  {'':1} {'PATH'.ljust(width)}  DETAIL")
    lines.append(f"  {'-':1} {'-' * width}  {'-' * 6}")
    for c in report.changes:
        sym = _SYMBOL[c.kind]
        if c.kind == ADDED:
            detail = _fmt_value(c.new)
        elif c.kind == REMOVED:
            detail = _fmt_value(c.old)
        else:
            detail = f"{_fmt_value(c.old)} -> {_fmt_value(c.new)}"
        lines.append(f"  {sym:1} {c.path.ljust(width)}  {detail}")
    return "\n".join(lines)


def cmd_baseline(args: argparse.Namespace) -> int:
    config = _load_json(args.config)
    if is_baseline(config):
        # Re-baseline from an existing envelope's captured config.
        config = extract_config(config)
    envelope = build_baseline(config)
    text = json.dumps(envelope, indent=2, ensure_ascii=False, sort_keys=True)
    if args.output and args.output != "-":
        with open(args.output, "w", encoding="utf-8") as fp:
            fp.write(text + "\n")
        print(f"Baseline written to {args.output}", file=sys.stderr)
        print(f"sha256: {envelope['digest']}", file=sys.stderr)
    else:
        print(text)
    return EXIT_OK


def cmd_verify(args: argparse.Namespace) -> int:
    doc = _load_json(args.baseline)
    if not is_baseline(doc):
        print("ERROR: not a compliancedrift baseline file", file=sys.stderr)
        return EXIT_ERROR
    ok, expected, actual = verify_baseline(doc)
    if args.json:
        print(json.dumps({"ok": ok, "expected": expected, "actual": actual}))
    elif ok:
        print(f"OK: baseline integrity intact (sha256 {expected})")
    else:
        print("FAIL: baseline integrity check failed (tampering detected)")
        print(f"  expected: {expected}")
        print(f"  actual:   {actual}")
    return EXIT_OK if ok else EXIT_DRIFT


def cmd_diff(args: argparse.Namespace) -> int:
    base_doc = _load_json(args.baseline)
    current_doc = _load_json(args.current)

    # If the baseline is a signed envelope, verify integrity first so a
    # tampered baseline cannot silently mask drift.
    if is_baseline(base_doc) and not args.no_verify:
        ok, expected, actual = verify_baseline(base_doc)
        if not ok:
            print(
                "ERROR: baseline integrity check failed; refusing to diff "
                "against a tampered baseline.",
                file=sys.stderr,
            )
            print(f"  expected: {expected}", file=sys.stderr)
            print(f"  actual:   {actual}", file=sys.stderr)
            return EXIT_ERROR

    base = extract_config(base_doc)
    current = extract_config(current_doc)
    ignore = _collect_ignore(args)
    report = diff_configs(base, current, ignore)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(_render_table(report))

    if args.fail_on_drift and report.has_drift:
        return EXIT_DRIFT
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="compliancedrift",
        description="Configuration/compliance drift detector.",
    )
    parser.add_argument("--version", action="version", version=f"compliancedrift {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_base = sub.add_parser("baseline", help="capture a config + embed a sha256 digest")
    p_base.add_argument("config", help="path to config JSON ('-' for stdin)")
    p_base.add_argument("-o", "--output", help="output baseline path ('-' for stdout)")
    p_base.set_defaults(func=cmd_baseline)

    p_verify = sub.add_parser("verify", help="check a baseline's embedded digest")
    p_verify.add_argument("baseline", help="path to baseline JSON ('-' for stdin)")
    p_verify.add_argument("--json", action="store_true", help="emit JSON result")
    p_verify.set_defaults(func=cmd_verify)

    p_diff = sub.add_parser("diff", help="report drift of current vs baseline")
    p_diff.add_argument("baseline", help="path to baseline (or plain config) JSON")
    p_diff.add_argument("current", help="path to current config JSON ('-' for stdin)")
    p_diff.add_argument(
        "-i", "--ignore", action="append", metavar="PATTERN",
        help="dotted-path glob to ignore (repeatable)",
    )
    p_diff.add_argument(
        "--ignore-file", action="append", metavar="FILE",
        help="file of ignore patterns, one per line (repeatable)",
    )
    p_diff.add_argument("--json", action="store_true", help="emit JSON drift report")
    p_diff.add_argument(
        "--fail-on-drift", action="store_true",
        help="exit non-zero when any drift is detected (CI gate)",
    )
    p_diff.add_argument(
        "--no-verify", action="store_true",
        help="skip baseline integrity check before diffing",
    )
    p_diff.set_defaults(func=cmd_diff)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"ERROR: file not found: {exc.filename}", file=sys.stderr)
        return EXIT_ERROR
    except json.JSONDecodeError as exc:
        print(f"ERROR: invalid JSON: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
