"""SARIF 2.1.0 export for drift reports.

Renders a :class:`~compliancedrift.diff.DriftReport` as a SARIF
(Static Analysis Results Interchange Format) 2.1.0 log so that detected
configuration drift can be ingested by CI dashboards and GitHub code
scanning (the ``codeql`` / ``upload-sarif`` action) alongside other
security findings.

SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

The mapping is intentionally simple and self-contained (standard library
only). Each drift entry becomes one SARIF ``result``:

* ``ruleId``   — the drift kind (``drift-added`` / ``drift-removed`` /
  ``drift-changed``).
* ``level``    — ``error`` for security-sensitive paths, otherwise
  ``warning`` (added/changed) or ``note`` (removed). The heuristic is
  conservative and only escalates well-known security keys.
* ``message``  — a human-readable description including the dotted path
  and old/new values.
* ``locations``— the baseline/current artifact plus a
  ``logicalLocation`` carrying the dotted path, so tools can group and
  navigate findings by configuration key.
"""

from __future__ import annotations

import json
from typing import Any, List, Optional

from . import __version__
from .diff import ADDED, CHANGED, REMOVED, DriftReport

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)
TOOL_NAME = "compliancedrift"
TOOL_URI = "https://github.com/cognis-digital/compliancedrift"

_RULE_FOR_KIND = {
    ADDED: "drift-added",
    REMOVED: "drift-removed",
    CHANGED: "drift-changed",
}

# Path segments that mark a finding as security-sensitive. Matching is done
# per dotted-path segment (case-insensitive) so e.g. ``security.tls.min_version``
# and ``auth.mfa_required`` both escalate. Kept deliberately small and explicit.
_SECURITY_SEGMENTS = frozenset(
    {
        "security",
        "tls",
        "ssl",
        "auth",
        "mfa",
        "mfa_required",
        "password_policy",
        "encryption",
        "egress_default",
        "allowed_cidrs",
        "cidr_blocks",
        "ingress",
        "egress",
        "firewall",
        "permissions",
        "privileged",
        "secrets",
        "rbac",
    }
)


def _is_security_path(path: str) -> bool:
    segments = {seg.lower() for seg in path.split(".")}
    return bool(segments & _SECURITY_SEGMENTS)


def _level_for(kind: str, path: str) -> str:
    if _is_security_path(path):
        return "error"
    if kind == REMOVED:
        return "note"
    return "warning"


def _message_for(change: Any) -> str:
    if change.kind == ADDED:
        return f"Configuration key '{change.path}' was added (value: {_short(change.new)})."
    if change.kind == REMOVED:
        return f"Configuration key '{change.path}' was removed (was: {_short(change.old)})."
    return (
        f"Configuration key '{change.path}' changed: "
        f"{_short(change.old)} -> {_short(change.new)}."
    )


def _short(value: Any, limit: int = 120) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


def build_sarif(
    report: DriftReport,
    baseline_uri: str = "baseline.json",
    current_uri: str = "current.json",
) -> dict:
    """Return a SARIF 2.1.0 log (as a dict) for ``report``.

    ``baseline_uri`` / ``current_uri`` are recorded as artifacts so the
    report is self-describing about what was compared.
    """
    rules = [
        {
            "id": "drift-added",
            "name": "ConfigurationKeyAdded",
            "shortDescription": {"text": "A configuration key was added relative to the baseline."},
            "defaultConfiguration": {"level": "warning"},
        },
        {
            "id": "drift-removed",
            "name": "ConfigurationKeyRemoved",
            "shortDescription": {"text": "A configuration key was removed relative to the baseline."},
            "defaultConfiguration": {"level": "note"},
        },
        {
            "id": "drift-changed",
            "name": "ConfigurationValueChanged",
            "shortDescription": {"text": "A configuration value changed relative to the baseline."},
            "defaultConfiguration": {"level": "warning"},
        },
    ]

    artifacts = [
        {"location": {"uri": baseline_uri}, "roles": ["referencedOnDisk"]},
        {"location": {"uri": current_uri}, "roles": ["analysisTarget"]},
    ]

    results: List[dict] = []
    for change in report.changes:
        rule_id = _RULE_FOR_KIND[change.kind]
        result = {
            "ruleId": rule_id,
            "level": _level_for(change.kind, change.path),
            "message": {"text": _message_for(change)},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": current_uri},
                    },
                    "logicalLocations": [
                        {"fullyQualifiedName": change.path, "kind": "member"}
                    ],
                }
            ],
            "partialFingerprints": {"driftPath": change.path},
            "properties": {"kind": change.kind, "path": change.path},
        }
        results.append(result)

    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": TOOL_URI,
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "artifacts": artifacts,
                "results": results,
            }
        ],
    }


def to_sarif_json(
    report: DriftReport,
    baseline_uri: str = "baseline.json",
    current_uri: str = "current.json",
    indent: Optional[int] = 2,
) -> str:
    """Serialize :func:`build_sarif` to a JSON string."""
    return json.dumps(
        build_sarif(report, baseline_uri, current_uri),
        indent=indent,
        ensure_ascii=False,
    )
