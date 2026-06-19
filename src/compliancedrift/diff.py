"""Deep diff over nested dicts/lists producing a drift report by dotted path.

Implemented from scratch (no third-party diff libraries). A path is a dotted
string where dict keys and list indices are joined with ``.`` — for example
``servers.0.host`` or ``policies.password.min_length``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional

from .ignore import IgnoreList

ADDED = "added"
REMOVED = "removed"
CHANGED = "changed"


@dataclass
class Change:
    """A single drift entry."""

    kind: str  # ADDED | REMOVED | CHANGED
    path: str
    old: Any = None
    new: Any = None

    def to_dict(self) -> dict:
        d = {"kind": self.kind, "path": self.path}
        if self.kind in (REMOVED, CHANGED):
            d["old"] = self.old
        if self.kind in (ADDED, CHANGED):
            d["new"] = self.new
        return d


@dataclass
class DriftReport:
    """Collection of changes between a baseline and a current config."""

    changes: List[Change] = field(default_factory=list)

    @property
    def added(self) -> List[Change]:
        return [c for c in self.changes if c.kind == ADDED]

    @property
    def removed(self) -> List[Change]:
        return [c for c in self.changes if c.kind == REMOVED]

    @property
    def changed(self) -> List[Change]:
        return [c for c in self.changes if c.kind == CHANGED]

    @property
    def has_drift(self) -> bool:
        return bool(self.changes)

    def sorted(self) -> "DriftReport":
        return DriftReport(sorted(self.changes, key=lambda c: (c.path, c.kind)))

    def to_dict(self) -> dict:
        return {
            "has_drift": self.has_drift,
            "summary": {
                "added": len(self.added),
                "removed": len(self.removed),
                "changed": len(self.changed),
            },
            "changes": [c.to_dict() for c in self.changes],
        }


def _join(prefix: str, key: Any) -> str:
    key = str(key)
    return key if not prefix else f"{prefix}.{key}"


def _is_container(value: Any) -> bool:
    return isinstance(value, (dict, list))


def _walk(
    base: Any,
    current: Any,
    prefix: str,
    out: List[Change],
    ignore: IgnoreList,
) -> None:
    """Recursively compare ``base`` and ``current``, appending to ``out``."""

    # Same type containers recurse; otherwise it is a leaf comparison.
    if isinstance(base, dict) and isinstance(current, dict):
        for key in base:
            child_path = _join(prefix, key)
            if key not in current:
                if not ignore.is_ignored(child_path):
                    out.append(Change(REMOVED, child_path, old=base[key]))
            else:
                _walk(base[key], current[key], child_path, out, ignore)
        for key in current:
            if key not in base:
                child_path = _join(prefix, key)
                if not ignore.is_ignored(child_path):
                    out.append(Change(ADDED, child_path, new=current[key]))
        return

    if isinstance(base, list) and isinstance(current, list):
        common = min(len(base), len(current))
        for i in range(common):
            _walk(base[i], current[i], _join(prefix, i), out, ignore)
        # Extra elements in base were removed.
        for i in range(common, len(base)):
            child_path = _join(prefix, i)
            if not ignore.is_ignored(child_path):
                out.append(Change(REMOVED, child_path, old=base[i]))
        # Extra elements in current were added.
        for i in range(common, len(current)):
            child_path = _join(prefix, i)
            if not ignore.is_ignored(child_path):
                out.append(Change(ADDED, child_path, new=current[i]))
        return

    # Leaf (or type-mismatched container) comparison.
    if base != current:
        if not ignore.is_ignored(prefix):
            out.append(Change(CHANGED, prefix, old=base, new=current))


def diff_configs(
    base: Any,
    current: Any,
    ignore: Optional[IgnoreList] = None,
) -> DriftReport:
    """Return a :class:`DriftReport` describing drift from ``base`` to
    ``current``.

    ``ignore`` filters out drift on expected-volatile dotted paths.
    """
    ignore = ignore or IgnoreList()
    changes: List[Change] = []
    _walk(base, current, "", changes, ignore)
    return DriftReport(changes).sorted()
