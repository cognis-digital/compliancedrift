"""Path-ignore matching for expected-volatile configuration keys.

Patterns are matched against dotted paths (e.g. ``database.password`` or
``servers.0.last_seen``). Glob-style wildcards are supported:

    *   matches a run of characters within a single path segment
    **  matches across path segments (any depth, including zero)
    ?   matches a single character

A plain pattern with no wildcards matches a path exactly, or matches any path
nested beneath it (so ``metadata`` also ignores ``metadata.timestamp``).
A single-level wildcard pattern likewise covers paths nested below a match
(so ``servers.*`` ignores ``servers.0.host``).
"""

from __future__ import annotations

from typing import Iterable, List


def _segment_match(pattern: str, text: str) -> bool:
    """Glob match within a single path segment using ``*`` and ``?``.

    ``*`` here never crosses a ``.`` separator.
    """
    pi = ti = 0
    star_pi = star_ti = -1
    while ti < len(text):
        if pi < len(pattern) and (pattern[pi] == "?" or pattern[pi] == text[ti]):
            if text[ti] == ".":
                # '?' must not match a separator; only a literal '.' may.
                if pattern[pi] != ".":
                    return False
            pi += 1
            ti += 1
        elif pi < len(pattern) and pattern[pi] == "*":
            star_pi = pi
            star_ti = ti
            pi += 1
        elif star_pi != -1:
            if text[star_ti] == ".":
                return False
            star_ti += 1
            ti = star_ti
            pi = star_pi + 1
        else:
            return False
    while pi < len(pattern) and pattern[pi] == "*":
        pi += 1
    return pi == len(pattern)


def _glob_segments(pattern: str, path: str) -> bool:
    """Match a dotted pattern against a dotted path, segment by segment."""
    p_segs = pattern.split(".")
    t_segs = path.split(".")
    if len(p_segs) != len(t_segs):
        return False
    return all(_segment_match(p, t) for p, t in zip(p_segs, t_segs))


def _double_star_match(pattern: str, path: str) -> bool:
    """Match a pattern containing ``**`` against a dotted path.

    ``**`` matches zero or more whole segments.
    """
    parts = pattern.split("**")
    return _double_star_recurse(parts, path)


def _double_star_recurse(parts: List[str], path: str) -> bool:
    if len(parts) == 1:
        piece = parts[0].strip(".")
        if piece == "":
            return True
        return _glob_segments(piece, path)

    head = parts[0].strip(".")
    rest = parts[1:]
    segments = path.split(".") if path else []

    if head:
        hlen = head.count(".") + 1
        if hlen > len(segments):
            return False
        if not _glob_segments(head, ".".join(segments[:hlen])):
            return False
        rem_segments = segments[hlen:]
    else:
        rem_segments = segments

    # Try every split point for this '**'.
    for i in range(len(rem_segments) + 1):
        if _double_star_recurse(rest, ".".join(rem_segments[i:])):
            return True
    return False


def _match_pattern(pattern: str, path: str) -> bool:
    """Return True if ``path`` is ignored by ``pattern``."""
    if "**" in pattern:
        return _double_star_match(pattern, path)

    has_wildcard = any(ch in pattern for ch in "*?")
    if not has_wildcard:
        return path == pattern or path.startswith(pattern + ".")

    # Single-level wildcard: exact match, or prefix match at a segment
    # boundary so that ``servers.*`` also covers ``servers.0.host``.
    if _glob_segments(pattern, path):
        return True
    depth = pattern.count(".") + 1
    segs = path.split(".")
    if depth < len(segs):
        prefix = ".".join(segs[:depth])
        if _glob_segments(pattern, prefix):
            return True
    return False


class IgnoreList:
    """A collection of ignore patterns applied to dotted paths."""

    def __init__(self, patterns: Iterable[str] | None = None) -> None:
        self.patterns: List[str] = [p.strip() for p in (patterns or []) if p.strip()]

    def add(self, pattern: str) -> None:
        pattern = pattern.strip()
        if pattern:
            self.patterns.append(pattern)

    def is_ignored(self, path: str) -> bool:
        return any(_match_pattern(p, path) for p in self.patterns)

    @classmethod
    def from_file(cls, fp) -> "IgnoreList":
        """Load patterns from a file object, one per line.

        Blank lines and ``#`` comments are skipped.
        """
        patterns: List[str] = []
        for line in fp:
            line = line.split("#", 1)[0].strip()
            if line:
                patterns.append(line)
        return cls(patterns)

    def __len__(self) -> int:
        return len(self.patterns)
