"""Baseline capture and integrity verification.

A baseline file is a JSON document with this shape::

    {
      "compliancedrift_baseline": "1",
      "algorithm": "sha256",
      "digest": "<hex>",
      "config": { ... captured configuration ... }
    }

The ``digest`` is computed over the canonical (normalized, key-sorted) form
of ``config``. :func:`verify_baseline` recomputes it to detect tampering.
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

from .digest import compute_digest

BASELINE_MARKER = "compliancedrift_baseline"
SCHEMA_VERSION = "1"
ALGORITHM = "sha256"


def build_baseline(config: Any) -> Dict[str, Any]:
    """Wrap ``config`` in a baseline envelope with an embedded digest."""
    return {
        BASELINE_MARKER: SCHEMA_VERSION,
        "algorithm": ALGORITHM,
        "digest": compute_digest(config),
        "config": config,
    }


def is_baseline(doc: Any) -> bool:
    return isinstance(doc, dict) and BASELINE_MARKER in doc and "config" in doc


def extract_config(doc: Any) -> Any:
    """Return the captured config from a baseline envelope, or ``doc`` itself
    if it is a plain config document (so ``diff`` accepts both forms)."""
    if is_baseline(doc):
        return doc["config"]
    return doc


def verify_baseline(doc: Dict[str, Any]) -> Tuple[bool, str, str]:
    """Verify a baseline envelope's integrity.

    Returns ``(ok, expected_digest, actual_digest)``. ``ok`` is True when the
    stored digest matches a freshly computed digest of the embedded config.
    Raises :class:`ValueError` if ``doc`` is not a baseline envelope.
    """
    if not is_baseline(doc):
        raise ValueError("document is not a compliancedrift baseline")
    algorithm = doc.get("algorithm", ALGORITHM)
    if algorithm != ALGORITHM:
        raise ValueError(f"unsupported digest algorithm: {algorithm!r}")
    expected = doc.get("digest", "")
    actual = compute_digest(doc["config"])
    return (expected == actual, expected, actual)
