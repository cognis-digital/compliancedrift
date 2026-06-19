"""Deterministic normalization + sha256 digest of configuration data.

The digest must be stable regardless of key ordering or insignificant
whitespace in the source JSON, so that a baseline captured today verifies
against the same logical config tomorrow.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def normalize(config: Any) -> Any:
    """Return a canonical form of ``config``.

    Dicts are recursively reproduced with their keys sorted so that two
    semantically identical configs serialize identically. Lists preserve
    order (order is significant for sequences). Scalars pass through.
    """
    if isinstance(config, dict):
        return {key: normalize(config[key]) for key in sorted(config.keys())}
    if isinstance(config, list):
        return [normalize(item) for item in config]
    return config


def canonical_json(config: Any) -> str:
    """Serialize ``config`` to a canonical JSON string.

    Keys are sorted, separators are compact and deterministic, and
    ``ensure_ascii`` is enabled so the byte representation is stable across
    platforms and locales.
    """
    return json.dumps(
        normalize(config),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def compute_digest(config: Any) -> str:
    """Return the sha256 hex digest of the canonical form of ``config``."""
    payload = canonical_json(config).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
