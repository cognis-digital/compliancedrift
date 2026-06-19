"""compliancedrift - configuration/compliance drift detector.

Capture a signed baseline snapshot of configuration, verify its integrity,
and compare current configuration against the baseline to detect drift.

Maintainer: Cognis Digital
License: COCL 1.0
"""

__version__ = "0.1.0"

from .digest import normalize, compute_digest
from .diff import diff_configs, DriftReport, Change
from .ignore import IgnoreList
from .baseline import build_baseline, verify_baseline

__all__ = [
    "__version__",
    "normalize",
    "compute_digest",
    "diff_configs",
    "DriftReport",
    "Change",
    "IgnoreList",
    "build_baseline",
    "verify_baseline",
]
