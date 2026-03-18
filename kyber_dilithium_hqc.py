"""Deprecated compatibility stub for ML-KEM/ML-DSA bridge imports."""

import warnings

from mlkem_mldsa_bridge import *  # noqa: F403

warnings.warn(
    "kyber_dilithium_hqc.py is deprecated. Use mlkem_mldsa_bridge.py instead.",
    DeprecationWarning,
    stacklevel=2,
)
