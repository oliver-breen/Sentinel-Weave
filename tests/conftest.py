"""
pytest configuration for the SentinelWeave test suite.

Ensures the project root is on sys.path so that `sentinel_weave`,
`dashboard`, and `quantaweave` packages are always importable regardless
of how pytest is invoked (e.g. from a venv without the package installed).
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add the repository root to sys.path so test modules can import the project
# packages directly without requiring `pip install -e .`
_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
