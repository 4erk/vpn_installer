"""Run the test suite from an isolated Python distribution."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    root = str(ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), pattern="test_*.py", top_level_dir=root)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
