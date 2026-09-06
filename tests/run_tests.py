"""Run the test suite from an isolated Python distribution."""

from __future__ import annotations

import sys
import json
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RecordedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executed = []

    def startTest(self, test):
        self.executed.append(test.id())
        super().startTest(test)

    def wasSuccessful(self):
        return self.testsRun > 0 and super().wasSuccessful()


def main(report_path: Path | None = None) -> int:
    root = str(ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), pattern="test_*.py", top_level_dir=root)
    started = time.monotonic()
    result = unittest.TextTestRunner(verbosity=1, resultclass=RecordedResult).run(suite)
    if report_path is not None:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps({
            "tests_run": result.testsRun,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "successful": result.wasSuccessful(),
            "executed": result.executed,
            "skipped": [{"test": test.id(), "reason": reason} for test, reason in result.skipped],
            "failures": [test.id() for test, _trace in result.failures],
            "errors": [test.id() for test, _trace in result.errors],
            "expected_failures": [test.id() for test, _trace in result.expectedFailures],
            "unexpected_successes": [test.id() for test in result.unexpectedSuccesses],
        }, indent=2) + "\n", encoding="utf-8")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
