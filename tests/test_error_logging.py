from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_installer import error_logging


class ErrorLoggingTests(unittest.TestCase):
    def test_log_exception_writes_archived_and_latest_logs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp) / "out" / "logs" / "runtime"
            latest = log_dir / "latest-error.log"
            with patch.object(error_logging, "ERROR_LOG_DIR", log_dir), patch.object(error_logging, "LATEST_ERROR_LOG", latest):
                try:
                    raise RuntimeError("boom")
                except RuntimeError as exc:
                    archived = error_logging.log_exception("unit.test", exc, argv=["install"], extra={"role": "ru-gateway"})
            self.assertIsNotNone(archived)
            assert archived is not None
            self.assertTrue(archived.is_file())
            self.assertTrue(latest.is_file())
            content = latest.read_text(encoding="utf-8")
            self.assertIn("context: unit.test", content)
            self.assertIn("exception: boom", content)
            self.assertIn('argv: ["install"]', content)
            self.assertIn("role: ru-gateway", content)
            self.assertIn("traceback:", content)


if __name__ == "__main__":
    unittest.main()
