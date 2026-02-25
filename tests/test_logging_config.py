"""Tests for logging_config module."""

from __future__ import annotations

import json
import logging

from fackel.logging_config import _JSONFormatter, configure_logging


class TestJSONFormatter:
    """Verify JSON log formatter output."""

    def test_formats_valid_json(self):
        formatter = _JSONFormatter()
        record = logging.LogRecord(
            name="fackel.test",
            level=logging.WARNING,
            pathname="test.py",
            lineno=1,
            msg="something happened",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["level"] == "WARNING"
        assert parsed["logger"] == "fackel.test"
        assert parsed["message"] == "something happened"
        assert "ts" in parsed

    def test_includes_exception_info(self):
        formatter = _JSONFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            import sys

            exc_info = sys.exc_info()

        record = logging.LogRecord(
            name="fackel.test",
            level=logging.ERROR,
            pathname="test.py",
            lineno=1,
            msg="error occurred",
            args=(),
            exc_info=exc_info,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "exception" in parsed
        assert "ValueError" in parsed["exception"]


class TestConfigureLogging:
    """Verify logging configuration."""

    def test_default_text_format(self, monkeypatch):
        monkeypatch.delenv("FACKEL_LOG_FORMAT", raising=False)
        configure_logging(verbose=False)
        root = logging.getLogger()
        assert len(root.handlers) == 1
        assert root.level == logging.WARNING

    def test_verbose_enables_debug(self, monkeypatch):
        monkeypatch.delenv("FACKEL_LOG_FORMAT", raising=False)
        configure_logging(verbose=True)
        fackel_logger = logging.getLogger("fackel")
        assert fackel_logger.level == logging.DEBUG

    def test_json_format(self, monkeypatch):
        monkeypatch.setenv("FACKEL_LOG_FORMAT", "json")
        configure_logging(verbose=False)
        root = logging.getLogger()
        assert isinstance(root.handlers[0].formatter, _JSONFormatter)

    def test_clears_existing_handlers(self, monkeypatch):
        monkeypatch.delenv("FACKEL_LOG_FORMAT", raising=False)
        root = logging.getLogger()
        root.addHandler(logging.StreamHandler())
        root.addHandler(logging.StreamHandler())
        configure_logging(verbose=False)
        assert len(root.handlers) == 1
