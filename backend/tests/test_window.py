"""Tests for the window-string parser."""

from datetime import timedelta

import pytest

from backend.analytics.window import parse_window


class TestParseWindow:
    def test_seconds(self):
        assert parse_window("30s") == timedelta(seconds=30)

    def test_minutes(self):
        assert parse_window("5m") == timedelta(minutes=5)

    def test_hours(self):
        assert parse_window("1h") == timedelta(hours=1)

    def test_days(self):
        assert parse_window("7d") == timedelta(days=7)

    def test_strips_whitespace(self):
        assert parse_window(" 10m ") == timedelta(minutes=10)

    def test_case_insensitive(self):
        assert parse_window("5M") == timedelta(minutes=5)

    def test_invalid_format_raises(self):
        with pytest.raises(ValueError, match="Invalid window format"):
            parse_window("abc")

    def test_invalid_unit_raises(self):
        with pytest.raises(ValueError, match="Invalid window format"):
            parse_window("5w")

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="Invalid window format"):
            parse_window("")
