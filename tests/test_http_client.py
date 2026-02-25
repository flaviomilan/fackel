"""Tests for http_client module — shared session and retry configuration."""

from __future__ import annotations

from tools.http_client import get_session


class TestGetSession:
    """Verify shared session behaviour."""

    def test_returns_session_instance(self):
        import tools.http_client as mod

        # Reset module state for clean test
        mod._session = None
        session = get_session()
        assert session is not None

    def test_returns_same_instance(self):
        import tools.http_client as mod

        mod._session = None
        s1 = get_session()
        s2 = get_session()
        assert s1 is s2

    def test_has_user_agent_header(self):
        import tools.http_client as mod

        mod._session = None
        session = get_session()
        assert "User-Agent" in session.headers
        assert "fackel" in session.headers["User-Agent"]

    def test_has_retry_adapter_mounted(self):
        import tools.http_client as mod

        mod._session = None
        session = get_session()
        assert "https://" in session.adapters
        assert "http://" in session.adapters
