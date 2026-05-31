"""Tests for OSINT tools — email_analyzer and job_search."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from fackel.tools.osint.email_analyzer import (
    _check_breaches,
    _check_reputation,
    analyze_email,
)
from fackel.tools.osint.job_search import job_search


class TestCheckBreaches:
    """Verify HIBP breach checking."""

    def test_no_api_key_returns_empty(self, monkeypatch):
        monkeypatch.delenv("HIBP_API_KEY", raising=False)
        result = _check_breaches("test@example.com")
        assert result == []

    @patch("fackel.tools.osint.email_analyzer.get_session")
    def test_with_api_key_returns_breaches(self, mock_session, monkeypatch):
        monkeypatch.setenv("HIBP_API_KEY", "test-key")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"Name": "Breach1"}]
        mock_session.return_value.get.return_value = mock_resp

        result = _check_breaches("test@example.com")
        assert len(result) == 1

    @patch("fackel.tools.osint.email_analyzer.get_session")
    def test_api_error_returns_empty(self, mock_session, monkeypatch):
        monkeypatch.setenv("HIBP_API_KEY", "test-key")
        mock_session.return_value.get.side_effect = Exception("timeout")

        result = _check_breaches("test@example.com")
        assert result == []


class TestCheckReputation:
    """Verify EmailRep reputation checking."""

    def test_no_api_key_returns_none(self, monkeypatch):
        monkeypatch.delenv("EMAILREP_API_KEY", raising=False)
        result = _check_reputation("test@example.com")
        assert result is None

    @patch("fackel.tools.osint.email_analyzer.get_session")
    def test_with_api_key_returns_data(self, mock_session, monkeypatch):
        monkeypatch.setenv("EMAILREP_API_KEY", "test-key")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"reputation": "high", "suspicious": False}
        mock_session.return_value.get.return_value = mock_resp

        result = _check_reputation("test@example.com")
        assert result is not None
        assert result["reputation"] == "high"


class TestAnalyzeEmail:
    """Verify the full tool function."""

    def test_invalid_email_returns_error(self):
        result = analyze_email.invoke({"email": "not-an-email"})
        assert "invalid email" in result

    @patch("fackel.tools.osint.email_analyzer._check_reputation", return_value=None)
    @patch("fackel.tools.osint.email_analyzer._check_breaches", return_value=[])
    def test_valid_email_returns_ok(self, _breaches, _rep):
        result = analyze_email.invoke({"email": "test@example.com"})
        assert result["status"] == "ok"
        assert result["data"]["breaches"] == []

    @patch(
        "fackel.tools.osint.email_analyzer._check_reputation", return_value={"reputation": "high"}
    )
    @patch("fackel.tools.osint.email_analyzer._check_breaches", return_value=[{"Name": "Breach1"}])
    def test_aggregates_results(self, _breaches, _rep):
        result = analyze_email.invoke({"email": "test@example.com"})
        assert len(result["data"]["breaches"]) == 1
        assert result["data"]["reputation"]["reputation"] == "high"


class TestJobSearch:
    """Verify job posting search tool."""

    def test_empty_company_returns_error(self):
        result = job_search.invoke({"company_name": ""})
        assert "empty" in result

    @patch("fackel.tools.osint.job_search.DDGS")
    def test_returns_job_posts(self, mock_ddgs_cls):
        mock_ddgs = MagicMock()
        mock_ddgs.__enter__ = MagicMock(return_value=mock_ddgs)
        mock_ddgs.__exit__ = MagicMock(return_value=False)
        mock_ddgs.text.return_value = [
            {
                "title": "Backend Engineer",
                "body": "Python, AWS, Docker",
                "href": "https://linkedin.com/jobs/123",
            },
        ]
        mock_ddgs_cls.return_value = mock_ddgs

        result = job_search.invoke({"company_name": "Acme Corp"})
        assert result["status"] == "ok"
        assert len(result["data"]["results"]) >= 1

    @patch("fackel.tools.osint.job_search.DDGS", None)
    def test_ddgs_not_installed_returns_error(self):
        result = job_search.invoke({"company_name": "Acme Corp"})
        assert "not installed" in result

    @patch("fackel.tools.osint.job_search.DDGS")
    def test_search_error_returns_error(self, mock_ddgs_cls):
        mock_ddgs = MagicMock()
        mock_ddgs.__enter__ = MagicMock(return_value=mock_ddgs)
        mock_ddgs.__exit__ = MagicMock(return_value=False)
        mock_ddgs.text.side_effect = RuntimeError("rate limited")
        mock_ddgs_cls.return_value = mock_ddgs

        result = job_search.invoke({"company_name": "Acme Corp"})
        assert "rate limited" in result
