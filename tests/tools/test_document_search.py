"""Tests for document_search — public document discovery via DDGS dorking."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from fackel.tools.osint.document_search import document_search


def _ddgs(results: list[dict[str, str]]) -> MagicMock:
    mock = MagicMock()
    mock.__enter__ = MagicMock(return_value=mock)
    mock.__exit__ = MagicMock(return_value=False)
    mock.text.return_value = results
    return mock


class TestDocumentSearch:
    @patch("fackel.tools.osint.document_search.DDGS")
    def test_discovers_documents(self, mock_ddgs_cls: MagicMock) -> None:
        mock_ddgs_cls.return_value = _ddgs(
            [
                {"title": "Annual Report", "href": "https://example.com/report.pdf"},
                {"title": "Budget", "href": "https://example.com/budget.xlsx"},
            ]
        )
        result = document_search.invoke({"domain": "example.com"})
        assert result["status"] == "ok"
        data = result["data"]
        assert data["count"] >= 1
        urls = {d["url"] for d in data["documents"]}
        assert "https://example.com/report.pdf" in urls
        assert all("filetype" in d for d in data["documents"])

    @patch("fackel.tools.osint.document_search.DDGS")
    def test_deduplicates_urls(self, mock_ddgs_cls: MagicMock) -> None:
        # Same URL returned for every filetype query — must appear once.
        mock_ddgs_cls.return_value = _ddgs(
            [{"title": "Doc", "href": "https://example.com/dup.pdf"}]
        )
        result = document_search.invoke({"domain": "example.com"})
        urls = [d["url"] for d in result["data"]["documents"]]
        assert urls.count("https://example.com/dup.pdf") == 1

    @patch("fackel.tools.osint.document_search.DDGS")
    def test_skips_results_without_url(self, mock_ddgs_cls: MagicMock) -> None:
        mock_ddgs_cls.return_value = _ddgs([{"title": "No URL", "href": ""}])
        result = document_search.invoke({"domain": "example.com"})
        assert result["status"] == "ok"
        assert result["data"]["count"] == 0

    @patch("fackel.tools.osint.document_search.DDGS", None)
    def test_ddgs_not_installed_returns_error(self) -> None:
        result = document_search.invoke({"domain": "example.com"})
        assert "not installed" in result

    @patch("fackel.tools.osint.document_search.DDGS")
    def test_search_error_returns_error(self, mock_ddgs_cls: MagicMock) -> None:
        mock = MagicMock()
        mock.__enter__ = MagicMock(return_value=mock)
        mock.__exit__ = MagicMock(return_value=False)
        mock.text.side_effect = RuntimeError("rate limited")
        mock_ddgs_cls.return_value = mock
        result = document_search.invoke({"domain": "example.com"})
        assert "rate limited" in result

    def test_rejects_ip(self) -> None:
        result = document_search.invoke({"domain": "1.2.3.4"})
        assert "document_search" in result

    def test_rejects_empty(self) -> None:
        result = document_search.invoke({"domain": ""})
        assert "document_search" in result
