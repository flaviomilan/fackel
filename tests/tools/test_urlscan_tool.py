"""Tests for urlscan_search tool — HTTP calls mocked via unittest.mock."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests

from fackel.tooling.circuit_breaker import reset_all as reset_circuits
from tools.recon.urlscan_tool import urlscan_search


def _ok_response(json_data: dict, status: int = 200) -> MagicMock:
    """Build a mock requests.Response with JSON payload."""
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status
    resp.json.return_value = json_data
    resp.raise_for_status.return_value = None
    return resp


def _error_response(status: int) -> MagicMock:
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status
    resp.raise_for_status.side_effect = requests.HTTPError(f"{status} Server Error")
    return resp


_SEARCH_RESPONSE = {
    "total": 42,
    "results": [
        {
            "page": {
                "url": "https://example.com/",
                "domain": "example.com",
                "ip": "93.184.216.34",
                "server": "ECS (dcb/7F3C)",
                "asn": "AS15133",
                "asnname": "Edgecast",
                "title": "Example Domain",
                "status": "200",
                "mimeType": "text/html",
                "country": "US",
            },
            "task": {
                "time": "2025-01-15T12:00:00.000Z",
                "visibility": "public",
            },
            "stats": {
                "protocolStats": [
                    {"protocol": "h2"},
                    {"protocol": "TLSv1.3"},
                ],
            },
        },
        {
            "page": {
                "url": "https://www.example.com/page",
                "domain": "www.example.com",
                "ip": "93.184.216.34",
                "server": "nginx",
                "asn": "AS15133",
                "asnname": "Edgecast",
                "title": "Example Page",
                "status": "200",
                "mimeType": "text/html",
                "country": "US",
            },
            "task": {
                "time": "2025-01-10T08:30:00.000Z",
                "visibility": "public",
            },
            "stats": {},
        },
    ],
}


class TestUrlscanSearchHappyPath:
    """Successful Urlscan.io search responses."""

    @patch("tools.recon.urlscan_tool.get_session")
    def test_returns_parsed_results(self, mock_gs: MagicMock) -> None:
        mock_get = mock_gs.return_value.get
        mock_get.return_value = _ok_response(_SEARCH_RESPONSE)

        result = urlscan_search.invoke({"domain": "example.com"})

        assert result["status"] == "ok"
        assert result["tool"] == "urlscan_search"
        data = result["data"]
        assert data["total"] == 42
        assert len(data["results"]) == 2

        first = data["results"][0]
        assert first["url"] == "https://example.com/"
        assert first["ip"] == "93.184.216.34"
        assert first["server"] == "ECS (dcb/7F3C)"
        assert first["asn"] == "AS15133"
        assert first["title"] == "Example Domain"
        assert first["technologies"] == ["h2", "TLSv1.3"]

    @patch("tools.recon.urlscan_tool.get_session")
    def test_passes_correct_query_params(self, mock_gs: MagicMock) -> None:
        mock_get = mock_gs.return_value.get
        mock_get.return_value = _ok_response({"total": 0, "results": []})

        urlscan_search.invoke({"domain": "example.com"})

        call_args = mock_get.call_args
        assert call_args.kwargs["params"]["q"] == "domain:example.com"
        assert call_args.kwargs["params"]["size"] == "10"

    @patch("tools.recon.urlscan_tool.get_session")
    def test_empty_results(self, mock_gs: MagicMock) -> None:
        mock_get = mock_gs.return_value.get
        mock_get.return_value = _ok_response({"total": 0, "results": []})

        result = urlscan_search.invoke({"domain": "example.com"})

        assert result["status"] == "ok"
        assert result["data"]["total"] == 0
        assert result["data"]["results"] == []

    @patch("tools.recon.urlscan_tool.get_session")
    def test_caps_at_max_results(self, mock_gs: MagicMock) -> None:
        """Even if API returns more than 10, we cap at _MAX_RESULTS."""
        mock_get = mock_gs.return_value.get
        many_results = {
            "total": 100,
            "results": [
                {
                    "page": {"url": f"https://example.com/{i}", "domain": "example.com"},
                    "task": {},
                    "stats": {},
                }
                for i in range(15)
            ],
        }
        mock_get.return_value = _ok_response(many_results)

        result = urlscan_search.invoke({"domain": "example.com"})

        assert len(result["data"]["results"]) == 10

    @patch("tools.recon.urlscan_tool.get_session")
    def test_handles_missing_fields_gracefully(self, mock_gs: MagicMock) -> None:
        """Missing fields produce empty strings, not KeyErrors."""
        mock_get = mock_gs.return_value.get
        sparse = {
            "total": 1,
            "results": [{"page": {}, "task": {}, "stats": {}}],
        }
        mock_get.return_value = _ok_response(sparse)

        result = urlscan_search.invoke({"domain": "example.com"})

        assert result["status"] == "ok"
        first = result["data"]["results"][0]
        assert first["url"] == ""
        assert first["ip"] == ""
        assert first["technologies"] == []


class TestUrlscanSearchErrors:
    """Error handling."""

    def setup_method(self) -> None:
        reset_circuits()

    def teardown_method(self) -> None:
        reset_circuits()

    @patch("tools.recon.urlscan_tool.get_session")
    def test_http_error(self, mock_gs: MagicMock) -> None:
        mock_get = mock_gs.return_value.get
        mock_get.side_effect = requests.HTTPError("429 Too Many Requests")

        result = urlscan_search.invoke({"domain": "example.com"})

        assert isinstance(result, str)
        assert "429" in result

    @patch("tools.recon.urlscan_tool.get_session")
    def test_connection_error(self, mock_gs: MagicMock) -> None:
        mock_get = mock_gs.return_value.get
        mock_get.side_effect = requests.ConnectionError("Connection refused")

        result = urlscan_search.invoke({"domain": "example.com"})

        assert isinstance(result, str)
        assert "Connection refused" in result

    @patch("tools.recon.urlscan_tool.get_session")
    def test_non_json_response(self, mock_gs: MagicMock) -> None:
        mock_get = mock_gs.return_value.get
        resp = MagicMock(spec=requests.Response)
        resp.raise_for_status.return_value = None
        resp.json.side_effect = ValueError("No JSON")
        mock_get.return_value = resp

        result = urlscan_search.invoke({"domain": "example.com"})

        assert isinstance(result, str)
        assert "non-json" in result.lower()


class TestUrlscanSearchValidation:
    """Input validation via guard_target."""

    def test_rejects_ip_address(self) -> None:
        result = urlscan_search.invoke({"domain": "1.2.3.4"})
        assert isinstance(result, str)

    def test_rejects_empty_domain(self) -> None:
        result = urlscan_search.invoke({"domain": ""})
        assert isinstance(result, str)

    def test_rejects_shell_metacharacters(self) -> None:
        result = urlscan_search.invoke({"domain": "example.com; rm -rf /"})
        assert isinstance(result, str)
