"""Tests for dnsdumpster_lookup — subdomain enumeration via DNSDumpster."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from tools.recon.dnsdumpster_tool import dnsdumpster_lookup

_HOST_HTML = """
<table>
<tr><th>Domain</th><th>IP</th></tr>
</table>
<table>
<tr><td>sub.example.com</td><td>93.184.216.34</td><td>AS1234</td><td>CloudProvider</td></tr>
<tr><td>mail.example.com</td><td>93.184.216.35</td><td>AS1234</td><td>CloudProvider</td></tr>
</table>
<table>
<tr><td>mx1.example.com | 10</td></tr>
</table>
<table>
<tr><td>ns1.example.com</td></tr>
</table>
<table>
<tr><td>v=spf1 include:example.com</td></tr>
</table>
"""


class TestDnsDumpsterLookup:
    """Verify DNSDumpster JWT auth + HTML parsing."""

    @patch("tools.recon.dnsdumpster_tool.circuit_breaker")
    @patch("tools.recon.dnsdumpster_tool.get_session")
    def test_parses_host_table(self, mock_session, mock_cb):
        mock_cb.return_value.__enter__ = MagicMock()
        mock_cb.return_value.__exit__ = MagicMock(return_value=False)

        session = MagicMock()
        mock_session.return_value = session

        # JWT fetch response
        jwt_resp = MagicMock()
        jwt_resp.raise_for_status = MagicMock()
        jwt_resp.text = '"Authorization": "eyJhbGciOiJIUzI1NiJ9.test.sig"'

        # API response with HTML tables
        api_resp = MagicMock()
        api_resp.raise_for_status = MagicMock()
        api_resp.text = _HOST_HTML

        session.get.return_value = jwt_resp
        session.post.return_value = api_resp

        result = dnsdumpster_lookup.invoke({"domain": "example.com"})

        assert result["status"] == "ok"
        hosts = result["data"]["hosts"]
        assert len(hosts) == 2
        assert hosts[0]["hostname"] == "sub.example.com"
        assert hosts[0]["ip"] == "93.184.216.34"
        assert hosts[0]["provider"] == "CloudProvider"

    @patch("tools.recon.dnsdumpster_tool.circuit_breaker")
    @patch("tools.recon.dnsdumpster_tool.get_session")
    def test_empty_tables(self, mock_session, mock_cb):
        mock_cb.return_value.__enter__ = MagicMock()
        mock_cb.return_value.__exit__ = MagicMock(return_value=False)

        session = MagicMock()
        mock_session.return_value = session

        jwt_resp = MagicMock()
        jwt_resp.raise_for_status = MagicMock()
        jwt_resp.text = '"Authorization": "eyJhbGciOiJIUzI1NiJ9.x.y"'

        api_resp = MagicMock()
        api_resp.raise_for_status = MagicMock()
        api_resp.text = "<html><body>No tables</body></html>"

        session.get.return_value = jwt_resp
        session.post.return_value = api_resp

        result = dnsdumpster_lookup.invoke({"domain": "empty.example.com"})

        assert result["status"] == "ok"
        assert result["data"]["hosts"] == []

    @patch("tools.recon.dnsdumpster_tool.circuit_breaker")
    @patch("tools.recon.dnsdumpster_tool.get_session")
    def test_jwt_fetch_failure(self, mock_session, mock_cb):
        mock_cb.return_value.__enter__ = MagicMock()
        mock_cb.return_value.__exit__ = MagicMock(return_value=False)

        session = MagicMock()
        mock_session.return_value = session

        jwt_resp = MagicMock()
        jwt_resp.raise_for_status = MagicMock()
        jwt_resp.text = "<html>No JWT here</html>"

        session.get.return_value = jwt_resp

        result = dnsdumpster_lookup.invoke({"domain": "example.com"})
        assert "failed to obtain auth token" in result.lower()

    @patch("tools.recon.dnsdumpster_tool.circuit_breaker")
    @patch("tools.recon.dnsdumpster_tool.get_session")
    def test_mx_and_txt_records_parsed(self, mock_session, mock_cb):
        mock_cb.return_value.__enter__ = MagicMock()
        mock_cb.return_value.__exit__ = MagicMock(return_value=False)

        session = MagicMock()
        mock_session.return_value = session

        jwt_resp = MagicMock()
        jwt_resp.raise_for_status = MagicMock()
        jwt_resp.text = '"Authorization": "eyJhbGciOiJIUzI1NiJ9.t.s"'

        api_resp = MagicMock()
        api_resp.raise_for_status = MagicMock()
        api_resp.text = _HOST_HTML

        session.get.return_value = jwt_resp
        session.post.return_value = api_resp

        result = dnsdumpster_lookup.invoke({"domain": "example.com"})

        assert len(result["data"]["mx_records"]) >= 1
        assert len(result["data"]["txt_records"]) >= 1
