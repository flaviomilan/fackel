"""Tests for JavaScript secret scanner tool."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from fackel.tools.osint.js_secret_scanner import (
    _extract_script_urls,
    _scan_content,
    js_secret_scan,
)


class TestJsSecretScan:
    """Verify JS secret scanner logic."""

    @pytest.fixture(autouse=True)
    def _http(self):
        """Patch the pooled session's GET and neutralise the DNS-rebinding
        guard so these unit tests never touch the network.

        Exposes the underlying ``get`` mock as ``self.mock_get``.
        """
        with (
            patch("fackel.tools.osint.js_secret_scanner.get_session") as mock_session,
            patch("fackel.tools.osint.js_secret_scanner.guard_request_target"),
        ):
            self.mock_get = mock_session.return_value.get
            yield

    def test_scan_direct_js_file(self):
        resp = MagicMock()
        aws_key = "AKIA" + "IOSFODNN7EXAMPLE1"
        resp.text = f"var apiKey = '{aws_key}';"
        resp.status_code = 200
        resp.raise_for_status = MagicMock()
        self.mock_get.return_value = resp

        result = js_secret_scan.invoke({"target": "https://example.com/app.js"})
        assert result["status"] == "ok"
        assert result["data"]["total"] >= 1
        types = [f["type"] for f in result["data"]["findings"]]
        assert "aws_access_key" in types

    def test_scan_html_page_with_scripts(self):
        html = (
            """
        <html>
        <script src="/static/app.js"></script>
        <script>var secret = '"""
            + ("ghp_" + "abc123def456ghi789jkl012mno345pq6789")
            + """';</script>
        </html>
        """
        )
        js_content = "var key = 'nothing-secret-here';"

        def get_side_effect(url, **kwargs):
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            if url.endswith(".js"):
                resp.text = js_content
            else:
                resp.text = html
            resp.status_code = 200
            return resp

        self.mock_get.side_effect = get_side_effect

        result = js_secret_scan.invoke({"target": "https://example.com"})
        assert result["status"] == "ok"
        # Should find the GitHub token in inline script
        types = [f["type"] for f in result["data"]["findings"]]
        assert "github_token" in types

    def test_adds_scheme_when_missing(self):
        resp = MagicMock()
        resp.text = "var x = 1;"
        resp.status_code = 200
        resp.raise_for_status = MagicMock()
        self.mock_get.return_value = resp

        js_secret_scan.invoke({"target": "example.com/app.js"})
        call_url = self.mock_get.call_args[0][0]
        assert call_url.startswith("https://")

    def test_no_secrets_found(self):
        resp = MagicMock()
        resp.text = "console.log('hello world');"
        resp.status_code = 200
        resp.raise_for_status = MagicMock()
        self.mock_get.return_value = resp

        result = js_secret_scan.invoke({"target": "https://example.com/clean.js"})
        assert result["status"] == "ok"
        assert result["data"]["total"] == 0
        assert "no secrets" in result["data"]["message"]

    def test_fetch_failure_returns_error(self):
        self.mock_get.side_effect = requests.RequestException("connection refused")
        result = js_secret_scan.invoke({"target": "https://example.com/app.js"})
        assert "failed to fetch" in str(result)


class TestExtractScriptUrls:
    """Verify script URL extraction from HTML."""

    def test_extracts_relative_urls(self):
        html = '<script src="/static/app.js"></script>'
        urls = _extract_script_urls(html, "https://example.com")
        assert "https://example.com/static/app.js" in urls

    def test_extracts_absolute_urls(self):
        html = '<script src="https://cdn.example.com/lib.js"></script>'
        urls = _extract_script_urls(html, "https://example.com")
        assert "https://cdn.example.com/lib.js" in urls

    def test_ignores_data_urls(self):
        html = '<script src="data:text/javascript,alert(1)"></script>'
        urls = _extract_script_urls(html, "https://example.com")
        assert len(urls) == 0

    def test_multiple_scripts(self):
        html = """
        <script src="/a.js"></script>
        <script src="/b.js"></script>
        <script src="/c.js"></script>
        """
        urls = _extract_script_urls(html, "https://example.com")
        assert len(urls) == 3


class TestScanContent:
    """Verify regex-based secret scanning."""

    def test_detects_aws_key(self):
        aws_key = "AKIA" + "IOSFODNN7EXAMPLE1"
        content = f"const key = '{aws_key}';"
        results = _scan_content(content, "test.js")
        types = [r["type"] for r in results]
        assert "aws_access_key" in types

    def test_detects_github_token(self):
        github_token = "ghp_" + "abc123def456ghi789jkl012mno345pq6789"
        content = f"token = '{github_token}'"
        results = _scan_content(content, "test.js")
        types = [r["type"] for r in results]
        assert "github_token" in types

    def test_detects_jwt(self):
        content = "var jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456'"
        results = _scan_content(content, "test.js")
        types = [r["type"] for r in results]
        assert "jwt_token" in types

    def test_detects_stripe_key(self):
        stripe_key = "sk_" + "live_" + "abc123def456ghi789jklmnop"
        content = f"const stripe = '{stripe_key}'"
        results = _scan_content(content, "test.js")
        types = [r["type"] for r in results]
        assert "stripe_secret" in types

    def test_detects_private_key(self):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK..."
        results = _scan_content(content, "test.js")
        types = [r["type"] for r in results]
        assert "private_key" in types

    def test_detects_internal_ip(self):
        content = "const api = 'http://192.168.1.100:8080/api';"
        results = _scan_content(content, "test.js")
        types = [r["type"] for r in results]
        assert "internal_ip" in types

    def test_no_secrets_in_clean_content(self):
        content = "function add(a, b) { return a + b; }"
        results = _scan_content(content, "test.js")
        assert len(results) == 0

    def test_deduplicates_same_match(self):
        aws_key = "AKIA" + "IOSFODNN7EXAMPLE1"
        content = f"{aws_key} {aws_key}"
        results = _scan_content(content, "test.js")
        aws_keys = [r for r in results if r["type"] == "aws_access_key"]
        assert len(aws_keys) == 1

    def test_line_number_reported(self):
        aws_key = "AKIA" + "IOSFODNN7EXAMPLE1"
        content = f"line1\nline2\n{aws_key}"
        results = _scan_content(content, "test.js")
        assert results[0]["line"] == 3
