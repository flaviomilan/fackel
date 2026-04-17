"""Tests for security headers audit tool."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from fackel.tools.vuln.security_headers import (
    _analyse_csp,
    _analyse_hsts,
    _check_cors_headers,
    security_headers_audit,
)


class TestSecurityHeadersAudit:
    """Verify HTTP security headers audit logic."""

    @pytest.fixture(autouse=True)
    def _http(self):
        """Patch the pooled session's GET and neutralise the DNS-rebinding
        guard so these unit tests never touch the network.

        Exposes the underlying ``get`` mock as ``self.mock_get``.
        """
        with (
            patch("fackel.tools.vuln.security_headers.get_session") as mock_session,
            patch("fackel.tools.vuln.security_headers.guard_request_target"),
        ):
            self.mock_get = mock_session.return_value.get
            yield

    def test_missing_headers_detected(self):
        resp = MagicMock()
        resp.headers = {}
        resp.status_code = 200
        self.mock_get.return_value = resp

        result = security_headers_audit.invoke({"target": "https://example.com"})
        assert result["status"] == "ok"
        findings = result["data"]["findings"]
        missing_headers = [f["header"] for f in findings if f["status"] == "missing"]
        assert "Strict-Transport-Security" in missing_headers
        assert "Content-Security-Policy" in missing_headers
        assert "X-Content-Type-Options" in missing_headers

    def test_all_headers_present(self):
        resp = MagicMock()
        resp.headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Permissions-Policy": "camera=()",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "X-XSS-Protection": "1; mode=block",
        }
        resp.status_code = 200
        self.mock_get.return_value = resp

        result = security_headers_audit.invoke({"target": "https://example.com"})
        assert result["status"] == "ok"
        # Only info-level or no issues expected
        findings = result["data"]["findings"]
        high_findings = [f for f in findings if f.get("severity") in ("high", "critical")]
        assert len(high_findings) == 0

    def test_adds_scheme_when_missing(self):
        resp = MagicMock()
        resp.headers = {}
        resp.status_code = 200
        self.mock_get.return_value = resp

        security_headers_audit.invoke({"target": "example.com"})
        call_url = self.mock_get.call_args[0][0]
        assert call_url.startswith("https://")

    def test_server_disclosure_detected(self):
        resp = MagicMock()
        resp.headers = {"Server": "Apache/2.4.51"}
        resp.status_code = 200
        self.mock_get.return_value = resp

        result = security_headers_audit.invoke({"target": "https://example.com"})
        findings = result["data"]["findings"]
        disclosure = [f for f in findings if f.get("status") == "disclosure"]
        assert len(disclosure) >= 1
        assert "Apache/2.4.51" in disclosure[0]["description"]

    def test_x_powered_by_detected(self):
        resp = MagicMock()
        resp.headers = {"X-Powered-By": "Express"}
        resp.status_code = 200
        self.mock_get.return_value = resp

        result = security_headers_audit.invoke({"target": "https://example.com"})
        findings = result["data"]["findings"]
        powered_by = [f for f in findings if f.get("header") == "X-Powered-By"]
        assert len(powered_by) == 1

    def test_cors_wildcard_with_credentials(self):
        resp = MagicMock()
        resp.headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
        resp.status_code = 200
        self.mock_get.return_value = resp

        result = security_headers_audit.invoke({"target": "https://example.com"})
        findings = result["data"]["findings"]
        cors = [f for f in findings if f.get("header") == "Access-Control-Allow-Origin"]
        assert len(cors) >= 1
        assert cors[0]["severity"] == "high"

    def test_request_exception_returns_error(self):
        self.mock_get.side_effect = requests.RequestException("connection refused")
        result = security_headers_audit.invoke({"target": "https://example.com"})
        assert "connection refused" in str(result)

    def test_connection_error_returns_structured_result(self):
        """Unreachable hosts should return a structured result, not a tool error."""
        self.mock_get.side_effect = requests.ConnectionError("Name or service not known")
        result = security_headers_audit.invoke({"target": "https://noc.eversafe.info"})
        assert result["status"] == "ok"
        assert "unreachable" in result["data"]["message"]
        assert result["data"]["status_code"] is None

    def test_timeout_returns_structured_result(self):
        """Timeout should return a structured result, not a tool error."""
        self.mock_get.side_effect = requests.Timeout("connect timed out")
        result = security_headers_audit.invoke({"target": "https://ehealth.eversafe.info"})
        assert result["status"] == "ok"
        assert "unreachable" in result["data"]["message"]
        assert result["data"]["total_issues"] == 0


class TestAnalyseCsp:
    """Verify CSP deep analysis."""

    def test_unsafe_inline_detected(self):
        warnings = _analyse_csp("default-src 'self'; script-src 'unsafe-inline'")
        types = [w["directive"] for w in warnings]
        assert "unsafe-inline" in types

    def test_unsafe_eval_detected(self):
        warnings = _analyse_csp("default-src 'self'; script-src 'unsafe-eval'")
        types = [w["directive"] for w in warnings]
        assert "unsafe-eval" in types

    def test_wildcard_detected(self):
        warnings = _analyse_csp("default-src *")
        types = [w["directive"] for w in warnings]
        assert "*" in types

    def test_missing_default_src(self):
        warnings = _analyse_csp("style-src 'self'")
        directives = [w["directive"] for w in warnings]
        assert "default-src/script-src" in directives

    def test_good_csp_no_warnings(self):
        warnings = _analyse_csp("default-src 'none'; script-src 'self'; style-src 'self'")
        assert len(warnings) == 0


class TestAnalyseHsts:
    """Verify HSTS deep analysis."""

    def test_short_max_age(self):
        warnings = _analyse_hsts("max-age=3600")
        assert any("max-age" in w["directive"] for w in warnings)

    def test_missing_include_subdomains(self):
        warnings = _analyse_hsts("max-age=31536000")
        assert any("includeSubDomains" in w["directive"] for w in warnings)

    def test_good_hsts_no_max_age_warning(self):
        warnings = _analyse_hsts("max-age=31536000; includeSubDomains")
        max_age_warnings = [w for w in warnings if w["directive"] == "max-age"]
        assert len(max_age_warnings) == 0


class TestCheckCorsHeaders:
    """Verify CORS header checks."""

    def test_wildcard_origin(self):
        warnings = _check_cors_headers({"access-control-allow-origin": "*"})
        assert len(warnings) == 1
        assert warnings[0]["severity"] == "medium"

    def test_wildcard_with_credentials(self):
        warnings = _check_cors_headers(
            {
                "access-control-allow-origin": "*",
                "access-control-allow-credentials": "true",
            }
        )
        assert len(warnings) == 1
        assert warnings[0]["severity"] == "high"

    def test_specific_origin_with_credentials(self):
        warnings = _check_cors_headers(
            {
                "access-control-allow-origin": "https://trusted.com",
                "access-control-allow-credentials": "true",
            }
        )
        assert len(warnings) == 1
        assert warnings[0]["severity"] == "low"

    def test_no_cors_headers(self):
        warnings = _check_cors_headers({})
        assert len(warnings) == 0
