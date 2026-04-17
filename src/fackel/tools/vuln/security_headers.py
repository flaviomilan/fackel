"""Security headers audit — pure-Python HTTP header analysis.

Fetches response headers from a target URL and evaluates the presence
and correctness of security-related headers: Strict-Transport-Security,
Content-Security-Policy, X-Content-Type-Options, X-Frame-Options,
Permissions-Policy, Referrer-Policy, and CORS configuration.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import requests
from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import (
    TargetType,
    ensure_scheme,
    format_tool_output,
    get_tool_timeout,
    guard_request_target,
    guard_target,
)
from fackel.tooling.http_client import get_session

_TIMEOUT = 30

# Headers to audit and their expected properties.
_SECURITY_HEADERS: dict[str, dict[str, Any]] = {
    "Strict-Transport-Security": {
        "severity": "high",
        "description": "Prevents protocol downgrade and cookie hijacking via HSTS.",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
    },
    "Content-Security-Policy": {
        "severity": "high",
        "description": "Mitigates XSS, clickjacking, and injection attacks.",
        "recommendation": "Define a strict CSP policy. Avoid 'unsafe-inline' and 'unsafe-eval'.",
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "description": "Prevents MIME-type sniffing attacks.",
        "recommendation": "Add 'X-Content-Type-Options: nosniff'.",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "Prevents clickjacking by disallowing framing.",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'.",
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Controls browser features (camera, microphone, geolocation).",
        "recommendation": "Add 'Permissions-Policy' with restrictive directives.",
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Controls how much referrer information is sent.",
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'.",
    },
    "X-XSS-Protection": {
        "severity": "info",
        "description": "Legacy XSS filter (deprecated in modern browsers).",
        "recommendation": "Prefer CSP over X-XSS-Protection. If set, use '1; mode=block'.",
    },
}

# CSP directives that weaken the policy significantly.
_WEAK_CSP_DIRECTIVES: list[str] = [
    "unsafe-inline",
    "unsafe-eval",
    "data:",
    "*",
]


class SecurityHeadersInput(BaseModel):
    """Input for security headers audit."""

    target: str = Field(
        description=(
            "URL to audit for security headers "
            "(e.g. 'https://example.com'). Must be reachable via HTTP(S). "
            "The tool makes a single GET request and analyses response headers."
        ),
    )


def _analyse_csp(value: str) -> list[dict[str, str]]:
    """Return warnings for weak CSP directives."""
    warnings: list[dict[str, str]] = []
    lower = value.lower()
    for weak in _WEAK_CSP_DIRECTIVES:
        if weak in lower:
            warnings.append(
                {
                    "directive": weak,
                    "severity": "high" if weak in ("unsafe-inline", "unsafe-eval") else "medium",
                    "message": f"CSP contains '{weak}' which weakens the policy.",
                }
            )
    if "default-src" not in lower and "script-src" not in lower:
        warnings.append(
            {
                "directive": "default-src/script-src",
                "severity": "medium",
                "message": "CSP missing 'default-src' or 'script-src' directive.",
            }
        )
    return warnings


def _analyse_hsts(value: str) -> list[dict[str, str]]:
    """Return warnings for weak HSTS configuration."""
    warnings: list[dict[str, str]] = []
    lower = value.lower()
    if "max-age" in lower:
        try:
            max_age_str = lower.split("max-age=")[1].split(";")[0].strip()
            max_age = int(max_age_str)
            if max_age < 31536000:
                warnings.append(
                    {
                        "directive": "max-age",
                        "severity": "medium",
                        "message": f"HSTS max-age is {max_age}s (< 1 year). Recommended: 31536000.",
                    }
                )
        except (IndexError, ValueError):
            pass
    if "includesubdomains" not in lower:
        warnings.append(
            {
                "directive": "includeSubDomains",
                "severity": "low",
                "message": "HSTS missing 'includeSubDomains' directive.",
            }
        )
    return warnings


def _check_cors_headers(headers: dict[str, str]) -> list[dict[str, str]]:
    """Check for dangerous CORS header combinations."""
    warnings: list[dict[str, str]] = []
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()
    if acao == "*":
        sev = "high" if acac == "true" else "medium"
        msg = "CORS allows all origins"
        if acac == "true":
            msg += " WITH credentials — critical data theft risk"
        warnings.append({"directive": "CORS", "severity": sev, "message": msg})
    elif acao and acac == "true":
        warnings.append(
            {
                "directive": "CORS",
                "severity": "low",
                "message": f"CORS allows credentials for origin '{acao}'. Verify trust.",
            }
        )
    return warnings


@tool(args_schema=SecurityHeadersInput)
def security_headers_audit(target: str) -> dict[str, Any]:
    """Audit HTTP security headers of a web target.

    Makes a single GET request and evaluates response headers for missing
    or misconfigured security controls: HSTS, CSP, X-Content-Type-Options,
    X-Frame-Options, Permissions-Policy, Referrer-Policy, and CORS.
    Returns actionable findings with severity and remediation guidance.
    """
    target = guard_target(target, "security_headers_audit", TargetType.HOST_OR_URL)

    target = ensure_scheme(target)

    timeout = get_tool_timeout("security_headers_audit", _TIMEOUT)

    # Guard the connect-to-target host against DNS rebinding to private IPs.
    guard_request_target(target, "security_headers_audit")

    try:
        resp = get_session().get(
            target,
            timeout=timeout,
            allow_redirects=True,
            verify=True,
            headers={"User-Agent": "Fackel-SecurityAudit/1.0"},
        )
    except (requests.ConnectionError, requests.Timeout) as exc:
        # Unreachable hosts are common in recon — return a structured
        # result so the agent can move on instead of treating it as a
        # tool failure.
        return format_tool_output(
            "security_headers_audit",
            target,
            "ok",
            data={
                "url": target,
                "hostname": urlparse(target).hostname or target,
                "status_code": None,
                "headers_present": [],
                "total_issues": 0,
                "findings": [],
                "message": f"host unreachable: {type(exc).__name__}",
            },
        )
    except requests.RequestException as exc:
        raise ToolException(f"security_headers_audit: {exc}") from exc

    # Normalise header names to lower-case for lookups.
    resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    findings: list[dict[str, Any]] = []
    present_headers: dict[str, str] = {}

    for header, meta in _SECURITY_HEADERS.items():
        value = resp_headers_lower.get(header.lower(), "")
        if not value:
            findings.append(
                {
                    "header": header,
                    "status": "missing",
                    "severity": meta["severity"],
                    "description": meta["description"],
                    "recommendation": meta["recommendation"],
                }
            )
        else:
            present_headers[header] = value

    # Deep analysis on present headers.
    csp_value = present_headers.get("Content-Security-Policy", "")
    if csp_value:
        for warn in _analyse_csp(csp_value):
            findings.append(
                {
                    "header": "Content-Security-Policy",
                    "status": "weak",
                    "severity": warn["severity"],
                    "description": warn["message"],
                    "directive": warn["directive"],
                }
            )

    hsts_value = present_headers.get("Strict-Transport-Security", "")
    if hsts_value:
        for warn in _analyse_hsts(hsts_value):
            findings.append(
                {
                    "header": "Strict-Transport-Security",
                    "status": "weak",
                    "severity": warn["severity"],
                    "description": warn["message"],
                    "directive": warn["directive"],
                }
            )

    # CORS analysis.
    cors_warnings = _check_cors_headers(resp_headers_lower)
    for warn in cors_warnings:
        findings.append(
            {
                "header": "Access-Control-Allow-Origin",
                "status": "misconfigured",
                "severity": warn["severity"],
                "description": warn["message"],
            }
        )

    # Check for information disclosure headers.
    server_header = resp_headers_lower.get("server", "")
    # Detailed version info is a disclosure risk.
    if server_header and any(ch.isdigit() for ch in server_header):
        findings.append(
            {
                "header": "Server",
                "status": "disclosure",
                "severity": "info",
                "description": f"Server header discloses version: '{server_header}'.",
                "recommendation": "Remove or genericise the Server header.",
            }
        )

    x_powered = resp_headers_lower.get("x-powered-by", "")
    if x_powered:
        findings.append(
            {
                "header": "X-Powered-By",
                "status": "disclosure",
                "severity": "info",
                "description": f"X-Powered-By header discloses technology: '{x_powered}'.",
                "recommendation": "Remove the X-Powered-By header.",
            }
        )

    # Parse domain for reporting.
    parsed = urlparse(target)
    hostname = parsed.hostname or target

    summary = {
        "url": target,
        "hostname": hostname,
        "status_code": resp.status_code,
        "headers_present": list(present_headers.keys()),
        "total_issues": len(findings),
        "findings": findings,
    }

    if not findings:
        summary["message"] = "all security headers are properly configured"

    return format_tool_output(
        "security_headers_audit",
        target,
        "ok",
        data=summary,
    )


security_headers_audit.handle_tool_error = True
