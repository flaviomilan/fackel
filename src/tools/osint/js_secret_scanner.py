"""JavaScript secret scanner — regex-based extraction of secrets from JS files.

Fetches JavaScript files from a target URL and scans for API keys,
tokens, credentials, internal URLs, and other sensitive data using
curated regular expressions.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import (
    TargetType,
    format_tool_output,
    get_tool_timeout,
    guard_target,
)

_TIMEOUT = 30

# Regex patterns for common secrets in JavaScript files.
# Each entry: (name, regex_pattern, severity, description).
_SECRET_PATTERNS: list[tuple[str, str, str, str]] = [
    (
        "aws_access_key",
        r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
        "critical",
        "AWS Access Key ID",
    ),
    (
        "aws_secret_key",
        r"(?:aws)?_?(?:secret)?_?(?:access)?_?key['\"\s]*[:=]\s*['\"][0-9a-zA-Z/+=]{40}['\"]",
        "critical",
        "AWS Secret Access Key",
    ),
    (
        "google_api_key",
        r"AIza[0-9A-Za-z_-]{35}",
        "high",
        "Google API Key",
    ),
    (
        "google_oauth",
        r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        "high",
        "Google OAuth Client ID",
    ),
    (
        "github_token",
        r"gh[pousr]_[0-9a-zA-Z]{36}",
        "critical",
        "GitHub Personal Access Token",
    ),
    (
        "github_classic_token",
        r"github_pat_[0-9a-zA-Z_]{82}",
        "critical",
        "GitHub Fine-grained Token",
    ),
    (
        "slack_token",
        r"xox[baprs]-[0-9]{10,13}-[0-9a-zA-Z-]{20,}",
        "high",
        "Slack Token",
    ),
    (
        "slack_webhook",
        r"https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9a-zA-Z]{24}",
        "high",
        "Slack Webhook URL",
    ),
    (
        "stripe_secret",
        r"sk_live_[0-9a-zA-Z]{24,}",
        "critical",
        "Stripe Secret Key (live)",
    ),
    (
        "stripe_publishable",
        r"pk_live_[0-9a-zA-Z]{24,}",
        "medium",
        "Stripe Publishable Key (live)",
    ),
    (
        "twilio_api_key",
        r"SK[0-9a-fA-F]{32}",
        "high",
        "Twilio API Key",
    ),
    (
        "mailgun_api_key",
        r"key-[0-9a-zA-Z]{32}",
        "high",
        "Mailgun API Key",
    ),
    (
        "jwt_token",
        r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+",
        "high",
        "JWT Token",
    ),
    (
        "private_key",
        r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "critical",
        "Private Key",
    ),
    (
        "heroku_api_key",
        r"[hH][eE][rR][oO][kK][uU][\s]*[=:]+[\s]*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
        "high",
        "Heroku API Key",
    ),
    (
        "firebase_url",
        r"https://[a-z0-9-]+\.firebaseio\.com",
        "medium",
        "Firebase Database URL",
    ),
    (
        "sendgrid_api_key",
        r"SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}",
        "high",
        "SendGrid API Key",
    ),
    (
        "square_access_token",
        r"sq0atp-[0-9A-Za-z_-]{22}",
        "high",
        "Square Access Token",
    ),
    (
        "generic_api_key",
        r"(?:api[_-]?key|apikey|api_secret|access_token)['\"\s]*[:=]\s*['\"][0-9a-zA-Z]{16,}['\"]",
        "medium",
        "Generic API Key/Secret",
    ),
    (
        "generic_password",
        r"(?:password|passwd|pwd|secret)['\"\s]*[:=]\s*['\"][^\s'\"]{8,}['\"]",
        "high",
        "Hardcoded Password/Secret",
    ),
    (
        "internal_ip",
        r"(?:https?://)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::\d+)?",
        "medium",
        "Internal/Private IP Address",
    ),
    (
        "s3_bucket",
        r"[a-z0-9.-]+\.s3\.amazonaws\.com|s3://[a-z0-9.-]+",
        "medium",
        "AWS S3 Bucket Reference",
    ),
]

# Compile regexes once.
_COMPILED_PATTERNS: list[tuple[str, re.Pattern[str], str, str]] = [
    (name, re.compile(pattern, re.IGNORECASE), severity, desc)
    for name, pattern, severity, desc in _SECRET_PATTERNS
]


class JsSecretScannerInput(BaseModel):
    """Input for JavaScript secret scanner."""

    target: str = Field(
        description=(
            "URL of a JavaScript file or a web page to scan for secrets. "
            "If a .js URL is given, it is fetched directly. "
            "If a web page URL is given, the tool extracts <script src> "
            "references and scans each one. "
            "Example: 'https://example.com/static/app.js' or "
            "'https://example.com'."
        ),
    )


def _fetch(url: str, timeout: int) -> str:
    """Fetch URL content, returning empty string on failure."""
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "Fackel-JSScanner/1.0"},
            allow_redirects=True,
        )
        resp.raise_for_status()
        return resp.text
    except requests.RequestException:
        return ""


def _extract_script_urls(html: str, base_url: str) -> list[str]:
    """Extract JavaScript URLs from HTML script tags."""
    urls: list[str] = []
    # Simple regex to find <script src="..."> without pulling in a full parser.
    for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
        src = match.group(1)
        if src.startswith(("data:", "blob:")):
            continue
        full_url = urljoin(base_url, src)
        urls.append(full_url)
    return urls


def _scan_content(
    content: str,
    source_url: str,
) -> list[dict[str, Any]]:
    """Scan text content for secret patterns."""
    results: list[dict[str, Any]] = []
    seen: set[str] = set()

    for name, pattern, severity, description in _COMPILED_PATTERNS:
        for match in pattern.finditer(content):
            value = match.group(0)
            # Truncate long matches for readability.
            display = value[:80] + "..." if len(value) > 80 else value
            dedup_key = f"{name}:{value}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # Approximate line number.
            line_num = content[:match.start()].count("\n") + 1

            results.append({
                "type": name,
                "severity": severity,
                "description": description,
                "match": display,
                "source": source_url,
                "line": line_num,
            })
    return results


@tool(args_schema=JsSecretScannerInput)
def js_secret_scan(target: str) -> dict[str, Any]:
    """Scan JavaScript files for leaked secrets, API keys, and tokens.

    If a .js URL is given, scans that file directly.  If a web page URL
    is given, extracts all <script src> references and scans each one.
    Also scans inline JavaScript on the page.  Uses curated regex patterns
    for AWS keys, GitHub tokens, Stripe keys, JWTs, private keys, and more.
    """
    target = guard_target(target, "js_secret_scan", TargetType.HOST_OR_URL)

    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    timeout = get_tool_timeout("js_secret_scan", _TIMEOUT)

    # Determine if target is a direct JS file or an HTML page.
    parsed = urlparse(target)
    path_lower = parsed.path.lower()
    is_js = path_lower.endswith((".js", ".mjs", ".cjs"))

    all_findings: list[dict[str, Any]] = []
    scanned_urls: list[str] = []

    if is_js:
        # Direct JS file scan.
        content = _fetch(target, timeout)
        if not content:
            raise ToolException(f"js_secret_scan: failed to fetch {target}")
        all_findings.extend(_scan_content(content, target))
        scanned_urls.append(target)
    else:
        # HTML page — extract inline + external scripts.
        page_content = _fetch(target, timeout)
        if not page_content:
            raise ToolException(f"js_secret_scan: failed to fetch {target}")

        # Scan inline scripts on the page.
        for inline_match in re.finditer(
            r"<script[^>]*>(.*?)</script>", page_content, re.DOTALL | re.IGNORECASE
        ):
            inline = inline_match.group(1).strip()
            if inline:
                all_findings.extend(_scan_content(inline, f"{target} (inline)"))

        # Extract and scan external JS files.
        js_urls = _extract_script_urls(page_content, target)
        scanned_urls.append(target)
        for js_url in js_urls[:20]:  # Cap at 20 to avoid excessive fetches.
            js_content = _fetch(js_url, timeout)
            if js_content:
                all_findings.extend(_scan_content(js_content, js_url))
                scanned_urls.append(js_url)

    data: dict[str, Any] = {
        "scanned_urls": scanned_urls,
        "total_urls_scanned": len(scanned_urls),
        "total": len(all_findings),
        "findings": all_findings,
    }

    if not all_findings:
        data["message"] = "no secrets or sensitive data found in JavaScript files"

    return format_tool_output("js_secret_scan", target, "ok", data=data)


js_secret_scan.handle_tool_error = True  # type: ignore[attr-defined]
