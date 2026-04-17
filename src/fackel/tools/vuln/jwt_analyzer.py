"""JWT analyzer — decode and assess JWT token security.

Decodes JWT tokens without signature verification and checks for common
security issues: algorithm none attacks, expired tokens, weak secrets,
missing claims, and dangerous algorithm choices.
"""

from __future__ import annotations

import base64
import hmac
import json
import time
from typing import Any

from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import format_tool_output

# Well-known weak secrets used in JWT brute-force attacks.
_WEAK_SECRETS: tuple[str, ...] = (
    "secret",
    "password",
    "123456",
    "key",
    "jwt_secret",
    "changeme",
    "test",
    "admin",
    "default",
    "private",
    "mysecret",
    "your-256-bit-secret",
)


class JwtAnalyzerInput(BaseModel):
    """Input for JWT analyzer."""

    token: str = Field(
        description=(
            "JWT token string to analyse (three base64url-encoded parts "
            "separated by dots). Example: 'eyJhbGciOiJIUzI1NiJ9.eyJ...'.  "
            "The tool decodes header and payload WITHOUT signature verification "
            "and checks for security weaknesses."
        ),
    )


def _b64url_decode(data: str) -> bytes:
    """Decode base64url with padding correction."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _decode_jwt_part(encoded: str) -> dict[str, Any]:
    """Decode a single JWT segment (header or payload) to dict."""
    try:
        raw = _b64url_decode(encoded)
        decoded = json.loads(raw)
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError) as exc:
        raise ToolException(f"jwt_analyzer: failed to decode JWT segment: {exc}") from exc
    if not isinstance(decoded, dict):
        raise ToolException("jwt_analyzer: JWT segment is not a JSON object")
    return decoded


def _check_weak_secret(token: str, header: dict[str, Any]) -> str | None:
    """Try common weak secrets against HS256/HS384/HS512 tokens."""
    alg = header.get("alg", "").upper()
    hash_map: dict[str, str] = {
        "HS256": "sha256",
        "HS384": "sha384",
        "HS512": "sha512",
    }
    if alg not in hash_map:
        return None

    parts = token.split(".")
    if len(parts) != 3:
        return None

    signing_input = f"{parts[0]}.{parts[1]}".encode()
    try:
        signature = _b64url_decode(parts[2])
    except Exception:
        return None

    for secret in _WEAK_SECRETS:
        computed = hmac.new(secret.encode(), signing_input, hash_map[alg]).digest()
        if hmac.compare_digest(computed, signature):
            return secret
    return None


@tool(args_schema=JwtAnalyzerInput)
def jwt_analyzer(token: str) -> dict[str, Any]:
    """Decode and analyse a JWT token for security weaknesses.

    Checks for: algorithm none attacks, expired tokens, missing standard
    claims (iat, exp, iss), weak HMAC secrets from a common wordlist,
    and dangerous algorithm choices.  Does NOT require network access.
    """
    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise ToolException("jwt_analyzer: invalid JWT — expected 3 dot-separated segments")

    header = _decode_jwt_part(parts[0])
    payload = _decode_jwt_part(parts[1])

    findings: list[dict[str, Any]] = []
    alg = header.get("alg", "")

    # -- Algorithm checks --
    if alg.lower() == "none" or not alg:
        findings.append(
            {
                "type": "alg_none",
                "severity": "critical",
                "description": (
                    "JWT uses 'none' algorithm — the token can be forged without any secret key."
                ),
                "recommendation": "Enforce a strong algorithm (RS256, ES256) server-side.",
            }
        )
    elif alg.upper() in ("HS256", "HS384", "HS512"):
        findings.append(
            {
                "type": "symmetric_algorithm",
                "severity": "info",
                "description": f"JWT uses symmetric algorithm '{alg}'.",
                "recommendation": (
                    "Consider asymmetric algorithms (RS256, ES256) for "
                    "public-facing APIs to avoid shared-secret risks."
                ),
            }
        )

    # -- Expiration checks --
    now = int(time.time())
    exp = payload.get("exp")
    if exp is None:
        findings.append(
            {
                "type": "missing_exp",
                "severity": "high",
                "description": "JWT has no 'exp' (expiration) claim — token never expires.",
                "recommendation": "Always set an expiration time for JWT tokens.",
            }
        )
    elif isinstance(exp, int | float) and exp < now:
        findings.append(
            {
                "type": "expired",
                "severity": "medium",
                "description": (
                    f"JWT is expired. Expiration: {int(exp)}, "
                    f"current: {now}, delta: {now - int(exp)}s."
                ),
                "recommendation": "Token should be refreshed or revoked.",
            }
        )

    nbf = payload.get("nbf")
    if isinstance(nbf, int | float) and nbf > now:
        findings.append(
            {
                "type": "not_yet_valid",
                "severity": "low",
                "description": f"JWT 'nbf' is in the future ({int(nbf)}).",
                "recommendation": "Verify clock synchronisation or token issuance logic.",
            }
        )

    # -- Missing standard claims --
    if "iat" not in payload:
        findings.append(
            {
                "type": "missing_iat",
                "severity": "low",
                "description": "JWT missing 'iat' (issued at) claim.",
                "recommendation": "Include 'iat' for token age tracking.",
            }
        )
    if "iss" not in payload:
        findings.append(
            {
                "type": "missing_iss",
                "severity": "low",
                "description": "JWT missing 'iss' (issuer) claim.",
                "recommendation": "Include 'iss' to validate token origin.",
            }
        )

    # -- Weak secret check (HMAC only) --
    weak = _check_weak_secret(token, header)
    if weak:
        findings.append(
            {
                "type": "weak_secret",
                "severity": "critical",
                "description": f"JWT signed with known weak secret: '{weak}'.",
                "recommendation": "Use a strong, randomly generated secret (≥256 bits).",
            }
        )

    # -- Dangerous header parameters --
    if "jku" in header:
        findings.append(
            {
                "type": "jku_present",
                "severity": "high",
                "description": (
                    "JWT header contains 'jku' (JWK Set URL). "
                    "An attacker could redirect to a controlled key set."
                ),
                "recommendation": "Validate 'jku' against a whitelist of trusted URLs.",
            }
        )
    if "jwk" in header:
        findings.append(
            {
                "type": "jwk_embedded",
                "severity": "high",
                "description": (
                    "JWT header contains embedded 'jwk'. "
                    "An attacker could supply their own public key."
                ),
                "recommendation": "Ignore embedded JWK; use server-side key management.",
            }
        )
    if "kid" in header and ("../" in str(header["kid"]) or "/" in str(header["kid"])):
        findings.append(
            {
                "type": "kid_injection",
                "severity": "high",
                "description": f"JWT 'kid' header may contain path traversal: '{header['kid']}'.",
                "recommendation": "Validate 'kid' against a whitelist.",
            }
        )

    data: dict[str, Any] = {
        "header": header,
        "payload": payload,
        "algorithm": alg,
        "total_issues": len(findings),
        "findings": findings,
    }

    if not findings:
        data["message"] = "no security issues detected in JWT"

    return format_tool_output("jwt_analyzer", "jwt_token", "ok", data=data)


jwt_analyzer.handle_tool_error = True
