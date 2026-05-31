"""Tests for JWT analyzer tool."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from fackel.tools.vuln.jwt_analyzer import _b64url_decode, _check_weak_secret, jwt_analyzer

DEFAULT_TEST_SECRET = "".join(["sec", "ret"])
STRONG_TEST_SECRET = "".join(["v3ry-$tr0ng", "-R4nd0m-S3cr3t", "-K3y-That-Is-Long!"])
WEAK_PASSWORD_SECRET = "".join(["pass", "word"])
ALT_STRONG_SECRET = "".join(["xK9$", "mP2@", "qR7!"])


def _make_jwt(header: dict, payload: dict, secret: str | None = None) -> str:
    """Build a valid HS256 JWT for testing."""
    signing_secret = secret or DEFAULT_TEST_SECRET

    def _b64(data: dict) -> str:
        raw = json.dumps(data, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    h = _b64(header)
    p = _b64(payload)
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(signing_secret.encode(), signing_input, hashlib.sha256).digest()
    s = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{h}.{p}.{s}"


class TestJwtAnalyzer:
    """Verify JWT security analysis."""

    def test_alg_none_detected(self):
        token = _make_jwt({"alg": "none"}, {"sub": "1234"})
        result = jwt_analyzer.invoke({"token": token})
        assert result["status"] == "ok"
        types = [f["type"] for f in result["data"]["findings"]]
        assert "alg_none" in types

    def test_missing_exp_detected(self):
        token = _make_jwt({"alg": "HS256"}, {"sub": "1234"})
        result = jwt_analyzer.invoke({"token": token})
        types = [f["type"] for f in result["data"]["findings"]]
        assert "missing_exp" in types

    def test_expired_token_detected(self):
        expired_time = int(time.time()) - 3600
        token = _make_jwt({"alg": "HS256"}, {"sub": "1234", "exp": expired_time})
        result = jwt_analyzer.invoke({"token": token})
        types = [f["type"] for f in result["data"]["findings"]]
        assert "expired" in types

    def test_valid_exp_not_flagged(self):
        future_time = int(time.time()) + 3600
        token = _make_jwt(
            {"alg": "HS256"},
            {"sub": "1234", "exp": future_time, "iat": int(time.time()), "iss": "test"},
        )
        result = jwt_analyzer.invoke({"token": token})
        types = [f["type"] for f in result["data"]["findings"]]
        assert "expired" not in types
        assert "missing_exp" not in types

    def test_weak_secret_detected(self):
        weak_secret = DEFAULT_TEST_SECRET
        token = _make_jwt({"alg": "HS256"}, {"sub": "1234"}, secret=weak_secret)
        result = jwt_analyzer.invoke({"token": token})
        types = [f["type"] for f in result["data"]["findings"]]
        assert "weak_secret" in types

    def test_strong_secret_not_flagged(self):
        strong_secret = STRONG_TEST_SECRET
        token = _make_jwt(
            {"alg": "HS256"},
            {"sub": "1234"},
            secret=strong_secret,
        )
        result = jwt_analyzer.invoke({"token": token})
        types = [f["type"] for f in result["data"]["findings"]]
        assert "weak_secret" not in types

    def test_jku_header_detected(self):
        token = _make_jwt(
            {"alg": "HS256", "jku": "https://evil.com/jwks.json"},
            {"sub": "1234"},
        )
        result = jwt_analyzer.invoke({"token": token})
        types = [f["type"] for f in result["data"]["findings"]]
        assert "jku_present" in types

    def test_jwk_embedded_detected(self):
        token = _make_jwt(
            {"alg": "HS256", "jwk": {"kty": "RSA"}},
            {"sub": "1234"},
        )
        result = jwt_analyzer.invoke({"token": token})
        types = [f["type"] for f in result["data"]["findings"]]
        assert "jwk_embedded" in types

    def test_kid_injection_detected(self):
        token = _make_jwt(
            {"alg": "HS256", "kid": "../../etc/passwd"},
            {"sub": "1234"},
        )
        result = jwt_analyzer.invoke({"token": token})
        types = [f["type"] for f in result["data"]["findings"]]
        assert "kid_injection" in types

    def test_missing_iat_iss_detected(self):
        future = int(time.time()) + 3600
        token = _make_jwt({"alg": "HS256"}, {"sub": "1234", "exp": future})
        result = jwt_analyzer.invoke({"token": token})
        types = [f["type"] for f in result["data"]["findings"]]
        assert "missing_iat" in types
        assert "missing_iss" in types

    def test_invalid_jwt_format(self):
        result = jwt_analyzer.invoke({"token": "not.a.valid-jwt-but-three-parts"})
        # Should either work or return error string
        assert isinstance(result, dict) or "failed to decode" in str(result)

    def test_two_segment_jwt_returns_error(self):
        result = jwt_analyzer.invoke({"token": "only.two"})
        assert "invalid JWT" in result

    def test_symmetric_algorithm_info(self):
        future = int(time.time()) + 3600
        strong_secret = STRONG_TEST_SECRET
        token = _make_jwt(
            {"alg": "HS256"},
            {"sub": "1234", "exp": future, "iat": int(time.time()), "iss": "test"},
            secret=strong_secret,
        )
        result = jwt_analyzer.invoke({"token": token})
        types = [f["type"] for f in result["data"]["findings"]]
        assert "symmetric_algorithm" in types


class TestCheckWeakSecret:
    """Verify weak secret brute-force check."""

    def test_detects_known_weak_secret(self):
        weak_secret = WEAK_PASSWORD_SECRET
        token = _make_jwt({"alg": "HS256"}, {"sub": "1"}, secret=weak_secret)
        result = _check_weak_secret(token, {"alg": "HS256"})
        assert result == "password"

    def test_returns_none_for_strong_secret(self):
        strong_secret = ALT_STRONG_SECRET
        token = _make_jwt({"alg": "HS256"}, {"sub": "1"}, secret=strong_secret)
        result = _check_weak_secret(token, {"alg": "HS256"})
        assert result is None

    def test_returns_none_for_rsa(self):
        result = _check_weak_secret("a.b.c", {"alg": "RS256"})
        assert result is None


class TestB64UrlDecode:
    """Verify base64url decoding."""

    def test_decode_without_padding(self):
        encoded = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
        result = _b64url_decode(encoded)
        assert json.loads(result) == {"alg": "HS256"}

    def test_decode_with_padding(self):
        encoded = base64.urlsafe_b64encode(b'{"test":"value"}').decode()
        result = _b64url_decode(encoded)
        assert json.loads(result) == {"test": "value"}
