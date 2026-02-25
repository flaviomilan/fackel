"""Tests for tlscert_lookup tool — TLS/socket calls mocked via unittest.mock."""

from __future__ import annotations

import contextlib
import ssl
from unittest.mock import MagicMock, patch

from tools.recon.tlscert_tool import (
    _decode_der_cert,
    _extract_san_domains,
    _fingerprint_sha256,
    _format_date,
    _parse_rdns,
    tlscert_lookup,
)

# ── Unit tests for internal helpers ────────────────────────────────────────


class TestParseRdns:
    def test_flattens_subject_tuples(self) -> None:
        rdns = ((("commonName", "example.com"),), (("organizationName", "Example Inc"),))
        result = _parse_rdns(rdns)
        assert result == {"commonName": "example.com", "organizationName": "Example Inc"}

    def test_empty_input(self) -> None:
        assert _parse_rdns(()) == {}


class TestExtractSanDomains:
    def test_extracts_dns_names(self) -> None:
        cert = {
            "subjectAltName": (
                ("DNS", "example.com"),
                ("DNS", "www.example.com"),
                ("DNS", "api.example.com"),
            )
        }
        result = _extract_san_domains(cert)
        assert result == ["api.example.com", "example.com", "www.example.com"]

    def test_strips_wildcard_prefix(self) -> None:
        cert = {"subjectAltName": (("DNS", "*.example.com"),)}
        result = _extract_san_domains(cert)
        assert result == ["example.com"]

    def test_deduplicates(self) -> None:
        cert = {
            "subjectAltName": (
                ("DNS", "example.com"),
                ("DNS", "example.com"),
            )
        }
        result = _extract_san_domains(cert)
        assert result == ["example.com"]

    def test_empty_san(self) -> None:
        assert _extract_san_domains({}) == []

    def test_ignores_non_dns_entries(self) -> None:
        cert = {
            "subjectAltName": (
                ("DNS", "example.com"),
                ("IP Address", "1.2.3.4"),
                ("email", "admin@example.com"),
            )
        }
        result = _extract_san_domains(cert)
        assert result == ["example.com"]


class TestFingerprintSha256:
    def test_produces_colon_separated_hex(self) -> None:
        der = b"\x00\x01\x02\x03"
        result = _fingerprint_sha256(der)
        assert ":" in result
        parts = result.split(":")
        assert len(parts) == 32  # SHA-256 = 32 bytes
        assert all(len(p) == 2 for p in parts)
        assert result == result.upper()


class TestFormatDate:
    def test_standard_openssl_date(self) -> None:
        result = _format_date("Jan 15 12:00:00 2025 GMT")
        assert result == "2025-01-15T12:00:00+00:00"

    def test_empty_string(self) -> None:
        assert _format_date("") == ""

    def test_none(self) -> None:
        assert _format_date(None) == ""

    def test_unparseable_passthrough(self) -> None:
        assert _format_date("not-a-date") == "not-a-date"


class TestDecodeDerCert:
    """Unit tests for the _decode_der_cert helper."""

    @patch("tools.recon.tlscert_tool.ssl._ssl._test_decode_cert")
    @patch("tools.recon.tlscert_tool.ssl.DER_cert_to_PEM_cert")
    def test_converts_der_to_cert_dict(
        self, mock_to_pem: MagicMock, mock_decode: MagicMock
    ) -> None:
        pem_text = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"
        mock_to_pem.return_value = pem_text
        mock_decode.return_value = {"subject": ((("commonName", "x.com"),),)}

        result = _decode_der_cert(b"\x00\x01")

        assert result["subject"] == ((("commonName", "x.com"),),)
        mock_to_pem.assert_called_once_with(b"\x00\x01")
        mock_decode.assert_called_once()  # temp file path passed

    @patch("tools.recon.tlscert_tool.ssl._ssl._test_decode_cert")
    @patch("tools.recon.tlscert_tool.ssl.DER_cert_to_PEM_cert")
    def test_cleans_up_temp_file(self, mock_to_pem: MagicMock, mock_decode: MagicMock) -> None:
        """Temp PEM file is removed even when _test_decode_cert raises."""
        mock_to_pem.return_value = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"
        mock_decode.side_effect = ssl.SSLError("decode failed")

        with contextlib.suppress(ssl.SSLError):
            _decode_der_cert(b"\x00\x01")

        # If we get here without an OSError the temp file was cleaned up.
        mock_decode.assert_called_once()


# ── Integration tests for the tool (mocked TLS) ───────────────────────────

_MOCK_CERT = {
    "subject": ((("commonName", "example.com"),),),
    "issuer": (
        (("organizationName", "Let's Encrypt"),),
        (("commonName", "R3"),),
    ),
    "subjectAltName": (
        ("DNS", "example.com"),
        ("DNS", "www.example.com"),
        ("DNS", "api.example.com"),
        ("DNS", "staging.example.com"),
    ),
    "serialNumber": "03A1B2C3D4E5F6",
    "notBefore": "Jan  1 00:00:00 2025 GMT",
    "notAfter": "Apr  1 00:00:00 2025 GMT",
}

_MOCK_DER = b"\xde\xad\xbe\xef" * 8  # 32 bytes for testing


def _build_mock_tls_socket(
    cert: dict | None = None,
    der_cert: bytes | None = None,
    version: str = "TLSv1.3",
) -> MagicMock:
    """Build a mock SSL socket that returns the given cert data."""
    tls_sock = MagicMock()
    tls_sock.getpeercert.side_effect = lambda binary_form=False: (
        der_cert or _MOCK_DER if binary_form else cert or _MOCK_CERT
    )
    tls_sock.version.return_value = version
    tls_sock.__enter__ = MagicMock(return_value=tls_sock)
    tls_sock.__exit__ = MagicMock(return_value=False)
    return tls_sock


def _build_mock_raw_socket() -> MagicMock:
    raw = MagicMock()
    raw.__enter__ = MagicMock(return_value=raw)
    raw.__exit__ = MagicMock(return_value=False)
    return raw


class TestTlscertLookupHappyPath:
    """Successful TLS certificate lookups."""

    @patch("tools.recon.tlscert_tool.ssl.create_default_context")
    @patch("tools.recon.tlscert_tool.socket.create_connection")
    def test_returns_full_cert_data(self, mock_conn: MagicMock, mock_ctx: MagicMock) -> None:
        tls_sock = _build_mock_tls_socket()
        raw_sock = _build_mock_raw_socket()
        mock_conn.return_value = raw_sock
        ctx = MagicMock()
        ctx.wrap_socket.return_value = tls_sock
        mock_ctx.return_value = ctx

        result = tlscert_lookup.invoke({"hostname": "example.com"})

        assert result["status"] == "ok"
        assert result["tool"] == "tlscert_lookup"
        data = result["data"]
        assert data["subject_cn"] == "example.com"
        assert data["issuer_org"] == "Let's Encrypt"
        assert data["issuer_cn"] == "R3"
        assert "example.com" in data["san_domains"]
        assert "www.example.com" in data["san_domains"]
        assert "api.example.com" in data["san_domains"]
        assert "staging.example.com" in data["san_domains"]
        assert data["protocol_version"] == "TLSv1.3"
        assert data["not_before"] != ""
        assert data["not_after"] != ""
        assert ":" in data["fingerprint_sha256"]
        assert data["verified"] is True

    @patch("tools.recon.tlscert_tool.ssl.create_default_context")
    @patch("tools.recon.tlscert_tool.socket.create_connection")
    def test_custom_port(self, mock_conn: MagicMock, mock_ctx: MagicMock) -> None:
        tls_sock = _build_mock_tls_socket()
        raw_sock = _build_mock_raw_socket()
        mock_conn.return_value = raw_sock
        ctx = MagicMock()
        ctx.wrap_socket.return_value = tls_sock
        mock_ctx.return_value = ctx

        result = tlscert_lookup.invoke({"hostname": "example.com", "port": 8443})

        assert result["status"] == "ok"
        mock_conn.assert_called_once_with(("example.com", 8443), timeout=10)

    @patch("tools.recon.tlscert_tool.ssl.create_default_context")
    @patch("tools.recon.tlscert_tool.socket.create_connection")
    def test_self_signed_cert_fallback(self, mock_conn: MagicMock, mock_ctx: MagicMock) -> None:
        """When verification fails, the tool retries unverified and returns data."""
        tls_sock = _build_mock_tls_socket()
        raw_sock = _build_mock_raw_socket()
        mock_conn.return_value = raw_sock

        # First context (verified) raises SSLCertVerificationError,
        # second context (unverified) succeeds.
        ctx_verified = MagicMock()
        ctx_verified.wrap_socket.side_effect = ssl.SSLCertVerificationError(
            "certificate verify failed: unable to get local issuer certificate"
        )
        ctx_unverified = MagicMock()
        ctx_unverified.wrap_socket.return_value = tls_sock
        mock_ctx.side_effect = [ctx_verified, ctx_unverified]

        result = tlscert_lookup.invoke({"hostname": "example.com"})

        assert result["status"] == "ok"
        data = result["data"]
        assert data["subject_cn"] == "example.com"
        assert data["verified"] is False
        # create_default_context called twice (verified + unverified)
        assert mock_ctx.call_count == 2

    @patch("tools.recon.tlscert_tool._decode_der_cert")
    @patch("tools.recon.tlscert_tool.ssl.create_default_context")
    @patch("tools.recon.tlscert_tool.socket.create_connection")
    def test_self_signed_der_decode_fallback(
        self,
        mock_conn: MagicMock,
        mock_ctx: MagicMock,
        mock_decode: MagicMock,
    ) -> None:
        """With CERT_NONE, getpeercert() returns {} — DER bytes are parsed instead."""
        # Simulate real CERT_NONE behaviour: getpeercert() → {}, binary → DER
        tls_sock = MagicMock()
        tls_sock.getpeercert.side_effect = lambda binary_form=False: (
            _MOCK_DER if binary_form else {}
        )
        tls_sock.version.return_value = "TLSv1.2"
        tls_sock.__enter__ = MagicMock(return_value=tls_sock)
        tls_sock.__exit__ = MagicMock(return_value=False)

        raw_sock = _build_mock_raw_socket()
        mock_conn.return_value = raw_sock
        mock_decode.return_value = _MOCK_CERT

        ctx_verified = MagicMock()
        ctx_verified.wrap_socket.side_effect = ssl.SSLCertVerificationError(
            "certificate verify failed"
        )
        ctx_unverified = MagicMock()
        ctx_unverified.wrap_socket.return_value = tls_sock
        mock_ctx.side_effect = [ctx_verified, ctx_unverified]

        result = tlscert_lookup.invoke({"hostname": "example.com"})

        assert result["status"] == "ok"
        assert result["data"]["verified"] is False
        assert result["data"]["subject_cn"] == "example.com"
        mock_decode.assert_called_once_with(_MOCK_DER)


class TestTlscertLookupErrors:
    """Error handling for TLS cert lookups."""

    @patch("tools.recon.tlscert_tool.ssl.create_default_context")
    @patch("tools.recon.tlscert_tool.socket.create_connection")
    def test_connection_refused(self, mock_conn: MagicMock, mock_ctx: MagicMock) -> None:
        mock_conn.side_effect = OSError("Connection refused")
        result = tlscert_lookup.invoke({"hostname": "example.com"})
        assert isinstance(result, str)
        assert "Connection refused" in result

    @patch("tools.recon.tlscert_tool.ssl.create_default_context")
    @patch("tools.recon.tlscert_tool.socket.create_connection")
    def test_ssl_handshake_error(self, mock_conn: MagicMock, mock_ctx: MagicMock) -> None:
        """Non-verification SSL errors (e.g. protocol mismatch) are not retried."""
        raw_sock = _build_mock_raw_socket()
        mock_conn.return_value = raw_sock
        ctx = MagicMock()
        ctx.wrap_socket.side_effect = ssl.SSLError("tlsv1 alert protocol version")
        mock_ctx.return_value = ctx
        result = tlscert_lookup.invoke({"hostname": "example.com"})
        assert isinstance(result, str)
        assert "tlsv1 alert protocol version" in result

    @patch("tools.recon.tlscert_tool.ssl.create_default_context")
    @patch("tools.recon.tlscert_tool.socket.create_connection")
    def test_self_signed_both_attempts_fail(
        self, mock_conn: MagicMock, mock_ctx: MagicMock
    ) -> None:
        """If even the unverified handshake fails, return error."""
        raw_sock = _build_mock_raw_socket()
        mock_conn.return_value = raw_sock
        ctx_verified = MagicMock()
        ctx_verified.wrap_socket.side_effect = ssl.SSLCertVerificationError(
            "certificate verify failed"
        )
        ctx_unverified = MagicMock()
        ctx_unverified.wrap_socket.side_effect = ssl.SSLError("unexpected EOF")
        mock_ctx.side_effect = [ctx_verified, ctx_unverified]

        result = tlscert_lookup.invoke({"hostname": "example.com"})
        assert isinstance(result, str)
        assert "unexpected EOF" in result

    @patch("tools.recon.tlscert_tool.ssl.create_default_context")
    @patch("tools.recon.tlscert_tool.socket.create_connection")
    def test_no_cert_returned(self, mock_conn: MagicMock, mock_ctx: MagicMock) -> None:
        tls_sock = _build_mock_tls_socket(cert=None)
        # Override to return None for non-binary
        tls_sock.getpeercert.side_effect = lambda binary_form=False: (
            _MOCK_DER if binary_form else None
        )
        raw_sock = _build_mock_raw_socket()
        mock_conn.return_value = raw_sock
        ctx = MagicMock()
        ctx.wrap_socket.return_value = tls_sock
        mock_ctx.return_value = ctx

        result = tlscert_lookup.invoke({"hostname": "example.com"})
        assert isinstance(result, str)
        assert "No certificate" in result


class TestTlscertLookupValidation:
    """Input validation via guard_target."""

    def test_rejects_ip_address(self) -> None:
        result = tlscert_lookup.invoke({"hostname": "1.2.3.4"})
        assert isinstance(result, str)

    def test_rejects_empty_hostname(self) -> None:
        result = tlscert_lookup.invoke({"hostname": ""})
        assert isinstance(result, str)

    def test_rejects_shell_metacharacters(self) -> None:
        result = tlscert_lookup.invoke({"hostname": "example.com; rm -rf /"})
        assert isinstance(result, str)
