"""TLS certificate inspection via pure Python stdlib.

Connects to a host on a given port, performs a TLS handshake, and
extracts certificate metadata: subject CN, issuer, SAN domains,
serial number, SHA-256 fingerprint, validity dates, and protocol
version.  No external binary required.

When the default (verifying) context fails — e.g. self-signed certs,
expired certs, or missing intermediate CAs — the tool retries with
certificate verification disabled so that a pentest report still
captures the certificate data.  The output ``verified`` field
indicates whether the chain was trusted.
"""

from __future__ import annotations

import hashlib
import logging
import os
import socket
import ssl
import tempfile
from datetime import UTC, datetime
from typing import Any

from langchain_core.tools import ToolException, tool
from pydantic import BaseModel, Field

from fackel.tooling import TargetType, format_tool_output, guard_target

logger = logging.getLogger(__name__)

_DEFAULT_PORT = 443
_CONNECT_TIMEOUT = 10


class TlsCertInput(BaseModel):
    """Input for TLS certificate lookup."""

    hostname: str = Field(
        description=(
            "Domain name to inspect (e.g. 'example.com'). "
            "Connects via TLS and extracts certificate metadata including "
            "Subject Alternative Names (SANs) for subdomain discovery."
        ),
    )
    port: int = Field(
        default=_DEFAULT_PORT,
        description="TCP port for the TLS connection (default 443).",
        ge=1,
        le=65535,
    )


def _parse_rdns(rdns_tuples: tuple[tuple[tuple[str, str], ...], ...]) -> dict[str, str]:
    """Flatten an RDN sequence from ``getpeercert()`` into a plain dict.

    ``ssl.SSLSocket.getpeercert()`` returns subject/issuer as nested tuples:
    ``((('commonName', 'example.com'),),)``
    """
    result: dict[str, str] = {}
    for rdn in rdns_tuples:
        for key, value in rdn:
            result[key] = value
    return result


def _extract_san_domains(cert: dict[str, Any]) -> list[str]:
    """Return deduplicated DNS names from the certificate SAN extension."""
    sans: list[str] = []
    for typ, value in cert.get("subjectAltName", ()):
        if typ == "DNS":
            name = value.strip().lower().lstrip("*.")
            if name and name not in sans:
                sans.append(name)
    return sorted(sans)


def _fingerprint_sha256(der_cert: bytes) -> str:
    """Return the SHA-256 fingerprint of a DER-encoded certificate."""
    digest = hashlib.sha256(der_cert).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2)).upper()


def _format_date(date_str: str | None) -> str:
    """Normalise the OpenSSL date string to ISO-8601."""
    if not date_str:
        return ""
    try:
        dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
        return dt.isoformat()
    except (ValueError, TypeError):
        return date_str


def _do_handshake(
    hostname: str,
    port: int,
    ctx: ssl.SSLContext,
) -> tuple[dict[str, Any] | None, bytes | None, str]:
    """Perform a TLS handshake and return ``(cert, der_cert, protocol)``."""
    with (
        socket.create_connection((hostname, port), timeout=_CONNECT_TIMEOUT) as sock,
        ctx.wrap_socket(sock, server_hostname=hostname) as tls,
    ):
        cert = tls.getpeercert()
        der_cert = tls.getpeercert(binary_form=True)
        protocol_version = tls.version() or ""
    return cert, der_cert, protocol_version


def _decode_der_cert(der_cert: bytes) -> dict[str, Any]:
    """Decode a DER-encoded certificate into the same dict format as ``getpeercert()``.

    When ``verify_mode=CERT_NONE``, Python's ``getpeercert()`` returns an
    empty dict.  This helper writes the DER bytes to a temp PEM file and
    uses the stdlib OpenSSL binding to parse it (same codepath as
    ``getpeercert()`` in verified mode).
    """
    pem = ssl.DER_cert_to_PEM_cert(der_cert)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(pem)
        return ssl._ssl._test_decode_cert(path)  # type: ignore[attr-defined,no-any-return]
    finally:
        os.unlink(path)


def _connect_and_get_cert(
    hostname: str,
    port: int,
) -> tuple[dict[str, Any] | None, bytes | None, str, bool]:
    """Try a verified TLS handshake, falling back to unverified on cert errors.

    Returns ``(cert_dict, der_bytes, protocol_or_error, verified)``.
    On total failure ``cert_dict`` is None and ``protocol_or_error`` carries
    the error message.
    """
    ctx = ssl.create_default_context()
    try:
        cert, der_cert, proto = _do_handshake(hostname, port, ctx)
        if cert:
            return cert, der_cert, proto, True
        return None, None, f"No certificate returned by {hostname}:{port}.", False
    except ssl.SSLCertVerificationError as exc:
        logger.debug(
            "Verified TLS failed for %s:%d (%s) — retrying unverified",
            hostname,
            port,
            exc,
        )
    except (TimeoutError, OSError, ssl.SSLError) as exc:
        return None, None, f"TLS connection to {hostname}:{port} failed: {exc}", False

    ctx_noverify = ssl.create_default_context()
    ctx_noverify.check_hostname = False
    ctx_noverify.verify_mode = ssl.CERT_NONE
    try:
        cert, der_cert, proto = _do_handshake(hostname, port, ctx_noverify)
        if not cert and der_cert:
            cert = _decode_der_cert(der_cert)
        if cert:
            return cert, der_cert, proto, False
        return None, None, f"No certificate returned by {hostname}:{port}.", False
    except (TimeoutError, OSError, ssl.SSLError) as exc:
        return None, None, f"TLS connection to {hostname}:{port} failed: {exc}", False


@tool(args_schema=TlsCertInput)
def tlscert_lookup(hostname: str, port: int = _DEFAULT_PORT) -> dict[str, Any]:
    """Inspect the TLS certificate of a host.

    Performs a TLS handshake and extracts the server certificate.
    Returns subject CN, issuer organisation, SAN domains (useful for
    subdomain discovery), serial number, SHA-256 fingerprint, validity
    dates, and negotiated protocol version.  Pure Python — no external
    binary required.
    """
    hostname = guard_target(hostname, "tlscert_lookup", TargetType.DOMAIN)

    cert, der_cert, protocol_version, verified = _connect_and_get_cert(hostname, port)

    if cert is None:
        raise ToolException(f"tlscert_lookup: {protocol_version}")

    subject = _parse_rdns(cert.get("subject", ()))
    issuer = _parse_rdns(cert.get("issuer", ()))
    san_domains = _extract_san_domains(cert)
    fingerprint = _fingerprint_sha256(der_cert) if der_cert else ""

    serial_hex = str(cert.get("serialNumber", "")).upper() or ""

    return format_tool_output(
        "tlscert_lookup",
        hostname,
        "ok",
        data={
            "subject_cn": subject.get("commonName", ""),
            "issuer_org": issuer.get("organizationName", ""),
            "issuer_cn": issuer.get("commonName", ""),
            "san_domains": san_domains,
            "serial": serial_hex,
            "fingerprint_sha256": fingerprint,
            "not_before": _format_date(cert.get("notBefore")),
            "not_after": _format_date(cert.get("notAfter")),
            "protocol_version": protocol_version,
            "verified": verified,
        },
    )


tlscert_lookup.handle_tool_error = True
