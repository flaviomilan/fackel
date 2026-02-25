"""WHOIS domain registration data lookup with RDAP fallback.

Uses the ``python-whois`` library first and, when that fails (common for
``.info``, ``.dev``, ``.app`` and many newer gTLDs), falls back to RDAP —
the IETF-standardised successor to WHOIS (RFC 9082/9083).
"""

from __future__ import annotations

import json
import logging
import shutil
import urllib.error
import urllib.request
from typing import Any

import whois
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from fackel.tooling import TargetType, format_tool_output, guard_target

logger = logging.getLogger(__name__)

_RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_RDAP_TIMEOUT = 10


class WhoisInput(BaseModel):
    """Input for WHOIS lookup."""

    domain: str = Field(
        description=(
            "Domain name to look up (e.g. 'example.com'). "
            "Do NOT pass IPs, URLs, or subdomains — use the root domain."
        ),
    )


# ── Traditional WHOIS (python-whois) ──────────────────────────────────


def _whois_query(domain: str) -> whois.WhoisEntry:
    """Try the built-in NICClient first, fall back to the system ``whois`` binary."""
    try:
        record = whois.whois(domain)
        # NICClient may succeed but return an empty/unparsed result for some TLDs.
        if record and (record.registrar or record.name_servers or record.creation_date):
            return record
    except Exception:
        logger.debug("NICClient WHOIS failed for %s", domain)

    # Fallback: shell out to system whois (handles more TLDs).
    if shutil.which("whois"):
        try:
            return whois.whois(domain, command=True)
        except Exception:
            logger.debug("System whois fallback failed for %s", domain)

    raise whois.parser.PywhoisError(f"WHOIS lookup failed for {domain}")


def _extract_field(record: whois.WhoisEntry, field: str) -> str | list[str] | None:
    """Safely extract a field from a WhoisEntry, returning ``None`` on failure."""
    val = getattr(record, field, None)
    if val is None:
        return None
    if isinstance(val, list):
        return [str(v) for v in val] if val else None
    return str(val)


def _build_whois_data(record: whois.WhoisEntry) -> dict[str, Any]:
    """Build the normalised data dict from a ``WhoisEntry``."""
    registrar = _extract_field(record, "registrar")
    name_servers = _extract_field(record, "name_servers")
    creation_date = _extract_field(record, "creation_date")
    expiration_date = _extract_field(record, "expiration_date")

    raw = str(record) if record else ""
    has_data = any([registrar, name_servers, creation_date, expiration_date])

    return {
        "registrar": registrar if isinstance(registrar, str) else None,
        "name_servers": name_servers if isinstance(name_servers, list) else [],
        "creation_date": (
            creation_date
            if isinstance(creation_date, str)
            else str(creation_date[0])
            if isinstance(creation_date, list) and creation_date
            else None
        ),
        "expiration_date": (
            expiration_date
            if isinstance(expiration_date, str)
            else str(expiration_date[0])
            if isinstance(expiration_date, list) and expiration_date
            else None
        ),
        "raw": raw[:2000] if raw else None,
        "parsed": has_data,
        "source": "whois",
    }


# ── RDAP fallback (RFC 9082 / 9083) ──────────────────────────────────


def _rdap_server_for_tld(tld: str) -> str | None:
    """Look up the RDAP base URL for *tld* via the IANA bootstrap file."""
    try:
        req = urllib.request.Request(  # noqa: S310
            _RDAP_BOOTSTRAP_URL,
            headers={"Accept": "application/json"},
        )
        resp = urllib.request.urlopen(req, timeout=_RDAP_TIMEOUT)  # noqa: S310
        data = json.loads(resp.read())
        for service in data.get("services", []):
            tlds, urls = service
            if tld.lower() in (t.lower() for t in tlds):
                return urls[0].rstrip("/")
    except Exception:
        logger.debug("RDAP bootstrap lookup failed for TLD '%s'", tld)
    return None


def _rdap_query(domain: str) -> dict[str, Any] | None:
    """Query RDAP for *domain* and return the parsed JSON, or ``None``."""
    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    if not tld:
        return None

    base_url = _rdap_server_for_tld(tld)
    if not base_url:
        return None

    url = f"{base_url}/domain/{domain}"
    try:
        req = urllib.request.Request(  # noqa: S310
            url,
            headers={"Accept": "application/rdap+json"},
        )
        resp = urllib.request.urlopen(req, timeout=_RDAP_TIMEOUT)  # noqa: S310
        return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        logger.debug("RDAP HTTP %s for %s", exc.code, domain)
    except Exception:
        logger.debug("RDAP query failed for %s", domain)
    return None


def _extract_rdap_registrar(data: dict[str, Any]) -> str | None:
    """Extract registrar name from RDAP entities list."""
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            # vCard is [[type, props, datatype, value], ...]
            vcard = entity.get("vcardArray", [None, []])
            if len(vcard) >= 2:
                for prop in vcard[1]:
                    if len(prop) >= 4 and prop[0] == "fn":
                        return str(prop[3])
            # Some registries use publicIds or handle instead of vCard.
            handle = entity.get("handle")
            if handle:
                return handle
    return None


def _extract_rdap_nameservers(data: dict[str, Any]) -> list[str]:
    """Extract name-server hostnames from RDAP response."""
    return [ns["ldhName"].lower() for ns in data.get("nameservers", []) if ns.get("ldhName")]


def _extract_rdap_event(data: dict[str, Any], action: str) -> str | None:
    """Extract event date string for *action* (e.g. 'registration', 'expiration')."""
    for event in data.get("events", []):
        if event.get("eventAction") == action:
            return event.get("eventDate")
    return None


def _build_rdap_data(data: dict[str, Any]) -> dict[str, Any]:
    """Build the normalised data dict from an RDAP JSON response."""
    registrar = _extract_rdap_registrar(data)
    name_servers = _extract_rdap_nameservers(data)
    creation_date = _extract_rdap_event(data, "registration")
    expiration_date = _extract_rdap_event(data, "expiration")
    status = data.get("status", [])

    has_data = any([registrar, name_servers, creation_date, expiration_date])

    return {
        "registrar": registrar,
        "name_servers": name_servers,
        "creation_date": creation_date,
        "expiration_date": expiration_date,
        "status": status,
        "raw": json.dumps(data, indent=2, default=str)[:2000],
        "parsed": has_data,
        "source": "rdap",
    }


# ── Public tool ───────────────────────────────────────────────────────


@tool(args_schema=WhoisInput)
def whois_lookup(domain: str) -> dict[str, Any]:
    """Query WHOIS registration data for a domain.

    Returns registrar, name servers, creation/expiration dates, and the raw
    WHOIS record.  Falls back to RDAP (RFC 9082) when traditional WHOIS
    returns no data.  Reveals hosting provider, domain age, and registrar —
    useful for attribution and infrastructure mapping.
    """
    domain, err = guard_target(domain, "whois_lookup", TargetType.DOMAIN)
    if err:
        return err

    # ── Attempt 1: traditional WHOIS ──────────────────────────────────
    try:
        record = _whois_query(domain)
        data = _build_whois_data(record)
        if data["parsed"]:
            return format_tool_output("whois_lookup", domain, "ok", data=data)
    except Exception:
        logger.debug("WHOIS query failed for %s", domain)

    # ── Attempt 2: RDAP fallback ──────────────────────────────────────
    try:
        rdap_data = _rdap_query(domain)
        if rdap_data:
            data = _build_rdap_data(rdap_data)
            return format_tool_output("whois_lookup", domain, "ok", data=data)
    except Exception as exc:
        logger.debug("RDAP fallback failed for %s: %s", domain, exc)

    return format_tool_output(
        "whois_lookup",
        domain,
        "error",
        error=f"WHOIS and RDAP lookup returned no data for {domain}",
    )
