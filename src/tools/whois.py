
import shutil

import whois
from langchain_core.tools import tool
from pydantic import BaseModel, Field

from .utils import format_tool_output


class WhoisInput(BaseModel):
    """Input for WHOIS lookup."""

    domain: str = Field(
        description=(
            "Domain name to look up (e.g. 'example.com'). "
            "Do NOT pass IPs, URLs, or subdomains — use the root domain."
        ),
    )


def _whois_query(domain: str) -> whois.WhoisEntry:
    """Try the built-in NICClient first, fall back to the system ``whois`` binary."""
    try:
        record = whois.whois(domain)
        # NICClient may succeed but return an empty/unparsed result for some TLDs.
        if record and (record.registrar or record.name_servers or record.creation_date):
            return record
    except Exception:
        pass

    # Fallback: shell out to system whois (handles more TLDs).
    if shutil.which("whois"):
        try:
            return whois.whois(domain, command=True)
        except Exception:
            pass

    raise whois.parser.PywhoisError(f"WHOIS lookup failed for {domain}")


def _extract_field(record, field: str):
    """Safely extract a field from a WhoisEntry, returning ``None`` on failure."""
    val = getattr(record, field, None)
    if val is None:
        return None
    if isinstance(val, list):
        return [str(v) for v in val] if val else None
    return str(val)


@tool(args_schema=WhoisInput)
def whois_lookup(domain: str) -> dict:
    """Query WHOIS registration data for a domain.

    Returns registrar, name servers, creation/expiration dates, and the raw
    WHOIS record.  Reveals hosting provider, domain age, and registrar —
    useful for attribution and infrastructure mapping.
    """
    try:
        record = _whois_query(domain)

        registrar = _extract_field(record, "registrar")
        name_servers = _extract_field(record, "name_servers")
        creation_date = _extract_field(record, "creation_date")
        expiration_date = _extract_field(record, "expiration_date")

        raw = str(record) if record else ""

        # If the record parsed but every field is empty, return the raw text so
        # the LLM can still extract useful info (registrar privacy, ToS, etc.).
        has_data = any([registrar, name_servers, creation_date, expiration_date])

        return format_tool_output(
            "whois_lookup",
            domain,
            "ok",
            data={
                "registrar": registrar if isinstance(registrar, str) else None,
                "name_servers": name_servers if isinstance(name_servers, list) else [],
                "creation_date": (
                    creation_date if isinstance(creation_date, str)
                    else str(creation_date[0]) if isinstance(creation_date, list) and creation_date
                    else None
                ),
                "expiration_date": (
                    expiration_date if isinstance(expiration_date, str)
                    else str(expiration_date[0]) if isinstance(expiration_date, list) and expiration_date
                    else None
                ),
                "raw": raw[:2000] if raw else None,
                "parsed": has_data,
            },
        )
    except Exception as e:
        return format_tool_output(
            "whois_lookup",
            domain,
            "error",
            error=f"Error performing WHOIS lookup: {e}",
        )
