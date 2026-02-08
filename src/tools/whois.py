import whois
from langchain.tools import tool


@tool
def whois_lookup(domain: str):
    """Perform a WHOIS lookup for the given domain and return structured data."""
    try:
        record = whois.whois(domain)
        return {
            "tool": "whois_lookup",
            "status": "ok",
            "domain": domain,
            "registrar": record.registrar if hasattr(record, "registrar") else None,
            "name_servers": list(record.name_servers) if getattr(record, "name_servers", None) else [],
            "creation_date": str(record.creation_date) if getattr(record, "creation_date", None) else None,
            "expiration_date": str(record.expiration_date) if getattr(record, "expiration_date", None) else None,
            "raw": str(record),
        }
    except Exception as e:
        return {
            "tool": "whois_lookup",
            "status": "error",
            "domain": domain,
            "error": f"Error performing WHOIS lookup: {e}",
        }
