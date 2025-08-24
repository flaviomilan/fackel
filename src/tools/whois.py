import os

import whois
from langchain.tools import tool


@tool
def whois_lookup(domain: str) -> str:
    """Perform a WHOIS lookup for the given domain."""
    try:
        w = whois.whois(domain)
        return str(w)
    except Exception as e:
        return f"Error performing WHOIS lookup: {e}"
