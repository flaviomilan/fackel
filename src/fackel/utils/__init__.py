"""fackel.utils — shared pure-logic utilities.

Only stateless, side-effect-free helpers belong here.
Domain logic lives in ``fackel.domain``; infrastructure helpers
stay in the tool or infra layer that owns them.
"""

from fackel.utils.network import is_reverse_ptr_subdomain, is_valid_domain, is_valid_ip
from fackel.utils.target import extract_host, sanitize_target

__all__ = [
    "extract_host",
    "is_reverse_ptr_subdomain",
    "is_valid_domain",
    "is_valid_ip",
    "sanitize_target",
]
