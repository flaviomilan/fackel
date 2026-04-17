"""Catalog of semantic information types.

Adding a new type is the only schema change required to support a new
class of fact — translators populate the ``InformationCandidate.type``
with one of these values; persistence and reporting are type-agnostic.
"""

from __future__ import annotations

from enum import StrEnum


class InformationType(StrEnum):
    """Stable catalog of normalized fact categories.

    Backed by ``str`` so JSONL serialization is trivial and values stay
    stable across versions.  Add new entries; never rename existing ones.
    """

    # Identity & infrastructure
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    IP_ADDRESS = "IP_ADDRESS"
    HISTORICAL_IP_ADDRESS = "HISTORICAL_IP_ADDRESS"
    TLS_SAN_DOMAIN = "TLS_SAN_DOMAIN"

    # Service surface
    OPEN_PORT = "OPEN_PORT"
    SERVICE_VERSION = "SERVICE_VERSION"

    # Profile / classification
    IP_CLASSIFICATION = "IP_CLASSIFICATION"
    TECH_FINGERPRINT = "TECH_FINGERPRINT"

    # People / organisation (entity-OSINT)
    EMAIL = "EMAIL"
    PERSON = "PERSON"
    USERNAME = "USERNAME"
    ORGANIZATION = "ORGANIZATION"
    SOCIAL_ACCOUNT = "SOCIAL_ACCOUNT"
    DOCUMENT = "DOCUMENT"
    PHONE = "PHONE"

    # Risk
    SECURITY_VULNERABILITY = "SECURITY_VULNERABILITY"
    CREDENTIAL_LEAK = "CREDENTIAL_LEAK"
