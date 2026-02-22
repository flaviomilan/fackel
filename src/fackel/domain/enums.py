from enum import StrEnum


class Phase(StrEnum):
    """Pentest workflow phases, matching the keys of ALLOWED_TRANSITIONS."""

    START = "start"
    SCOPE_GUARD = "scope_guard"
    OSINT = "osint"
    PORT_SCAN = "port_scan"
    REPORT = "report"


class InformationType(StrEnum):
    """Semantic catalog of discoverable information types."""

    DOMAIN = "DOMAIN"
    IP_ADDRESS = "IP_ADDRESS"
    OPEN_PORT = "OPEN_PORT"
    SERVICE = "SERVICE"
    URL = "URL"
    CERTIFICATE = "CERTIFICATE"
    TECHNOLOGY = "TECHNOLOGY"
    EMAIL_ADDRESS = "EMAIL_ADDRESS"
    EMPLOYEE = "EMPLOYEE"
    VULNERABILITY = "VULNERABILITY"


class InformationStatus(StrEnum):
    """Lifecycle status of a persisted InformationRecord."""

    ACTIVE = "active"
    RESOLVED = "resolved"
    MASKED = "masked"
    OUTDATED = "outdated"
    REINTRODUCED = "reintroduced"
