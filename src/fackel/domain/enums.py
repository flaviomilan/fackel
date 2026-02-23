from enum import StrEnum


class Phase(StrEnum):
    """Pentest workflow phases in the orchestrator graph."""

    OSINT = "osint"
    APPROVAL = "approval"
    PORT_SCAN = "port_scan"
    VULN_SCAN = "vuln_scan"
    TRIAGE = "triage"
    REPORT = "report"


class Severity(StrEnum):
    """Finding severity levels, ordered from highest to lowest impact."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


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
