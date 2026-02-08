from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class CVE(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=False)

    cve_id: str
    cvss: float | None = None
    source: str | None = None


class Service(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=False)

    port: int
    protocol: str
    state: str
    name: str | None = None
    product: str | None = None
    version: str | None = None
    extra: str | None = None
    cves: list[CVE] = Field(default_factory=list)


class Host(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=False)

    hostname: str
    ip: str | None = None
    services: list[Service] = Field(default_factory=list)


class Finding(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=False)

    title: str
    severity: str | None = None
    description: str | None = None
    evidence: str | None = None
    cves: list[CVE] = Field(default_factory=list)


class Person(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=False)

    name: str
    role: str | None = None
    profile_url: str | None = None
    technologies: list[str] = Field(default_factory=list)


class Evidence(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=False)

    source_tool: str
    content: str


class DomainReport(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=False)

    domain: str
    hosts: dict[str, Host] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    people: list[Person] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)

    def to_dict(self) -> dict:
        return self.model_dump()
