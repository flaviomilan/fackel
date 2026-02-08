from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class CVE(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=False)

    cve_id: str
    cvss: Optional[float] = None
    source: Optional[str] = None


class Service(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=False)

    port: int
    protocol: str
    state: str
    name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extra: Optional[str] = None
    cves: List[CVE] = Field(default_factory=list)


class Host(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=False)

    hostname: str
    ip: Optional[str] = None
    services: List[Service] = Field(default_factory=list)


class Finding(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=False)

    title: str
    severity: Optional[str] = None
    description: Optional[str] = None
    evidence: Optional[str] = None
    cves: List[CVE] = Field(default_factory=list)


class Person(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=False)

    name: str
    role: Optional[str] = None
    profile_url: Optional[str] = None
    technologies: List[str] = Field(default_factory=list)


class Evidence(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=False)

    source_tool: str
    content: str


class DomainReport(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=False)

    domain: str
    hosts: Dict[str, Host] = Field(default_factory=dict)
    findings: List[Finding] = Field(default_factory=list)
    people: List[Person] = Field(default_factory=list)
    evidence: List[Evidence] = Field(default_factory=list)

    def to_dict(self) -> Dict:
        return self.model_dump()
