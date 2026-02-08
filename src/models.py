from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class CVE:
    cve_id: str
    cvss: Optional[float] = None
    source: Optional[str] = None


@dataclass
class Service:
    port: int
    protocol: str
    state: str
    name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extra: Optional[str] = None
    cves: List[CVE] = field(default_factory=list)


@dataclass
class Host:
    hostname: str
    ip: Optional[str] = None
    services: List[Service] = field(default_factory=list)


@dataclass
class Finding:
    title: str
    severity: Optional[str] = None
    description: Optional[str] = None
    evidence: Optional[str] = None
    cves: List[CVE] = field(default_factory=list)


@dataclass
class Person:
    name: str
    role: Optional[str] = None
    profile_url: Optional[str] = None
    technologies: List[str] = field(default_factory=list)


@dataclass
class Evidence:
    source_tool: str
    content: str


@dataclass
class DomainReport:
    domain: str
    hosts: Dict[str, Host] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    people: List[Person] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)

    def add_host(self, host: Host) -> None:
        existing = self.hosts.get(host.hostname)
        if not existing:
            self.hosts[host.hostname] = host
            return
        if host.ip and not existing.ip:
            existing.ip = host.ip
        existing.services.extend(host.services)

    def to_dict(self) -> Dict:
        return {
            "domain": self.domain,
            "hosts": {
                name: {
                    "ip": host.ip,
                    "services": [
                        {
                            "port": svc.port,
                            "protocol": svc.protocol,
                            "state": svc.state,
                            "name": svc.name,
                            "product": svc.product,
                            "version": svc.version,
                            "extra": svc.extra,
                            "cves": [
                                {"cve_id": c.cve_id, "cvss": c.cvss, "source": c.source}
                                for c in svc.cves
                            ],
                        }
                        for svc in host.services
                    ],
                }
                for name, host in self.hosts.items()
            },
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "description": f.description,
                    "evidence": f.evidence,
                    "cves": [
                        {"cve_id": c.cve_id, "cvss": c.cvss, "source": c.source} for c in f.cves
                    ],
                }
                for f in self.findings
            ],
            "people": [
                {
                    "name": p.name,
                    "role": p.role,
                    "profile_url": p.profile_url,
                    "technologies": p.technologies,
                }
                for p in self.people
            ],
            "evidence": [
                {"source_tool": e.source_tool, "content": e.content} for e in self.evidence
            ],
        }
