from __future__ import annotations

import json
from typing import Any

from .models import CVE, DomainReport, Evidence, Host, Person, Service


class StructuredStore:
    """Armazena resultados estruturados para correlação e scoring (Pydantic)."""

    def __init__(self, domain: str):
        self.report = DomainReport(domain=domain)

    def add_host(self, hostname: str, ip: str | None = None) -> Host:
        host = self.report.hosts.get(hostname)
        if not host:
            host = Host(hostname=hostname, ip=ip)
            self.report.hosts[hostname] = host
        else:
            if ip and not host.ip:
                host.ip = ip
        return host

    def add_service(
        self,
        hostname: str,
        port: int,
        protocol: str,
        state: str,
        name: str | None = None,
        product: str | None = None,
        version: str | None = None,
        extra: str | None = None,
        cves: list[CVE] | None = None,
    ) -> None:
        host = self.add_host(hostname)
        for svc in host.services:
            if svc.port == port and svc.protocol == protocol:
                if name:
                    svc.name = name
                if product:
                    svc.product = product
                if version:
                    svc.version = version
                if extra:
                    svc.extra = extra
                if cves:
                    svc.cves.extend(cves)
                return

        host.services.append(
            Service(
                port=port,
                protocol=protocol,
                state=state,
                name=name,
                product=product,
                version=version,
                extra=extra,
                cves=cves or [],
            )
        )

    def add_evidence(self, tool: str, content: str) -> None:
        self.report.evidence.append(Evidence(source_tool=tool, content=content))

    def add_person(
        self,
        name: str,
        role: str | None = None,
        profile_url: str | None = None,
        technologies: list[str] | None = None,
    ) -> None:
        for p in self.report.people:
            if p.name == name and (not profile_url or p.profile_url == profile_url):
                if role and not p.role:
                    p.role = role
                if profile_url and not p.profile_url:
                    p.profile_url = profile_url
                if technologies:
                    p.technologies = sorted(list(set(p.technologies + technologies)))
                return

        self.report.people.append(
            Person(
                name=name,
                role=role,
                profile_url=profile_url,
                technologies=technologies or [],
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return self.report.to_dict()

    def save_json(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)
