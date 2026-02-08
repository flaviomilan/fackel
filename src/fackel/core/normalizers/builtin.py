from __future__ import annotations

import json
import re
from typing import Any, Callable

from ..models import CVE
from ..store import StructuredStore

StructuredIngester = Callable[[dict[str, Any], StructuredStore], None]
TextIngester = Callable[[str, StructuredStore], None]


def _as_dict(output: Any) -> dict[str, Any] | None:
    if isinstance(output, dict):
        return output
    if isinstance(output, str):
        try:
            return json.loads(output)
        except Exception:
            return None
    return None


def normalize_output(tool: str, output: Any, store: StructuredStore) -> None:
    evidence_content: str
    if isinstance(output, (dict, list)):
        try:
            evidence_content = json.dumps(output, ensure_ascii=False)
        except Exception:
            evidence_content = str(output)
    else:
        evidence_content = str(output)

    store.add_evidence(tool, evidence_content)

    data = _as_dict(output)

    # Unwrap standard tool output format
    if (
        data
        and "status" in data
        and "data" in data
        and "target" in data
        and isinstance(data["data"], dict)
    ):
        target = data["target"]
        data = data["data"].copy()
        if "domain" not in data:
            data["domain"] = target
        if "host" not in data:
            data["host"] = target

    if data:
        ingestor = _STRUCTURED_INGESTORS.get(tool)
        if ingestor:
            ingestor(data, store)
        return

    if isinstance(output, str):
        text_ingestor = _TEXT_INGESTORS.get(tool)
        if text_ingestor:
            text_ingestor(output, store)


def _ingest_virustotal(data: dict[str, Any], store: StructuredStore) -> None:
    domain = data.get("domain")
    subdomains = data.get("subdomains") or []
    for sub in subdomains:
        store.add_host(sub)
    if domain:
        store.add_host(domain)


def _ingest_probe(data: dict[str, Any], store: StructuredStore) -> None:
    host = data.get("host") or data.get("domain")
    ip = data.get("ip")
    if not host:
        return
    services = data.get("services", [])
    for svc in services:
        store.add_service(
            hostname=host,
            port=svc.get("port", 0),
            protocol=svc.get("scheme", "tcp"),
            state="open" if svc.get("status") == "up" else "closed",
            name=svc.get("server"),
            extra=svc.get("note"),
        )
    store.add_host(hostname=host, ip=ip)


def _ingest_nmap(data: dict[str, Any], store: StructuredStore) -> None:
    host = data.get("host")
    if not host:
        return
    for svc in data.get("services", []):
        cves = [
            CVE(cve_id=c.get("id"), cvss=c.get("cvss"), source="nmap")
            for c in svc.get("cves", [])
        ]
        store.add_service(
            hostname=host,
            port=svc.get("port", 0),
            protocol=svc.get("protocol", "tcp"),
            state=svc.get("state", "unknown"),
            name=svc.get("name"),
            product=svc.get("product"),
            version=svc.get("version"),
            extra=svc.get("extra"),
            cves=cves,
        )


def _ingest_shodan(data: dict[str, Any], store: StructuredStore) -> None:
    for match in data.get("matches", []):
        host = match.get("ip") or match.get("ip_str") or match.get("host")
        if not host:
            continue
        port = match.get("port", 0)
        product = match.get("org") or match.get("product")
        store.add_service(
            hostname=str(host),
            port=port,
            protocol="tcp",
            state="open",
            name=match.get("service"),
            product=product,
            extra=match.get("data"),
        )


def _ingest_nmap_text(text: str, store: StructuredStore) -> None:
    host_match = re.search(r"Nmap scan report for ([^:\n]+)", text)
    host = host_match.group(1) if host_match else None
    if not host:
        return
    current_port = None
    services: list[dict[str, Any]] = []
    for line in text.splitlines():
        port_match = re.search(r"Port: (\d+)", line)
        if port_match:
            if current_port:
                services.append(current_port)
            current_port = {
                "port": int(port_match.group(1)),
                "protocol": "tcp",
                "state": "open",
                "cves": [],
            }
            continue
        if current_port:
            if "State:" in line:
                current_port["state"] = line.split("State:")[-1].strip()
            if "Service:" in line:
                current_port["name"] = line.split("Service:")[-1].strip()
            if "Product:" in line:
                current_port["product"] = line.split("Product:")[-1].strip()
            if "Version:" in line:
                current_port["version"] = line.split("Version:")[-1].strip()
            cve_match = re.findall(r"CVE-\d{4}-\d{4,7}", line)
            for cve_id in cve_match:
                current_port.setdefault("cves", []).append({"id": cve_id})
    if current_port:
        services.append(current_port)
    for svc in services:
        cves = [CVE(cve_id=c.get("id"), source="nmap") for c in svc.get("cves", [])]
        store.add_service(
            hostname=host,
            port=svc.get("port", 0),
            protocol=svc.get("protocol", "tcp"),
            state=svc.get("state", "open"),
            name=svc.get("name"),
            product=svc.get("product"),
            version=svc.get("version"),
            cves=cves,
        )


def _ingest_probe_text(text: str, store: StructuredStore) -> None:
    host_match = re.search(r"Probing results for ([^:]+):", text)
    host = host_match.group(1) if host_match else None
    ip_match = re.search(r"IP Address: ([^\n]+)", text)
    ip = ip_match.group(1).strip() if ip_match else None
    if not host:
        return
    if "HTTP (Port 80): Found" in text:
        store.add_service(
            hostname=host, port=80, protocol="tcp", state="open", name="http"
        )
    if "HTTPS (Port 443): Found" in text:
        store.add_service(
            hostname=host, port=443, protocol="tcp", state="open", name="https"
        )
    store.add_host(hostname=host, ip=ip)


def _ingest_virustotal_text(text: str, store: StructuredStore) -> None:
    for line in text.splitlines():
        if line and "." in line and not line.startswith("Found"):
            store.add_host(line.strip())


def _ingest_shodan_text(text: str, store: StructuredStore) -> None:
    for match in re.finditer(r"IP:\s*([^,\n]+).*Port:\s*(\d+)", text):
        host = match.group(1).strip()
        port = int(match.group(2))
        store.add_service(hostname=host, port=port, protocol="tcp", state="open")


def _ingest_email(data: dict[str, Any], store: StructuredStore) -> None:
    email = data.get("email")
    if not email:
        return

    services = data.get("services") or {}
    if services:
        summary = {"email": email, "services": services}
        store.add_evidence(
            "analyze_email:services", json.dumps(summary, ensure_ascii=False)
        )

    breaches = data.get("breaches") or []
    for breach in breaches:
        breach_entry = {
            "email": email,
            "breach": breach.get("Name") or breach.get("name"),
            "domain": breach.get("Domain") or breach.get("domain"),
            "breach_date": breach.get("BreachDate") or breach.get("breach_date"),
            "records": breach.get("PwnCount") or breach.get("records"),
        }
        store.add_evidence(
            "analyze_email:breach", json.dumps(breach_entry, ensure_ascii=False)
        )

    reputation = data.get("reputation") or {}
    if reputation:
        rep_entry = {
            "email": email,
            "reputation": reputation.get("reputation"),
            "suspicious": reputation.get("suspicious"),
            "references": reputation.get("references"),
        }
        store.add_evidence(
            "analyze_email:reputation", json.dumps(rep_entry, ensure_ascii=False)
        )


def _ingest_censys(data: dict[str, Any], store: StructuredStore) -> None:
    results = data.get("results") or []
    for item in results:
        host = item.get("ip") or item.get("ip_address") or item.get("host")
        if not host:
            continue
        services = item.get("services") or []
        for svc in services:
            port = svc.get("port") or 0
            protocol = svc.get("service_name") or svc.get("transport_protocol") or "tcp"
            name = svc.get("service_name")
            product = svc.get("software") or svc.get("description")
            store.add_service(
                hostname=str(host),
                port=port,
                protocol=protocol,
                state="open",
                name=name,
                product=product,
            )
        store.add_host(str(host))


def _ingest_search(
    data: dict[str, Any], store: StructuredStore, source_tool: str = "search"
) -> None:
    # For search results, only evidence is stored; normalization is minimal
    summary = json.dumps(data, ensure_ascii=False)
    store.add_evidence(source_tool, summary)


def _ingest_httpx(data: dict[str, Any], store: StructuredStore) -> None:
    for entry in data.get("results", []):
        url = entry.get("url")
        host = entry.get("ip") or url
        port = entry.get("port") or (443 if str(url).startswith("https") else 80)
        store.add_evidence("httpx", json.dumps(entry, ensure_ascii=False))
        if host:
            store.add_service(
                hostname=str(host),
                port=int(port),
                protocol="tcp",
                state="open",
                name="http",
                product=entry.get("webserver"),
                version=entry.get("tls_version"),
            )


def _ingest_naabu(data: dict[str, Any], store: StructuredStore) -> None:
    for entry in data.get("results", []):
        host = entry.get("ip") or data.get("host")
        port = entry.get("port") or 0
        proto = entry.get("proto") or "tcp"
        if host:
            store.add_service(
                hostname=str(host), port=int(port), protocol=proto, state="open"
            )


def _ingest_nuclei(data: dict[str, Any], store: StructuredStore) -> None:
    for finding in data.get("findings", []):
        host = finding.get("host") or finding.get("ip") or data.get("target")
        matched = finding.get("matched")
        sev = finding.get("severity")
        title = finding.get("name") or finding.get("template_id")
        store.add_evidence("nuclei", json.dumps(finding, ensure_ascii=False))
        if matched:
            store.add_host(matched)
        if host:
            store.add_host(str(host))
        if title:
            store.add_evidence(
                "nuclei:finding",
                json.dumps(
                    {"title": title, "severity": sev, "matched": matched},
                    ensure_ascii=False,
                ),
            )


def _ingest_katana(data: dict[str, Any], store: StructuredStore) -> None:
    for url in data.get("urls", []):
        store.add_evidence("katana", url)


def _ingest_feroxbuster(data: dict[str, Any], store: StructuredStore) -> None:
    for entry in data.get("results", []):
        url = entry.get("url")
        store.add_evidence("feroxbuster", json.dumps(entry, ensure_ascii=False))
        if url:
            store.add_host(url)


def _ingest_wafw00f(data: dict[str, Any], store: StructuredStore) -> None:
    name = data.get("waf_name")
    if name:
        store.add_evidence("wafw00f", json.dumps(data, ensure_ascii=False))


_STRUCTURED_INGESTORS: dict[str, StructuredIngester] = {
    "virustotal_subdomain_enum": _ingest_virustotal,
    "probe_host": _ingest_probe,
    "nmap_port_scan": _ingest_nmap,
    "shodan_lookup": _ingest_shodan,
    "analyze_email": _ingest_email,
    "censys_lookup": _ingest_censys,
    "censys_web_lookup": _ingest_censys,
    "serp_search": lambda data, store: _ingest_search(
        data, store, source_tool="serp_search"
    ),
    "duckduckgo_lookup": lambda data, store: _ingest_search(
        data, store, source_tool="duckduckgo_lookup"
    ),
    "httpx_scan": _ingest_httpx,
    "naabu_scan": _ingest_naabu,
    "nuclei_scan": _ingest_nuclei,
    "katana_crawl": _ingest_katana,
    "feroxbuster_scan": _ingest_feroxbuster,
    "wafw00f_detect": _ingest_wafw00f,
}


_TEXT_INGESTORS: dict[str, TextIngester] = {
    "nmap_port_scan": _ingest_nmap_text,
    "probe_host": _ingest_probe_text,
    "virustotal_subdomain_enum": _ingest_virustotal_text,
    "shodan_lookup": _ingest_shodan_text,
}


BUILTIN_NORMALIZERS = normalize_output
