from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from src.models import CVE
from src.store import StructuredStore


def _as_dict(output: Any) -> Optional[Dict[str, Any]]:
    if isinstance(output, dict):
        return output
    if isinstance(output, str):
        try:
            return json.loads(output)
        except Exception:
            return None
    return None


def normalize_and_store(tool: str, output: Any, store: StructuredStore) -> None:
    """Tenta extrair hosts/serviços/CVEs de um resultado de tool e persistir."""
    evidence_content = None
    if isinstance(output, (dict, list)):
        try:
            evidence_content = json.dumps(output, ensure_ascii=False)
        except Exception:
            evidence_content = str(output)
    else:
        evidence_content = str(output)
    store.add_evidence(tool, evidence_content)

    data = _as_dict(output)
    if data:
        if tool == "virustotal_subdomain_enum":
            _ingest_virustotal(data, store)
        elif tool == "probe_host":
            _ingest_probe(data, store)
        elif tool == "nmap_port_scan":
            _ingest_nmap(data, store)
        elif tool == "shodan_lookup":
            _ingest_shodan(data, store)
        elif tool == "analyze_email":
            _ingest_email(data, store)
        return

    # fallback best-effort parsing for string outputs
    if isinstance(output, str):
        if tool == "nmap_port_scan":
            _ingest_nmap_text(output, store)
        elif tool == "probe_host":
            _ingest_probe_text(output, store)
        elif tool == "virustotal_subdomain_enum":
            _ingest_virustotal_text(output, store)
        elif tool == "shodan_lookup":
            _ingest_shodan_text(output, store)


def _ingest_virustotal(data: Dict[str, Any], store: StructuredStore) -> None:
    domain = data.get("domain")
    subdomains = data.get("subdomains") or []
    for sub in subdomains:
        store.add_host(sub)
    if domain:
        store.add_host(domain)


def _ingest_probe(data: Dict[str, Any], store: StructuredStore) -> None:
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


def _ingest_nmap(data: Dict[str, Any], store: StructuredStore) -> None:
    host = data.get("host")
    if not host:
        return
    for svc in data.get("services", []):
        cves = [CVE(cve_id=c.get("id"), cvss=c.get("cvss"), source="nmap") for c in svc.get("cves", [])]
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


def _ingest_shodan(data: Dict[str, Any], store: StructuredStore) -> None:
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
    services: List[Dict[str, Any]] = []
    for line in text.splitlines():
        port_match = re.search(r"Port: (\d+)", line)
        if port_match:
            if current_port:
                services.append(current_port)
            current_port = {"port": int(port_match.group(1)), "protocol": "tcp", "state": "open", "cves": []}
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
        store.add_service(hostname=host, port=80, protocol="tcp", state="open", name="http")
    if "HTTPS (Port 443): Found" in text:
        store.add_service(hostname=host, port=443, protocol="tcp", state="open", name="https")
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


def _ingest_email(data: Dict[str, Any], store: StructuredStore) -> None:
    email = data.get("email")
    if not email:
        return

    services = data.get("services") or {}
    if services:
        summary = {"email": email, "services": services}
        store.add_evidence("analyze_email:services", json.dumps(summary, ensure_ascii=False))

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
