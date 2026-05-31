# Tool — Port Scanning

## Purpose

Identify open ports, active services, and software versions on
target hosts to map network attack surface.

## Tools

| Tool            | Purpose                                         |
|-----------------|---------------------------------------------------|
| `naabu_scan`    | Fast port scan (SYN scan, top-1000)        |
| `nmap_port_scan`| Deep scan — service detection, versions, scripts|

## Usage Rules

1. **naabu first** — fast scan to identify open ports.
2. **nmap afterwards** — detailed scan (-sV -sC) only on ports that
   naabu found.
3. **Never nmap full scan (-p-)** on all hosts — use naabu to filter first.
4. **Service version mandatory** — `nmap -sV` always, version is
   essential for CVE matching.
5. **Selective NSE scripts** — use `--script=default,vuln` only on
   priority hosts.

## Scope Boundaries

- Only authorized IPs/hosts.
- Respect configured rate limits.
- Do not run exploit scripts (--script=exploit).
- UDP scan only when justified (DNS, SNMP, NTP).

## Fallback Strategy

| Scenario                 | Action                                        |
|--------------------------|---------------------------------------------|
| Host filtered/firewalled | Document as "filtered", do not retry    |
| naabu timeout            | Reduce rate, try top-100 ports          |
| nmap -sV without result  | Try with --version-intensity 9            |
| IDS/IPS detected         | Reduce aggressiveness, document           |

## Output Structure

```json
{
  "tool": "nmap_port_scan",
  "target": "203.0.113.10",
  "data": {
    "ports": [
      {
        "port": 22,
        "protocol": "tcp",
        "state": "open",
        "service": "ssh",
        "version": "OpenSSH 8.9p1",
        "product": "OpenSSH",
        "extra_info": "Ubuntu Linux"
      },
      {
        "port": 443,
        "protocol": "tcp",
        "state": "open",
        "service": "https",
        "version": "nginx 1.24.0",
        "product": "nginx"
      }
    ],
    "os_detection": "Linux 5.x",
    "total_open": 5,
    "scan_type": "SYN",
    "scan_duration_seconds": 45
  }
}
```

## Normalization

- Ports as integers (not strings).
- Protocols lowercase (tcp, udp).
- State: open, closed, filtered (nmap vocabulary).
- Service names standardized (http, https, ssh, not HTTP or SSH).

## Anomalies

- **High ports open (>10000)** → possible backdoor or custom service.
- **SSH on non-standard port** → possible hardening or evasion.
- **Outdated services** → check CVEs immediately.
- **Multiple web ports** (80, 443, 8080, 8443) → multiple applications,
   each is distinct surface.
- **Database ports exposed** (3306, 5432, 27017) → critical risk if
   externally accessible.
