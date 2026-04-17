# Nmap Tool Contract

## Identity

- **Tool name**: `nmap_port_scan`
- **Category**: Scanning / Active
- **Requires approval**: Yes (active scanning tool)

## Purpose

Detailed TCP port scanning with service version detection (-sV) and
default scripts (-sC). Used after naabu discovers open ports.

## Input Contract

| Parameter          | Type   | Required | Description                    |
|--------------------|--------|----------|--------------------------------|
| host               | string | yes      | IP address or hostname         |
| ports              | string | no       | Comma-separated port list      |
| scan_type          | string | no       | "default" (-sV -sC)           |
| skip_host_discovery| bool   | no       | Skip ping check (-Pn)         |

## Output Contract

Returns a JSON envelope:

```json
{
  "tool": "nmap_port_scan",
  "target": "<host>",
  "status": "ok|error",
  "data": {
    "target": "example.com",
    "state": "up",
    "hostnames": [{"name": "example.com", "type": "user"}],
    "addresses": {"ipv4": "203.0.113.10"},
    "os_info": {
      "os_matches": [{"name": "Linux 5.x", "accuracy": 95}],
      "os_classes": [{"type": "general purpose", "vendor": "Linux", "osfamily": "Linux", "osgen": "5.X", "accuracy": 95}]
    },
    "host_scripts": {"smb-os-discovery": "..."},
    "services": [
      {
        "port": 443,
        "protocol": "tcp",
        "state": "open",
        "service": "https",
        "product": "nginx",
        "version": "1.24",
        "extrainfo": "",
        "cpe": "cpe:/a:nginx:nginx:1.24",
        "vulnerabilities": [{"id": "CVE-2024-1234", "cvss": 7.5, "source": "vulners"}],
        "scripts": {"http-title": "Example"}
      }
    ],
    "summary": {
      "total_ports_scanned": 100,
      "open_ports": 3,
      "filtered_ports": 0,
      "total_vulnerabilities": 1,
      "os_detected": true
    }
  }
}
```

> `os_info` and `-O` flag are only present when the agent runs as
> root (Nmap requires raw sockets for OS fingerprinting).

## Expected Discoveries

- OPEN_PORT for each discovered port
- TECHNOLOGY for each identified service version

## Failure Modes

- Timeout on filtered hosts → use `skip_host_discovery=true`
- Permission denied → requires root/capabilities for SYN scan
- Host unreachable → report as failure, do not retry

## Interaction Rules

- Always use after naabu for targeted port lists
- Prefer `scan_type="default"` for service identification
- Do not scan more than 10 hosts in a single batch
