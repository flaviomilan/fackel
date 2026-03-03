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
  "status": "success|error",
  "data": {
    "ports": [
      {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "version": "nginx 1.24"}
    ]
  }
}
```

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
