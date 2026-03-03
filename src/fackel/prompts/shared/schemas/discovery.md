# Discovery Schema

A discovery represents a normalized, deduplicated fact extracted from
tool outputs during a scan.

## Required Fields

- **discovery_type**: Category of the discovery (see types below)
- **value**: The normalized, comparable value
- **raw_value**: The original value as reported by the tool
- **source_tool**: Which tool produced this discovery
- **source_phase**: Which scan phase produced this discovery
- **severity**: critical | high | medium | low | info
- **confidence**: 0.0 to 1.0

## Discovery Types

| Type               | Description                           | Example Value          |
|--------------------|---------------------------------------|------------------------|
| IP_ADDRESS         | IPv4 or IPv6 address                  | 192.168.1.1            |
| DOMAIN             | Domain or subdomain                   | sub.example.com        |
| OPEN_PORT          | TCP port with service                 | 443/tcp (nginx)        |
| VULNERABILITY      | CVE or misconfiguration               | CVE-2024-1234          |
| TECHNOLOGY         | Detected software/framework           | WordPress 6.4.2        |
| EMAIL_ADDRESS      | Email address found                   | admin@example.com      |
| CERTIFICATE        | TLS certificate details               | CN=example.com         |
| DNS_RECORD         | DNS record (A, MX, NS, TXT)          | MX: mail.example.com   |
| CLOUD_ASSET        | Cloud infrastructure                  | s3://bucket-name       |
| SENSITIVE_PATH     | Exposed path or endpoint              | /.env, /admin          |

## Deduplication

Discoveries are deduplicated by fingerprint: `sha256(type + normalized_value)`.
Multiple tools finding the same IP produce one discovery with multiple
source references.

## Severity Assignment

- **critical**: Exploitable vulnerability with public exploit
- **high**: Significant misconfiguration or known CVE
- **medium**: Information disclosure or weak configuration
- **low**: Minor issue, limited impact
- **info**: Intelligence only, no direct risk
