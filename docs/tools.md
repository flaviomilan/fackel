# Tools Reference

Complete reference for all 25 tool wrappers in Fackel. Each tool is a
LangChain `@tool`-decorated function with a Pydantic `BaseModel` input schema
and standardised output envelope.

---

## Table of contents

- [Output envelope](#output-envelope)
- [Input validation](#input-validation)
- [OSINT tools](#osint-tools)
  - [dns_resolve](#dns_resolve)
  - [whois_lookup](#whois_lookup)
  - [shodan_lookup](#shodan_lookup)
  - [censys_lookup](#censys_lookup)
  - [dnsdumpster_lookup](#dnsdumpster_lookup)
  - [virustotal_subdomain_enum](#virustotal_subdomain_enum)
  - [crtsh_subdomain_enum](#crtsh_subdomain_enum)
  - [subfinder_enum](#subfinder_enum)
  - [reverse_dns_lookup](#reverse_dns_lookup)
  - [job_search](#job_search)
  - [analyze_email](#analyze_email)
- [Port scan tools](#port-scan-tools)
  - [naabu_scan](#naabu_scan)
  - [nmap_port_scan](#nmap_port_scan)
- [Vulnerability scan tools](#vulnerability-scan-tools)
  - [nuclei_scan](#nuclei_scan)
  - [httpx_scan](#httpx_scan)
  - [wafw00f_detect](#wafw00f_detect)
  - [graphql_scan](#graphql_scan)
  - [feroxbuster_scan](#feroxbuster_scan)
  - [katana_crawl](#katana_crawl)
  - [testssl_scan](#testssl_scan)
  - [extract_webpage_content](#extract_webpage_content)
- [Available but unwired tools](#available-but-unwired-tools)
- [External binaries](#external-binaries)
- [Shared utilities](#shared-utilities)

---

## Output envelope

All tools return a standardised dict via `format_tool_output()`:

```python
{
    "tool": "tool_name",
    "target": "example.com",
    "status": "success" | "error",
    "data": { ... },      # Tool-specific payload (on success)
    "error": "message"    # Error description (on failure)
}
```

The orchestrator's `_validate_tool_output()` checks for this envelope and logs
warnings for malformed outputs.

---

## Input validation

Every tool that accepts a target validates its input via `guard_target()` before
any processing. See [input-validation.md](input-validation.md) for the full
specification of the validation system.

**Quick reference — accepted target types per tool:**

| Tool | `TargetType` | Accepts | Rejects |
|------|-------------|---------|---------|
| `dns_resolve` | `HOST` | Domain, IP | URLs |
| `whois_lookup` | `DOMAIN` | Domain | IPs, URLs |
| `censys_lookup` | `HOST` | Domain, IP | URLs |
| `dnsdumpster_lookup` | `DOMAIN` | Domain | IPs, URLs |
| `virustotal_subdomain_enum` | `DOMAIN` | Domain | IPs, URLs |
| `crtsh_subdomain_enum` | `DOMAIN` | Domain | IPs, URLs |
| `subfinder_enum` | `DOMAIN` | Domain | IPs, URLs |
| `reverse_dns_lookup` | `IP` | IPv4/IPv6 | Domains, URLs |
| `naabu_scan` | `HOST` | Domain, IP | URLs |
| `nmap_port_scan` | `HOST` | Domain, IP | URLs |
| `nuclei_scan` | `DOMAIN` | Domain | IPs, URLs |
| `httpx_scan` | `HOST_OR_URL` | Domain, IP, URL | — |
| `wafw00f_detect` | `HOST_OR_URL` | Domain, IP, URL | — |
| `graphql_scan` | `URL` | Full URL | Bare domains/IPs |
| `feroxbuster_scan` | `HOST_OR_URL` | Domain, IP, URL | — |
| `katana_crawl` | `HOST_OR_URL` | Domain, IP, URL | — |
| `testssl_scan` | `HOST` | Domain, IP | URLs |
| `extract_webpage_content` | `URL` | Full URL | Bare domains/IPs |

Tools not listed (`shodan_lookup`, `job_search`, `analyze_email`) have custom
or no target validation (free-text inputs).

All target types reject **shell metacharacters** (`; & | \` $ ( ) { } ! [ ] < > ' " \ \n \r`).

---

## OSINT tools

### dns_resolve

Resolve a domain to its IP addresses (A + AAAA records), or validate an IP.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | `str` | *(required)* | Domain name or bare IP address. Do NOT pass URLs. |

**Returns:**
- `target` — input value
- `ips` — list of resolved IPv4/IPv6 addresses
- `type` — `"domain"` or `"ip"`

**Requires:** Nothing (uses stdlib `socket`)

---

### whois_lookup

Query WHOIS registration data for a domain.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `domain` | `str` | *(required)* | Root domain name (e.g. `example.com`). No IPs, URLs, or subdomains. |

**Returns:**
- `registrar` — registrar name (or `null`)
- `name_servers` — list of nameserver hostnames
- `creation_date` / `expiration_date` — ISO date strings (or `null`)
- `raw` — raw WHOIS text (truncated to 2000 chars)
- `parsed` — whether structured parsing succeeded

**Requires:** `whois` binary (fallback when python-whois fails)

---

### shodan_lookup

Query Shodan for passive intelligence — no packets sent to the target.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `query` | `str` | *(required)* | IP address for host API, or Shodan search query (e.g. `hostname:example.com`) for broader discovery. |

**Returns (IP mode):**
- `ip`, `org`, `isp`, `os`, `hostnames`, `ports`, `city`, `country_name`
- `vulns` — known CVEs
- `services` — list of `{port, transport, product, version, banner, module}`

**Returns (search mode):**
- `total` — match count
- `matches` — list of `{ip, port, org, data, service}`

**Requires:** `SHODAN_API_KEY` environment variable

---

### censys_lookup

Search host and service data via the Censys REST API.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `domain` | `str` | *(required)* | Domain or IP to search. |

**Returns:**
- `hosts` — list of `{ip, services: [{port, protocol, name}]}`

**Requires:** `CENSYS_API_ID` + `CENSYS_API_SECRET` environment variables

---

### dnsdumpster_lookup

Discover subdomains, DNS records, and hosting information via DNSDumpster.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `domain` | `str` | *(required)* | Root domain (e.g. `example.com`). No IPs, URLs, or subdomains. |

**Returns:**
- `hosts` — list of `{hostname, ip, asn, provider}`
- `dns_servers` — list of nameserver hostnames
- `mx_records` — list of mail servers
- `txt_records` — list of TXT record values

**Requires:** Nothing (web scraping)

---

### virustotal_subdomain_enum

Enumerate subdomains passively via VirusTotal's global sensor network.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `domain` | `str` | *(required)* | Root domain (e.g. `example.com`). |

**Returns:**
- `count` — number of subdomains found
- `subdomains` — sorted list of subdomain FQDNs

**Requires:** `VIRUSTOTAL_API_KEY` environment variable

---

### crtsh_subdomain_enum

Enumerate subdomains via Certificate Transparency logs (crt.sh).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `domain` | `str` | *(required)* | Root domain (e.g. `example.com`). Queries CT logs for all certificates issued to `*.domain`. |

**Returns:**
- `count` — number of unique subdomains
- `subdomains` — sorted, deduplicated list

**Requires:** Nothing (crt.sh public API)

---

### subfinder_enum

Enumerate subdomains passively using subfinder (40+ sources).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `domain` | `str` | *(required)* | Root domain (e.g. `example.com`). |
| `all_sources` | `bool` | `False` | Use all available sources (slower, more thorough). |
| `timeout` | `int` | `30` | Maximum seconds for enumeration. |

**Returns:**
- `subdomains` — sorted list of FQDNs
- `count` — number found
- `sources` — sorted list of data source names
- `details` — list of `{subdomain, source}`

**Requires:** `subfinder` binary

---

### reverse_dns_lookup

Reverse-resolve an IP to its PTR hostname and discover co-hosted domains.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ip` | `str` | *(required)* | IPv4 address. Call once per discovered IP to detect shared hosting. |

**Returns:**
- `ptr_hostname` — PTR record (or `null`)
- `ptr_aliases` — additional names
- `shared_domains` — domains sharing this IP
- `shared_domain_count` — count of co-hosted domains

**Requires:** Nothing (stdlib `socket` + HackerTarget API)

---

### job_search

Search job postings to identify technologies used by the target organisation.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `company_name` | `str` | *(required)* | Company or organisation name. |

**Returns:**
- `results` — list of `{title, body, url, type}` where `type` is `"job"` or `"career_page"`

**Requires:** `ddgs` Python package

---

### analyze_email

Analyse an email address for breach exposure (HIBP) and reputation (EmailRep).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `email` | `str` | *(required)* | Email address to analyse. |

**Returns:**
- `breaches` — list of breach records from HaveIBeenPwned
- `reputation` — reputation data from EmailRep (or `null`)

**Requires:** `HIBP_API_KEY` (optional, graceful degradation), `EMAILREP_API_KEY` (optional)

---

## Port scan tools

### naabu_scan

Fast SYN-based TCP port discovery using naabu.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | `str` | *(required)* | IP address or domain. One target per call. |
| `ports` | `str` | `""` | Comma-separated ports or ranges (e.g. `80,443,8000-9000`). Mutually exclusive with `top_ports`. |
| `top_ports` | `str` | `""` | Scan N most common ports (`100` for quick, `1000` for thorough). Ignored when `ports` is set. |
| `rate` | `int` | `0` | Packets per second (0 = naabu default ~1000). |
| `skip_cdn` | `bool` | `False` | Skip CDN ports (Cloudflare, Akamai, etc.). |

**Returns:**
- `results` — list of JSONL records, each containing `host`, `ip`, `port`

**Requires:** `naabu` binary

---

### nmap_port_scan

Advanced Nmap scan with version detection, OS fingerprinting, and NSE
vulnerability scripts.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | `str` | *(required)* | IP address or domain. One target per call. |
| `ports` | `str` | `""` | Comma-separated ports. Feed ports from `naabu_scan` for targeted analysis. |
| `scan_type` | `str` | `"default"` | `default` = version + vuln scripts + T4 timing; `quick` = version only; `deep` = all 65535 ports. |
| `skip_host_discovery` | `bool` | `False` | Skip host discovery (`-Pn`). Use when host drops ICMP. |

**Returns:**
- `target`, `state`, `hostnames`, `addresses`
- `os_info` — `{os_matches: [{name, accuracy}], os_classes: [{type, vendor, osfamily, osgen, accuracy}]}`
- `services` — list of `{port, protocol, state, service, product, version, extrainfo, cpe, vulnerabilities, scripts}`
- `summary` — `{total_ports_scanned, open_ports, filtered_ports, total_vulnerabilities, os_detected}`

**Requires:** `nmap` binary + `python-nmap` package

---

## Vulnerability scan tools

### nuclei_scan

Scan for vulnerabilities, misconfigurations, and technologies using Nuclei's
community-maintained template engine.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | `str` | *(required)* | Domain name, subdomain, or full URL. **Never pass raw IPs** — nuclei templates rely on DNS/SSL/SNI. |
| `severity` | `str` | `""` | Comma-separated severity filter: `critical`, `high`, `medium`, `low`, `info`. Empty = all. |
| `tags` | `str` | `""` | Comma-separated template tags (e.g. `cve,wordpress`, `tech,misconfig`). |

**Returns:**
- `total` — number of findings
- `findings` — list of `{template_id, matcher_name, name, severity, matched_at, type, host, ip, tags, description, extracted_results, curl_command}`

**Requires:** `nuclei` binary

---

### httpx_scan

HTTP probing and web surface mapping using ProjectDiscovery's httpx.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `domain` | `str` | *(required)* | IP, domain, or full URL to probe. |
| `ports` | `str` | `""` | Comma-separated ports (e.g. `80,443,8080`). Feed from naabu/nmap. |
| `tech_detect` | `bool` | `True` | Enable technology fingerprinting. |
| `follow_redirects` | `bool` | `True` | Follow HTTP redirects. |
| `status_code` | `bool` | `True` | Include HTTP status codes. |
| `title` | `bool` | `True` | Include HTML page titles. |

**Returns:**
- `results` — list of JSONL records with URL, status, title, tech, content-length, etc.

**Requires:** `httpx` binary (ProjectDiscovery's, not the Python library)

---

### wafw00f_detect

Detect Web Application Firewalls (WAF) protecting a web target.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | `str` | *(required)* | Domain name or URL. Use domain names, not bare IPs. |
| `check_all` | `bool` | `False` | Test all WAF signatures (slower). Default stops after first match. |

**Returns:**
- `identified` — list of identified WAFs
- `waf_name` — primary WAF name (or `null`)
- `manufacturer` — WAF manufacturer (or `null`)

**Requires:** `wafw00f` binary (`pip install wafw00f`)

---

### graphql_scan

Scan a GraphQL endpoint for security misconfigurations.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | `str` | *(required)* | Full URL of the GraphQL endpoint (e.g. `https://example.com/api/graphql`). |

**Returns:**
- `introspection_enabled` — whether introspection is exposed
- `schema_summary` — `{total_types, type_names, queries, mutations, has_mutations}`
- `issues` — list of `{issue, severity, detail}`
- `total_issues` — count of issues found

**Requires:** Nothing (`requests` library)

---

### feroxbuster_scan

Recursive directory and content discovery via feroxbuster.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | `str` | *(required)* | URL or domain. Scheme auto-added if missing. Discovers admin panels, backup files, config endpoints. |

**Returns:**
- `results` — list of `{url, status, length, mime, words, lines}`

**Requires:** `feroxbuster` binary

---

### katana_crawl

Crawl a web target to discover URLs, endpoints, and JavaScript routes.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | `str` | *(required)* | URL or domain. Scheme auto-added if missing. Spiders the site, discovers JS-defined API endpoints. |

**Returns:**
- `urls` — sorted, deduplicated list of discovered URLs

**Requires:** `katana` binary

---

### testssl_scan

Deep TLS/SSL analysis: protocols, ciphers, certificate chain, and known
vulnerabilities (Heartbleed, POODLE, BEAST, ROBOT, DROWN, Logjam, etc.).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | `str` | *(required)* | Hostname, hostname:port, or IP:port. Defaults to port 443. |
| `severity` | `str` | `""` | Filter by severity: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. Comma-separated. |
| `checks` | `str` | `""` | Specific checks: `protocols`, `ciphers`, `vulnerabilities`, `headers`, `certificate`. Empty = full scan. |

**Returns:**
- `findings` — list of `{id, severity, finding, cve, cwe}`
- `summary` — `{total, critical, high, medium, low, info, protocols_checked, cert_findings, vulnerabilities}`

**Requires:** `testssl.sh` binary

---

### extract_webpage_content

Extract relevant text content from a web page, stripping HTML boilerplate.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | `str` | *(required)* | Full URL (must include `http://` or `https://`). |

**Returns:**
- `content` — extracted text (truncated to 2000 chars)

**Requires:** Nothing (`requests` + `beautifulsoup4`)

---

## External binaries

Fackel wraps several security tools via subprocess. Install the ones you need:

| Binary | Tool(s) | Install |
|--------|---------|---------|
| `naabu` | `naabu_scan` | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| `nmap` | `nmap_port_scan` | `apt install nmap` / `brew install nmap` |
| `nuclei` | `nuclei_scan` | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `httpx` | `httpx_scan` | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `subfinder` | `subfinder_enum` | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `katana` | `katana_crawl` | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| `feroxbuster` | `feroxbuster_scan` | `cargo install feroxbuster` or package manager |
| `wafw00f` | `wafw00f_detect` | `pip install wafw00f` |
| `testssl.sh` | `testssl_scan` | `git clone https://github.com/drwetter/testssl.sh.git` |
| `whois` | `whois_lookup` | `apt install whois` / `brew install whois` |

**Missing binary handling:** Tools use `require_binary()` — if the binary is not
found in `$PATH`, the tool returns a clean error dict instead of crashing.
The LLM sees the error and can try alternative tools.

---

## Shared utilities

Defined in `src/fackel/tooling/execution.py`:

| Function | Signature | Purpose |
|----------|-----------|---------|
| `run_command` | `(cmd, timeout=180) → (returncode, stdout, stderr)` | Execute subprocess with timeout |
| `format_tool_output` | `(tool, target, status, data, error) → dict` | Standard output envelope |
| `require_binary` | `(binary, tool_name, target) → dict \| None` | Check binary in PATH, return error if missing |
| `require_env` | `(key, tool_name, target) → (value, None) \| (None, error)` | Check env var, return error if missing |
| `parse_jsonl` | `(output) → list[dict]` | Parse newline-delimited JSON safely |
| `DEFAULT_TIMEOUT` | `180` | Default subprocess timeout in seconds |
