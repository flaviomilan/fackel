# Tools Reference

Complete reference for all 35 tool wrappers in Fackel. Each tool is a
LangChain `@tool`-decorated function with a Pydantic `BaseModel` input schema,
`ToolException`-based error handling, and standardised output envelope.

---

## Table of contents

- [Error handling](#error-handling)
- [Output envelope](#output-envelope)
- [Input validation](#input-validation)
- [Circuit breaker](#circuit-breaker)
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
  - [ipinfo_lookup](#ipinfo_lookup)
  - [bgp_lookup](#bgp_lookup)
  - [tlscert_lookup](#tlscert_lookup)
  - [securitytrails_history](#securitytrails_history)
  - [urlscan_search](#urlscan_search)
  - [otx_passive_dns](#otx_passive_dns)
  - [job_search](#job_search)
  - [analyze_email](#analyze_email)
  - [trufflehog_scan](#trufflehog_scan)
- [Recon tools (extended)](#recon-tools-extended)
  - [amass_enum](#amass_enum)
  - [subzy_check](#subzy_check)
  - [paramspider_crawl](#paramspider_crawl)
  - [whatweb_scan](#whatweb_scan)
  - [linkfinder_extract](#linkfinder_extract)
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
  - [wpscan_scan](#wpscan_scan)
  - [corsy_scan](#corsy_scan)
- [External binaries](#external-binaries)
- [Shared utilities](#shared-utilities)

---

## Error handling

All tools use **`ToolException`** for error propagation and **`handle_tool_error`**
for LLM-visible error messages:

```python
from langchain_core.tools import ToolException, tool

@tool(args_schema=MyInput)
def my_tool(target: str) -> dict:
    """Tool docstring."""
    target = guard_target(target, "my_tool", TargetType.DOMAIN)  # raises ToolException
    require_binary("my-bin", "my_tool")  # raises ToolException
    # ... implementation ...

my_tool.handle_tool_error = True  # type: ignore[attr-defined]
```

When a `ToolException` is raised and `handle_tool_error = True`, LangChain
converts the exception message into a `ToolMessage` with `status="error"`.
The LLM sees the error as a tool result and can self-correct (retry with
different arguments, try a different tool, or skip).

**Why `handle_tool_error` is set as an attribute (not a decorator parameter):**
`langchain_core` 1.2.9 does not support `@tool(handle_tool_error=True)` as a
decorator argument. The attribute must be set after function definition.

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

The orchestrator's `validate_tool_output()` in `streaming.py` detects both
`ToolException`-based errors (`msg.status == "error"`) and legacy envelope errors.

---

## Circuit breaker

HTTP-based tools (crt.sh, dnsdumpster, virustotal, urlscan, ipinfo, otx,
censys, securitytrails, shodan, webpage extractor) are wrapped in a
**per-service circuit breaker** (`src/tools/circuit_breaker.py`).

```python
from tools.circuit_breaker import circuit_breaker

with circuit_breaker("crtsh"):
    resp = get_session().get(url, timeout=30)
    resp.raise_for_status()
```

| Parameter | Value |
|-----------|-------|
| Failure threshold | 3 consecutive failures |
| Reset timeout | 60 seconds |
| States | closed → open → half-open → closed |

When a service’s circuit is **open**, subsequent calls raise `ToolException`
immediately with a clear message (“service temporarily disabled”), preventing
cascading timeouts.

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
| `ipinfo_lookup` | `IP` | IPv4/IPv6 | Domains, URLs |
| `bgp_lookup` | `IP` | IPv4/IPv6 | Domains, URLs |
| `tlscert_lookup` | `DOMAIN` | Domain | IPs, URLs |
| `securitytrails_history` | `DOMAIN` | Domain | IPs, URLs |
| `urlscan_search` | `DOMAIN` | Domain | IPs, URLs |
| `otx_passive_dns` | `DOMAIN` | Domain | IPs, URLs |
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
| `amass_enum` | `DOMAIN` | Domain | IPs, URLs |
| `subzy_check` | `DOMAIN` | Domain | IPs, URLs |
| `paramspider_crawl` | `DOMAIN` | Domain | IPs, URLs |
| `whatweb_scan` | `HOST_OR_URL` | Domain, IP, URL | — |
| `linkfinder_extract` | `HOST_OR_URL` | Domain, IP, URL | — |
| `wpscan_scan` | `HOST_OR_URL` | Domain, IP, URL | — |
| `corsy_scan` | `HOST_OR_URL` | Domain, IP, URL | — |

Tools not listed (`shodan_lookup`, `job_search`, `analyze_email`, `trufflehog_scan`) have custom
or no target validation (free-text inputs).

> **Note:** `httpx_scan` is shared between the **OSINT** and **Vuln Scan** agents.

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

### ipinfo_lookup

Look up IP geolocation, ASN, and organisation via ipinfo.io.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ip` | `str` | *(required)* | IPv4 address to look up (e.g. `104.21.36.250`). Returns ASN, organisation, CIDR, geolocation, and anycast flag. Call once per discovered IP to classify infrastructure. |

**Returns:**
- `ip` — queried IP address
- `hostname` — reverse hostname (if any)
- `city` — city name
- `region` — region / state
- `country` — country code
- `org` — organisation name (ASN holder)
- `asn` — AS number (e.g. `AS13335`)
- `anycast` — whether the IP is an anycast address (common for CDNs)

**Requires:** Nothing (free tier, no API key needed; 50 000 req/month)

---

### bgp_lookup

Look up ASN and prefix information for an IP via RIPEstat.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ip` | `str` | *(required)* | IPv4 address (e.g. `104.21.36.250`). Returns ASN, ASN holder, CIDR prefix, and RIR allocation. Call once per discovered IP to get BGP-level context. |

**Returns:**
- `ip` — queried IP address
- `asn` — AS number
- `asn_name` — short ASN holder name (e.g. `CLOUDFLARENET`)
- `asn_description` — full ASN holder description (e.g. `Cloudflare, Inc.`)
- `prefix` — announcing CIDR prefix
- `cidr` — prefix length as integer
- `rir` — Regional Internet Registry (ARIN, RIPE, APNIC, etc.)

**Requires:** Nothing (free public RIPEstat API, no authentication)

---

### tlscert_lookup

Inspect the TLS certificate of a host.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `hostname` | `str` | *(required)* | Domain name to inspect (e.g. `example.com`). Connects via TLS and extracts certificate metadata including SANs for subdomain discovery. |
| `port` | `int` | `443` | TCP port for the TLS connection (1–65535). |

**Returns:**
- `subject_cn` — certificate Subject Common Name
- `issuer_org` — issuer organisation name
- `issuer_cn` — issuer Common Name
- `san_domains` — Subject Alternative Name domains (useful for subdomain discovery)
- `serial` — certificate serial number (hex)
- `fingerprint_sha256` — SHA-256 fingerprint
- `not_before` — validity start date (ISO-8601)
- `not_after` — validity end date (ISO-8601)
- `protocol_version` — negotiated TLS protocol version
- `verified` — whether the certificate chain was trusted

**Requires:** Nothing (pure Python stdlib, no external binary)

---

### securitytrails_history

Look up historical DNS records via SecurityTrails.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `domain` | `str` | *(required)* | Domain name to query (e.g. `example.com`). Returns historical A, MX, and NS records — reveals previous IPs, hosting provider changes, and nameserver migrations. Old IPs may still be reachable and bypass CDN protection. |

**Returns:**
- `a_records` — list of `{value, first_seen, last_seen, org}` for historical A (IPv4) records
- `mx_records` — list of `{value, first_seen, last_seen, org}` for historical MX records
- `ns_records` — list of `{value, first_seen, last_seen, org}` for historical NS records

**Requires:** `SECURITYTRAILS_API_KEY` env var (free tier: 50 queries/month)

---

### urlscan_search

Search Urlscan.io for cached scan results of a domain.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `domain` | `str` | *(required)* | Domain name to search (e.g. `example.com`). Returns cached scan results from community scans — URLs, IPs, server headers, technologies, ASN info. |

**Returns:**
- `total` — total number of matching scans
- `results` — up to 10 most recent results, each containing:
  - `url` — scanned URL
  - `domain` — domain
  - `ip` — resolved IP
  - `server` — server header
  - `asn` / `asnname` — ASN number and name
  - `title` — page title
  - `status` — HTTP status code
  - `mime_type` — content MIME type
  - `country` — server country
  - `technologies` — detected protocols/technologies
  - `scan_time` — when the scan was performed
  - `visibility` — scan visibility (public/unlisted)

**Requires:** Nothing (free, no API key required)

---

### otx_passive_dns

Look up passive DNS records via AlienVault OTX.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `domain` | `str` | *(required)* | Domain name to query (e.g. `example.com`). Returns historical passive DNS records — IP resolutions with first-seen / last-seen timestamps. Complements SecurityTrails and other passive DNS sources. |

**Returns:**
- `count` — number of deduplicated records
- `records` — list of `{address, hostname, record_type, first_seen, last_seen, asn}`

**Requires:** `OTX_API_KEY` env var (free registration at AlienVault OTX)

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

### fofa_search

Search FOFA for internet-connected assets — passive reconnaissance alongside
Shodan and Censys. Discovers hosts, open ports, services, technologies, and
certificates indexed by FOFA's global scan engine.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `query` | `str` | *(required)* | FOFA query string. Use `domain=` for domain searches, `ip=` for IP lookups, or raw FOFA dork syntax. |

**Returns:**
- `results` — list of `{host, ip, port, protocol, server, title, domain, organization, banner}`
- `total` — total number of results in FOFA

**Requires:** `FOFA_EMAIL` + `FOFA_KEY` environment variables

---

### gau_urls

Fetch known URLs for a domain from passive historical sources (Wayback Machine,
Common Crawl, AlienVault OTX, URLScan). Discovers forgotten endpoints, admin
panels, API paths, and old versions that may still be live.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | `str` | *(required)* | Domain name to fetch known URLs for (e.g. `example.com`). Purely passive — no packets sent to the target. |

**Returns:**
- `urls` — sorted, deduplicated list of discovered URLs
- `count` — total number of unique URLs found

**Requires:** `gau` binary

---

### cloudbrute_enum

Enumerate cloud resources (storage buckets, apps, databases) across AWS, Azure,
GCP, and DigitalOcean for a given target keyword. Discovers misconfigured cloud
assets that may expose sensitive data.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `keyword` | `str` | *(required)* | Target keyword or company name (e.g. `acme-corp`). CloudBrute generates permutations. |
| `cloud` | `str` | `""` | Cloud provider: `aws`, `azure`, `gcp`, `digitalocean`, or empty for all. |

**Returns:**
- `resources` — list of `{provider, url, status}`
- `count` — total number of resources found

**Requires:** `cloudbrute` binary

---

### trufflehog_scan

Scan a Git repository or GitHub organisation for leaked secrets and credentials.
Detects API keys, tokens, passwords, and other sensitive data committed to source
control. Supports both individual repositories and full organisation scans.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | `str` | *(required)* | GitHub repo URL (e.g. `https://github.com/org/repo`) or org URL (e.g. `https://github.com/org`). |
| `only_verified` | `bool` | `True` | Only report secrets that TruffleHog has verified are still active. |

**Returns:**
- `findings` — list of `{detector, source_file, source_line, raw_secret, verified}`
- `count` — number of secrets found

**Requires:** `trufflehog` binary

---

## Recon tools (extended)

### amass_enum

Deep subdomain enumeration using OWASP Amass. Complements `subfinder_enum`
with additional data sources and active techniques.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | `str` | *(required)* | Root domain (e.g. `example.com`). |
| `passive` | `bool` | `True` | Passive mode only (no DNS brute-force). Set `False` for active enumeration. |
| `timeout_minutes` | `int` | `5` | Maximum enumeration time in minutes (clamped to 1–30). |

**Returns:**
- `subdomains` — sorted, deduplicated list of `{name, ips}` entries
- `count` — number of unique subdomains found

**Requires:** `amass` binary

---

### subzy_check

Check subdomains for potential subdomain takeover vulnerabilities. Detects
dangling CNAME records pointing to unclaimed cloud services (S3, GitHub Pages,
Heroku, Azure, etc.).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | `str` | *(required)* | Domain name to check — a single subdomain (e.g. `old.example.com`) or root domain. |
| `concurrency` | `int` | `10` | Number of concurrent checks (clamped to 1–50). |

**Returns:**
- `vulnerable` — list of `{subdomain, cname, service}` entries flagged as takeover-vulnerable
- `not_vulnerable` — list of `{subdomain, status}` entries confirmed safe
- `total_checked` — number of subdomains checked
- `vulnerable_count` — number of vulnerable subdomains

**Requires:** `subzy` binary

> **Active scanning tool** — included in `ACTIVE_SCAN_TOOLS` for human-in-the-loop
> gating when `approve_tools=True`.

---

### paramspider_crawl

Discover URL parameters for a domain from web archive sources (Wayback Machine).
Extracts unique parameter names from historically observed URLs — useful for
identifying hidden inputs, debug parameters, and potential injection points.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | `str` | *(required)* | Domain name (e.g. `example.com`). |
| `exclude` | `str` | `"png,jpg,gif,jpeg,swf,woff,svg,pdf,css"` | Comma-separated file extensions to exclude from results. |

**Returns:**
- `urls` — sorted list of discovered URLs containing parameters
- `params` — sorted list of unique parameter names
- `count` — total number of parameterised URLs

**Requires:** `paramspider` binary

---

### whatweb_scan

Identify web technologies, CMS platforms, JavaScript libraries, server software,
and frameworks using WhatWeb fingerprinting. Returns detailed technology
information with version numbers where available.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | `str` | *(required)* | Domain, IP, or URL to fingerprint. |
| `aggression` | `int` | `1` | Scan aggressiveness: 1 = stealthy (default), 2 = medium, 3 = aggressive. Clamped to 1–3. |

**Returns:**
- `technologies` — list of `{name, version, detail}` for each detected technology
- `target_url` — URL that was scanned

**Requires:** `whatweb` binary (Ruby gem)

---

### linkfinder_extract

Extract API endpoints and URLs from JavaScript files and HTML pages using
LinkFinder. Discovers JS-defined routes, API paths, and hidden endpoints not
visible through regular crawling.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | `str` | *(required)* | URL or domain to analyse (e.g. `https://example.com`). Scheme auto-added if missing. |

**Returns:**
- `absolute_urls` — list of fully-qualified URLs found in JavaScript
- `relative_paths` — list of relative paths and routes
- `total` — total number of unique endpoints discovered

**Requires:** `linkfinder` binary (Python package)

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

### dalfox_scan

Scan a URL for XSS vulnerabilities using DalFox. Analyses URL parameters for
reflected, stored, and DOM-based XSS. Tests with multiple payloads and evasion
techniques. Returns confirmed vulnerabilities with proof-of-concept payloads.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | `str` | *(required)* | URL to scan for XSS. URLs with query parameters are ideal — DalFox analyses each parameter for injection points. |

**Returns:**
- `findings` — list of `{type, severity, poc_url, param, payload, message, cwe}`
- `count` — number of confirmed XSS vulnerabilities

**Requires:** `dalfox` binary

> **Active scanning tool** — included in `ACTIVE_SCAN_TOOLS` for human-in-the-loop
> gating when `approve_tools=True`.

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

### s3scanner_scan

Scan an S3-compatible bucket for permission misconfigurations. Checks whether
a bucket exists, is publicly listable, publicly writable, or allows
authenticated access. Covers AWS S3, GCP Cloud Storage, and DigitalOcean Spaces.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `bucket` | `str` | *(required)* | S3 bucket name to scan (e.g. `example-backup`, `acme-uploads`). |
| `provider` | `str` | `"aws"` | Cloud storage provider: `aws`, `gcp`, or `digitalocean`. |

**Returns:**
- `results` — list of `{bucket, exists, public, permissions: {read, write, read_acp, write_acp, full_control}, num_objects, size, region}`

**Requires:** `s3scanner` binary

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

### wpscan_scan

Scan a WordPress site for vulnerabilities in core, plugins, themes, and users.
Identifies outdated components, known CVEs, weak configurations, and user
enumeration opportunities.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | `str` | *(required)* | WordPress site URL or domain. Scheme auto-added if missing. |
| `enumerate` | `str` | `"vp,vt,u"` | WPScan enumerate options: `vp` (vulnerable plugins), `vt` (vulnerable themes), `u` (users). |

**Returns:**
- `version` — WordPress version information (or `null`)
- `plugins` — list of `{slug, version, vulnerabilities}`
- `themes` — list of `{slug, version, vulnerabilities}`
- `users` — list of enumerated usernames
- `vulnerability_count` — total number of vulnerabilities found

**Requires:** `wpscan` binary (Ruby gem) + `WPSCAN_API_TOKEN` environment variable

> **Active scanning tool** — included in `ACTIVE_SCAN_TOOLS` for human-in-the-loop
> gating when `approve_tools=True`.

---

### corsy_scan

Detect CORS (Cross-Origin Resource Sharing) misconfigurations on a target URL.
Tests for wildcard origins, null origin trusting, credential leakage, and other
CORS policy weaknesses that could enable cross-origin attacks.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `target` | `str` | *(required)* | URL or domain to test. Scheme auto-added if missing. |

**Returns:**
- `issues` — list of `{url, type, description, severity}`
- `count` — number of CORS issues found

**Requires:** `corsy` binary (Python package)

---

## External binaries

Fackel wraps several security tools via subprocess. Install the ones you need:

| Binary | Tool(s) | Install |
|--------|---------|---------|
| `subfinder` | `subfinder_enum` | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `naabu` | `naabu_scan` | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| `nmap` | `nmap_port_scan` | `apt install nmap` / `brew install nmap` |
| `nuclei` | `nuclei_scan` | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `httpx` | `httpx_scan` | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `katana` | `katana_crawl` | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| `gau` | `gau_urls` | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| `dalfox` | `dalfox_scan` | `go install github.com/hahwul/dalfox/v2@latest` |
| `cloudbrute` | `cloudbrute_enum` | `go install github.com/0xsha/CloudBrute@latest` |
| `s3scanner` | `s3scanner_scan` | `go install github.com/sa7mon/S3Scanner@latest` |
| `feroxbuster` | `feroxbuster_scan` | `cargo install feroxbuster` or package manager |
| `wafw00f` | `wafw00f_detect` | `pip install wafw00f` |
| `testssl.sh` | `testssl_scan` | `git clone https://github.com/drwetter/testssl.sh.git` |
| `whois` | `whois_lookup` | `apt install whois` / `brew install whois` |
| `amass` | `amass_enum` | `go install github.com/owasp-amass/amass/v4/...@master` |
| `subzy` | `subzy_check` | `go install github.com/PentestPad/subzy@latest` |
| `paramspider` | `paramspider_crawl` | `pipx install paramspider` |
| `whatweb` | `whatweb_scan` | `gem install whatweb` / `apt install whatweb` |
| `linkfinder` | `linkfinder_extract` | `pipx install linkfinder` |
| `trufflehog` | `trufflehog_scan` | `pipx install trufflehog` |
| `wpscan` | `wpscan_scan` | `gem install wpscan` |
| `corsy` | `corsy_scan` | `pipx install corsy` |

> **Automated install:** Run `./scripts/install-tools.sh` to install all binaries
> automatically, or `./scripts/install-tools.sh --check` to audit which are present.

**Missing binary handling:** Tools use `require_binary()` — if the binary is not
found in `$PATH`, the tool raises `ToolException`. With `handle_tool_error = True`,
the LLM sees the error and can try alternative tools.

**Configurable timeouts:** Each tool's subprocess timeout can be overridden via
`FACKEL_TIMEOUT_{TOOL_NAME}` environment variable (value in seconds). The
`get_tool_timeout(tool_name, default)` helper reads these env vars.

---

## Shared utilities

Defined in `src/fackel/tooling/execution.py`:

| Function | Signature | Purpose |
|----------|-----------|----------|
| `run_command` | `(cmd, timeout=180) → (returncode, stdout, stderr)` | Execute subprocess with timeout |
| `format_tool_output` | `(tool, target, status, data, error) → dict` | Standard output envelope |
| `require_binary` | `(binary, tool_name) → None` | Raises `ToolException` if binary missing from PATH |
| `require_env` | `(key, tool_name) → str` | Returns env var value or raises `ToolException` |
| `get_tool_timeout` | `(tool_name, default) → int` | Reads `FACKEL_TIMEOUT_{TOOL}` env var or returns default |
| `parse_jsonl` | `(output) → list[dict]` | Parse newline-delimited JSON safely |
| `DEFAULT_TIMEOUT` | `180` | Default subprocess timeout in seconds |
