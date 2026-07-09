# GhostMCP

**Doesn't exist until it finds what it's looking for.**

---

## What Is This

GhostMCP is a standalone OSINT search and reconnaissance toolkit that exposes its capabilities via the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/). It enables AI coding agents (Claude, GPT, etc.) to search the web, build Google dork queries, fetch URL content, perform passive domain reconnaissance, enumerate people and assets, and query threat intelligence — all without leaving the IDE.

Designed as both a **development workflow accelerator** (find answers faster) and an **OSINT/recon capability** (discover exposed infrastructure, sensitive files, threat intelligence, and people-linked data).

Can be called by any MCP client (opencode, Claude Desktop, VS Code Copilot, Cursor) or used standalone via CLI.

**v0.5.2** — 29 tools, 1,453 unit tests + 35 integration tests, all passing.

---

## Installation

### Prerequisites

- Python 3.9+
- `httpx` (HTTP client)
- `pytest` + `pytest-asyncio` (for tests)

### Quick Start

```bash
# Clone
git clone https://github.com/mswilliamrude/GhostMCP.git
cd GhostMCP

# Install dependencies
pip install httpx pytest pytest-asyncio

# Optional: better Google scraping stealth
pip install curl_cffi

# Optional: headless browser rendering
pip install playwright && playwright install chromium

# Verify it works
python3 -m pytest tests/ -v    # 1,453 unit tests, all passing
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | python3 -m ghostmcp
```

### Windows (MSYS2 UCRT64)

For running `ghost_client.py` on Windows with MSYS2:

```bash
# Required packages (UCRT64 — note the ucrt prefix)
pacman -S mingw-w64-ucrt-x86_64-python-httpx mingw-w64-ucrt-x86_64-python-websockets mingw-w64-ucrt-x86_64-python-yaml

# IMPORTANT: Do NOT use the non-ucrt packages (mingw-w64-x86_64-*)
# Those install to MINGW64 site-packages which UCRT64 Python cannot find.

# Run the bridge client
python3 ghost_client.py --config ~/.ghost_client.yaml
```

### Docker (Recommended)

Run GhostMCP with all services (including internal SearXNG for metasearch):

```bash
# Start everything
docker compose up -d

# Check status
docker compose ps

# View logs
docker compose logs -f ghostmcp

# Stop
docker compose down
```

This starts:
- **ghostmcp** — Main MCP server on port 8080
- **searxng** — Internal metasearch engine (not exposed externally)

The internal SearXNG instance is pre-configured for API access and OSINT-optimized engine selection. No additional setup required — `ghost_searxng` works out of the box.

#### Docker Environment Variables

```bash
# In docker-compose.yml or .env file:
GHOST_PARANOIA=cautious          # OpSec level: casual, cautious, ghost, midnight
GHOST_MIN_DELAY=2.0              # Minimum delay between requests
GHOST_SEARXNG_URL=http://searxng:8080  # Auto-configured

# Optional API keys (add to docker-compose.yml):
SERPER_API_KEY=xxx               # Google search via Serper
GHOST_REGRID_KEY=xxx             # Property/parcel data via Regrid
VT_API_KEY=xxx                   # VirusTotal lookups
GHOST_HIBP_KEY=xxx               # Have I Been Pwned breach checks
```

#### Exposing SearXNG UI (Optional)

To access the SearXNG web interface for debugging:

```yaml
# In docker-compose.yml, uncomment:
services:
  searxng:
    ports:
      - "8888:8080"  # Access at http://localhost:8888
```

### MCP Client Configuration

#### opencode / Claude Desktop / Cursor

Add to your MCP configuration (`opencode.json`, `claude_desktop_config.json`, etc.):

```json
{
  "mcp": {
    "ghostmcp": {
      "type": "local",
      "command": [
        "python3",
        "-m", "src"
      ],
      "enabled": true,
      "environment": {
        "PYTHONPATH": "/path/to/GhostMCP",
        "GHOST_PARANOIA": "cautious",
        "GHOST_MIN_DELAY": "2.0",
        "SERPER_API_KEY": "optional-for-google-results",
        "VT_API_KEY": "optional-for-virustotal",
        "GHOST_HIBP_KEY": "optional-for-breach-lookups"
      }
    }
  }
}
```

Restart your MCP client after adding the configuration.

---

## MCP Tools

GhostMCP exposes 29 tools via the Model Context Protocol, organized into four categories:

---

### 1. Search & Discovery

#### `ghost_search` — Anonymous Web Search

Search the web using multiple engines with intelligent round-robin rotation. Supported engines: serper, brave, bing, google, duckduckgo.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `query` | string | (required) | Search query |
| `engine` | string | `"auto"` | Engine: `auto`, `serper`, `brave`, `bing`, `google`, `duckduckgo` |
| `paranoia` | string | `"cautious"` | OpSec level: `casual`, `cautious`, `ghost`, `midnight` |
| `num_results` | integer | `10` | Number of results (max 100) |

**Background:** Auto mode tries engines in order of quality/reliability. Serper uses Google's index via API (best structured results, requires free API key). Google scraper parses raw HTML SERPs (no key needed but may get CAPTCHAs). DuckDuckGo Lite is the most reliable free option — uses the lightweight `lite.duckduckgo.com` endpoint with POST form submission and handles DDG's 202 throttle responses with exponential backoff retry.

**Example usage by an AI agent:**
```
"Search for Python asyncio best practices 2024"
→ ghost_search(query="Python asyncio best practices 2024")
→ Returns: 10 results with titles, URLs, and snippets
```

---

#### `ghost_searxng` — SearXNG Metasearch

Search using a SearXNG instance — aggregates results from 70+ search engines without tracking. Requires `GHOST_SEARXNG_URL` environment variable (auto-configured when using Docker Compose).

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `query` | string | (required) | Search query |
| `categories` | string | `"general"` | Categories: `general`, `images`, `news`, `videos`, `files`, `it`, `science` |
| `engines` | string | `""` | Specific engines: `google`, `bing`, `duckduckgo`, `wikipedia`, `github` |
| `time_range` | string | `""` | Time filter: `day`, `week`, `month`, `year` |
| `language` | string | `"en"` | Language code |
| `num_results` | integer | `10` | Number of results |

**Background:** SearXNG is a privacy-focused metasearch engine that aggregates results from multiple sources. When using Docker Compose, an internal SearXNG instance is automatically available with API access enabled and OSINT-optimized engine configuration.

**Example usage:**
```
"Search for CVE-2024 exploits using SearXNG"
→ ghost_searxng(query="CVE-2024 remote code execution", categories="it", time_range="month")
→ Returns: Results from Google, Bing, GitHub, StackOverflow aggregated
```

---

#### `ghost_dork` — Google Dorking

Build and optionally execute Google dork queries using operators or predefined templates. Dorking uses advanced search operators to find specific content that regular searches miss — exposed config files, admin panels, sensitive documents, etc.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `query` | string | `""` | Base search terms |
| `template` | string | (optional) | Predefined template name (see below) |
| `domain` | string | (optional) | Target domain (`site:` operator) |
| `filetype` | string | (optional) | File extension filter |
| `inurl` | string | (optional) | String that must appear in URL |
| `intitle` | string | (optional) | String that must appear in page title |
| `intext` | string | (optional) | String that must appear in page body |
| `exclude` | string | (optional) | Comma-separated terms to exclude |
| `execute` | boolean | `true` | Whether to run the search or just build the query |
| `engine` | string | `"auto"` | Search engine to use |
| `paranoia` | string | `"cautious"` | OpSec level |
| `num_results` | integer | `10` | Results count |

**Built-in Templates (12):**

| Template | What It Finds |
|----------|---------------|
| `exposed_configs` | Config files (.env, .yml, .ini, .conf) exposed on a domain |
| `login_pages` | Admin panels, login pages, auth endpoints |
| `directory_listing` | Open directory indexes (file listings) |
| `git_exposed` | Exposed .git directories and config |
| `env_files` | Environment files with credentials |
| `api_docs` | API documentation pages (Swagger, GraphQL) |
| `error_messages` | Stack traces, SQL errors, debug output |
| `tech_stack` | Technology identification (WordPress, Node, etc.) |
| `database_dumps` | Database exports (.sql, .db, .sqlite, .bak) |
| `sensitive_docs` | Confidential documents (PDF, XLSX, DOCX) |
| `subdomains` | Subdomain discovery via search |
| `backup_files` | Backup files (.bak, .old, .zip, .tar.gz) |

**Example:**
```
"Find exposed config files on example.com"
→ ghost_dork(template="exposed_configs", domain="example.com")
→ Builds: site:example.com (filetype:env OR filetype:yml ...) -github.com
→ Executes search and returns results
```

---

#### `ghost_fetch` — URL Content Extraction

Fetch a URL and extract its content in various formats. Supports text extraction, raw HTML, response headers, and link extraction. Uses stealth headers and proxy routing via the paranoia system. **No API key required.**

---

#### `ghost_recon` — Domain Reconnaissance

Passive reconnaissance on a target domain. Runs dorking-based modules to discover subdomains, exposed configurations, and technology stack. Composable modules: `subdomains`, `configs`, `tech`. **No API key required.**

---

#### `ghost_api` — Passive API Surface Discovery

Probes Swagger/OpenAPI endpoints, GraphQL introspection, robots.txt, OIDC discovery, security.txt, and well-known paths. Identifies framework and CORS policy. **No API key required.**

---

### 2. Security Intelligence

#### `ghost_hash` — Hash Intelligence

Look up a hash (MD5, SHA1, SHA256, SHA512) against threat intelligence services: CIRCL NSRL, MalwareBazaar, ThreatFox, VirusTotal. Can also compute hashes from a local file path. Returns verdict (clean/malicious/suspicious/unknown). **No API key required** (VT optional via `VT_API_KEY`).

---

#### `ghost_cve` — CVE Lookup

Look up a specific CVE by ID or search by keyword. Returns severity, CVSS score, EPSS exploit probability, and CISA KEV (Known Exploited Vulnerabilities) status. **No API key required.**

---

#### `ghost_vuln` — Package Vulnerability Check

Check a package for known vulnerabilities via OSV.dev. Supports PyPI, npm, Go, crates.io, and other ecosystems. **No API key required.**

---

#### `ghost_threat` — Threat Intelligence Feeds

Look up an indicator (URL, IP, domain, hash) across multiple threat feeds: URLhaus, ThreatFox, RansomWatch, and Feodo Tracker. **No API key required.**

---

#### `ghost_cert` — TLS Certificate Inspection

Connect to a host, pull the TLS certificate, and report subject, issuer, expiry, SANs, fingerprint, protocol, cipher suite, key type, chain, and self-signed/expired status. Includes A+ through F security grading with optional JARM TLS fingerprinting. **No API key required.**

---

#### `ghost_headers` — HTTP Security Header Analysis

Analyze HTTP security headers of a URL. Grades CSP, HSTS, X-Frame-Options, CORS policy, and more. Returns A+ through F grade with detailed findings and recommendations. **No API key required.**

---

#### `ghost_dns` — DNS Reconnaissance

Comprehensive DNS reconnaissance via DNS-over-HTTPS (zero dependencies). SPF/DMARC/DKIM email security analysis, dangling CNAME detection, SRV service discovery, SaaS provider identification from TXT records. **No API key required.**

---

### 3. Browser Automation

#### `ghost_render` — Headless Chromium Rendering

Render a web page using headless Chromium. Captures the rendered DOM (after JavaScript execution), console.log/error output, and uncaught JS errors. Essential for debugging SPAs (Vue, React, Angular) where raw HTML contains unresolved template syntax. Supports optional JavaScript execution and screenshots. **No API key required** (requires Playwright + Chromium installed).

---

### 4. People Search

#### `ghost_phone` — Phone Intelligence

Phone number validation, carrier lookup, CNAM (caller name) resolution, and reverse-phone search URL generation. Supports international numbers. **Free tier via Veriphone** (1000 lookups/mo). Optional: `GHOST_VERIPHONE_KEY`, `GHOST_TWILIO_SID`/`GHOST_TWILIO_TOKEN`, `GHOST_OPENCNAM_SID`/`GHOST_OPENCNAM_TOKEN`.

---

#### `ghost_email` — Email Intelligence

Email address investigation: reputation scoring (EmailRep), social account enumeration (Holehe-style), professional verification (Hunter.io), and breach history (HIBP). **Partially free.** Optional keys: `GHOST_EMAILREP_KEY`, `GHOST_HUNTER_KEY`, `GHOST_HIBP_KEY`.

---

#### `ghost_username` — Username Enumeration

Check username existence across 20+ social platforms. Uses Maigret/Sherlock-style HTTP probing with status code and content matching. **No API key required.**

---

#### `ghost_people` — People Search URL Generator

IntelTechniques-style URL generator for 15+ people-search sites (Pipl, ThatsThem, Whitepages, TruePeopleSearch, etc.). Generates ready-to-click search URLs from name, location, phone, or email inputs. **No API key required.**

---

#### `ghost_court` — Court Record Search

Search US federal and state court records via the CourtListener REST API. Find cases, opinions, and docket entries by name, keyword, or jurisdiction. **Free registration required.** Key: `GHOST_COURTLISTENER_TOKEN`.

---

#### `ghost_breach` — Breach Database Search

Search breach databases for compromised credentials and exposed data. Aggregates results from Have I Been Pwned, Snusbase, DeHashed, and LeakCheck. **Paid keys required** for full coverage. Keys: `GHOST_HIBP_KEY`, `GHOST_SNUSBASE_KEY`, `GHOST_DEHASHED_EMAIL`/`GHOST_DEHASHED_KEY`, `GHOST_LEAKCHECK_KEY`.

---

#### `ghost_ip` — IP Geolocation & Intelligence

IP address geolocation, ASN lookup, ISP identification, and proxy/VPN/Tor detection via ip-api.com. **No API key required** (free tier: 45 req/min).

---

#### `ghost_asn` — BGP/ASN Network Reconnaissance

BGP/ASN network infrastructure reconnaissance. Query by ASN number, IP address, or organization name. Returns announced prefixes, peers, IX presence, and related ASNs via BGPView API. **No API key required.**

---

#### `ghost_vin` — Vehicle Identification

VIN (Vehicle Identification Number) decode, safety recall lookup, and consumer complaint search via NHTSA APIs. Returns make, model, year, plant, and safety history. **No API key required.**

---

#### `ghost_gis` — Property & Parcel Lookup

Look up property/parcel data by address, coordinates, or parcel ID. Returns owner name, mailing address, assessed value, zoning, acreage, and generates investigation URLs for people search and county assessor sites.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `address` | string | `""` | Street address to look up |
| `lat` | float | `0.0` | Latitude (for coordinate lookup) |
| `lon` | float | `0.0` | Longitude (for coordinate lookup) |
| `parcel_id` | string | `""` | Direct parcel ID lookup |
| `provider` | string | `"auto"` | Data source: `auto`, `regrid`, `state` |

**Data Sources:**
- **Regrid API** (nationwide, 25 free/day with `GHOST_REGRID_KEY`)
- **State GIS** (TX 222 counties, FL 67, NY 40+, CO 32+) — free, no key

**Owner Type Detection:** Automatically classifies owners as individual, LLC, trust, corporation, partnership, financial institution, or government entity.

**Example usage:**
```
"Who owns 1600 Pennsylvania Ave NW, Washington DC?"
→ ghost_gis(address="1600 Pennsylvania Ave NW, Washington DC")
→ Returns: Owner, mailing address, value, plus TruePeopleSearch/OpenCorporates URLs
```

---

#### `ghost_media` — Media Search

Search for images, videos, or news via Brave Search API. Returns direct URLs, thumbnails, dimensions, duration, and source domains. **Requires `GHOST_BRAVE_KEY`.**

---

#### `ghost_perplexity` — AI Research with Citations

Query Perplexity AI for search-augmented answers with source citations. Best for research questions, technical lookups, current events, and anything needing up-to-date grounded answers. Models: `sonar` (fast), `sonar-pro` (default, better sources), `sonar-deep-research` (thorough). **Requires `GHOST_PERPLEXITY_KEY`.**

---

#### `ghost_auth_session` — Ephemeral Authentication Sessions

Create and manage ephemeral authentication sessions. Sessions are memory-only, auto-expire, and origin-locked. Supports bearer, cookie, basic, and form-based login via Playwright. **No API key required** (requires Playwright for form-based login).

---

#### `ghost_report` — Composite Background Report

Orchestrates multiple ghost tools (phone, email, username, breach, court, IP) into a unified background report for a subject. Generates a structured summary with cross-referenced findings. **No additional API key** (uses keys configured for individual tools).

---

## Paranoia Levels

GhostMCP has 4 operational security levels that control how requests are made:

| Level | Proxy | User-Agent | Headers | Timing | Use Case |
|-------|-------|------------|---------|--------|----------|
| `casual` | Direct | Random browser UA | Standard browser headers, DNT:1 | `min_delay` only | Dev workflow, quick searches |
| `cautious` | Direct (rotating proxy future) | Random browser UA | Standard browser headers, DNT:1 | `min_delay` + jitter | Default, balanced |
| `ghost` | Tor SOCKS5 | Tor Browser UA (fixed) | Tor-standard headers, no DNT | Tor latency + delay | Anonymous research |
| `midnight` | Tor + circuit rotation | Tor Browser UA (fixed) | Tor-standard headers, no DNT | Max delays | Maximum anonymity |

**Why ghost/midnight use a fixed UA:** The Tor Browser deliberately uses a single, standardized User-Agent across all users. This makes every Tor user look identical — randomizing the UA would actually make you MORE fingerprintable, not less. GhostMCP follows this principle.

---

## Project Structure

```
GhostMCP/
├── README.md                    # This file
├── ghostmcp/
│   ├── __init__.py
│   ├── __main__.py              # Entry point: python3 -m ghostmcp
│   ├── mcp.py                   # MCP server (27 tools, JSON-RPC stdio)
│   ├── cli.py                   # CLI interface
│   ├── engines/                 # Search engine implementations
│   │   ├── base.py              # SearchResult dataclass, SearchEngine ABC, rate limiter
│   │   ├── duckduckgo.py        # DDG Lite scraper (POST, 202 retry)
│   │   ├── google.py            # Google HTML SERP scraper (CAPTCHA detection)
│   │   └── serper.py            # Serper.dev REST API (requires key)
│   ├── stealth/                 # Anti-detection and fingerprint evasion
│   ├── auth/                    # Authentication session management
│   ├── captcha/                 # CAPTCHA solving integrations
│   ├── dorking/                 # Google dork query builder
│   │   ├── builder.py           # build_dork() + from_template()
│   │   └── templates.py         # 12 predefined dork templates
│   ├── proxy/                   # Proxy and fingerprint management
│   │   ├── manager.py           # ProxyManager (paranoia → proxy selection)
│   │   └── fingerprint.py       # Browser header generation by paranoia level
│   ├── recon/                   # Reconnaissance modules
│   │   ├── hashes.py            # Hash intelligence (CIRCL, MalwareBazaar, ThreatFox, VT)
│   │   ├── subdomains.py        # Subdomain enumeration (crt.sh CT + DNS brute)
│   │   ├── cve.py               # CVE lookup (NVD, EPSS, CISA KEV)
│   │   ├── vuln.py              # Package vulnerability check (OSV.dev)
│   │   ├── threat.py            # Threat intel feeds (URLhaus, ThreatFox, Feodo)
│   │   ├── cert.py              # TLS certificate inspection
│   │   ├── render.py            # Headless Chromium rendering (Playwright)
│   │   ├── phone.py             # Phone validation, carrier, CNAM
│   │   ├── vehicles.py          # VIN decode, recalls, complaints (NHTSA)
│   │   ├── people.py            # IntelTechniques URL generator
│   │   ├── email_intel.py       # Email reputation, social, breach
│   │   ├── username.py          # Username enumeration (20+ sites)
│   │   ├── court.py             # Court record search (CourtListener)
│   │   ├── breach.py            # Breach database aggregator
│   │   ├── report.py            # Composite background report
│   │   └── ip_intel.py          # IP geolocation, ASN, proxy detection
│   │   ├── headers.py           # HTTP security header analysis
│   │   ├── dns_intel.py         # DNS reconnaissance (DoH, SPF/DMARC/DKIM)
│   │   ├── api_discovery.py     # Passive API surface discovery
│   │   └── asn.py               # BGP/ASN network reconnaissance
│   └── utils/
│       └── config.py            # ParanoiaLevel enum, Config dataclass
├── tests/                       # 1,453 unit tests + 35 integration tests
│   ├── conftest.py              # Shared fixtures, markers
│   ├── test_base.py             # SearchResult, exceptions, rate limiter
│   ├── test_dorking.py          # Dork builder + templates
│   ├── test_duckduckgo.py       # DDG Lite parser + search
│   ├── test_fingerprint.py      # Header generation, all paranoia levels
│   ├── test_google.py           # Google parser, CAPTCHA detection
│   ├── test_hashes.py           # Hash detection, verdicts, mocked lookups
│   ├── test_mcp.py              # MCP server registration + dispatch
│   ├── test_proxy.py            # Proxy selection, Tor health
│   ├── test_serper.py           # Serper API parsing, mocked HTTP
│   ├── test_subdomains.py       # CT log + DNS brute force
│   ├── test_cve.py              # CVE lookup, EPSS, KEV
│   ├── test_vuln.py             # OSV.dev package checks
│   ├── test_threat.py           # Threat feed lookups
│   ├── test_cert.py             # TLS inspection
│   ├── test_render.py           # Headless rendering
│   ├── test_phone.py            # Phone validation, carrier, CNAM
│   ├── test_vehicles.py         # VIN decode, NHTSA APIs
│   ├── test_people.py           # People search URL generation
│   ├── test_email_intel.py      # Email intelligence
│   ├── test_username.py         # Username enumeration
│   ├── test_court.py            # Court record search
│   ├── test_breach.py           # Breach database queries
│   ├── test_report.py           # Composite report generation
│   ├── test_ip_intel.py         # IP geolocation + ASN
│   ├── test_headers.py          # HTTP security header analysis
│   ├── test_dns_intel.py        # DNS reconnaissance
│   ├── test_api_discovery.py    # API surface discovery
│   ├── test_asn.py              # BGP/ASN reconnaissance
│   └── test_integration.py      # 35 integration tests (live free APIs)
├── docs/
│   ├── design/                  # Architecture and capability docs
│   ├── research/                # OSINT API research
│   └── status/                  # Project status tracking
├── config/                      # Configuration templates
├── scripts/                     # Utility scripts
└── docker/                      # Container build files (future)
```

---

## Environment Variables

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `GHOST_PARANOIA` | `casual` | Default paranoia level |
| `GHOST_MIN_DELAY` | `2.0` | Minimum seconds between requests (per engine) |
| `GHOST_TIMEOUT` | `30.0` | HTTP request timeout in seconds |
| `GHOST_MAX_RESULTS` | `10` | Default max results |
| `GHOST_ENGINES` | `duckduckgo` | Comma-separated engine preference |
| `GHOST_TOR_PROXY` | `socks5://127.0.0.1:9050` | Tor SOCKS5 address |
| `GHOST_OUTPUT` | `text` | Output format (`text`, `json`) |

### API Keys — Search & Security

| Variable | Default | Description |
|----------|---------|-------------|
| `GHOST_BRAVE_KEY` | (none) | Brave Search API key (2,000 free queries/month) |
| `GHOST_PERPLEXITY_KEY` | (none) | Perplexity AI API key (search-augmented research) |
| `SERPER_API_KEY` | (none) | Serper.dev API key (enables Google-quality results) |
| `GHOST_BING_KEY` | (none) | Bing Search API key (enables Bing engine) |
| `GHOST_CAPTCHA_KEY` | (none) | CAPTCHA solving service API key |
| `GHOST_CAPTCHA_SERVICE` | (none) | CAPTCHA service provider (e.g., 2captcha, anticaptcha) |
| `VT_API_KEY` | (none) | VirusTotal API key (enables AV detection lookups) |

### API Keys — People Search

| Variable | Default | Description |
|----------|---------|-------------|
| `GHOST_VERIPHONE_KEY` | (none) | Veriphone API key (1000 free lookups/mo) |
| `GHOST_TWILIO_SID` | (none) | Twilio Account SID (CNAM caller name lookup) |
| `GHOST_TWILIO_TOKEN` | (none) | Twilio Auth Token |
| `GHOST_OPENCNAM_SID` | (none) | OpenCNAM Account SID |
| `GHOST_OPENCNAM_TOKEN` | (none) | OpenCNAM Auth Token |
| `GHOST_EMAILREP_KEY` | (none) | EmailRep.io API key (free registration) |
| `GHOST_HUNTER_KEY` | (none) | Hunter.io API key ($49/mo) |
| `GHOST_HIBP_KEY` | (none) | Have I Been Pwned API key ($3.50/mo) |
| `GHOST_COURTLISTENER_TOKEN` | (none) | CourtListener API token (free registration) |
| `GHOST_SNUSBASE_KEY` | (none) | Snusbase API key ($27/mo) |
| `GHOST_DEHASHED_EMAIL` | (none) | DeHashed account email |
| `GHOST_DEHASHED_KEY` | (none) | DeHashed API key ($15-30/mo) |
| `GHOST_LEAKCHECK_KEY` | (none) | LeakCheck API key ($10/mo) |

---

## API Key Configuration

All API keys are **optional**. Core functionality (search, dorking, fetch, recon, CVE, vuln, threat, cert, render, IP, VIN, username, people) works without any keys.

| Key | Service | Free Tier | What It Enables |
|-----|---------|-----------|-----------------|
| `SERPER_API_KEY` | [Serper.dev](https://serper.dev) | 2,500 queries free | Google-quality structured search results |
| `VT_API_KEY` | [VirusTotal](https://virustotal.com) | 4 req/min free | AV detection scores for hash lookups |
| `GHOST_VERIPHONE_KEY` | [Veriphone](https://veriphone.io) | 1,000/mo free | Phone number validation + carrier |
| `GHOST_EMAILREP_KEY` | [EmailRep.io](https://emailrep.io) | Free registration | Email reputation scoring |
| `GHOST_COURTLISTENER_TOKEN` | [CourtListener](https://www.courtlistener.com) | Free registration | US court record search |
| `GHOST_HIBP_KEY` | [Have I Been Pwned](https://haveibeenpwned.com/API/Key) | $3.50/mo | Breach history lookups |
| `GHOST_HUNTER_KEY` | [Hunter.io](https://hunter.io) | $49/mo | Professional email verification |
| `GHOST_SNUSBASE_KEY` | [Snusbase](https://snusbase.com) | $27/mo | Breach credential search |
| `GHOST_DEHASHED_KEY` | [DeHashed](https://dehashed.com) | $15-30/mo | Breach database queries |
| `GHOST_LEAKCHECK_KEY` | [LeakCheck](https://leakcheck.io) | $10/mo | Leak database lookups |
| `GHOST_TWILIO_SID` | [Twilio](https://twilio.com) | Pay-per-use | CNAM caller name resolution |
| `GHOST_OPENCNAM_SID` | [OpenCNAM](https://opencnam.com) | Pay-per-use | CNAM caller name (alternative) |

---

## Running Tests

```bash
cd GhostMCP

# Unit tests (1,409 tests, all mocked, no network)
python3 -m pytest tests/ -v

# Integration tests (35 tests, hits live free APIs)
python3 -m pytest tests/ -v -m integration

# Paid API tests (13 tests, requires keys to be set)
python3 -m pytest tests/ -v -m paid

# All tests together
python3 -m pytest tests/ -v --run-all

# Stop on first failure
python3 -m pytest tests/ -v -x

# Single module
python3 -m pytest tests/test_phone.py -v
```

### Test Markers

| Marker | Count | Description |
|--------|-------|-------------|
| (default) | 1,409 | Unit tests — fully mocked, no network, run everywhere |
| `integration` | 35 | Integration tests — hit live free APIs (crt.sh, NVD, ip-api, NHTSA) |
| `paid` | 13 | Paid API tests — require keys, skipped if env vars not set |

Tests are configured in `conftest.py` to skip `integration` and `paid` markers by default. Use `-m integration` or `-m paid` to opt in.

---

## Design Principles

- **Free by default** — All core functionality works without API keys (19 of 27 tools need no keys)
- **No footprint** — Stealth headers, proxy support, Tor integration
- **Standalone** — Runs independently, but callable from any MCP client
- **Modular engines** — Add new search engines without touching core
- **Configurable paranoia** — From "just search" to "full ghost mode"
- **Structured output** — Title, URL, snippet, metadata — ready for AI consumption
- **Mandatory provenance** — Every result includes source engine and timestamp
- **Dorking is first-class** — Not an afterthought, a core capability
- **Graceful degradation** — Tools work with whatever keys are available, report what's missing

---

## Future Integration

### Unimind Integration

GhostMCP can be bundled into the Unimind MCP container or run as a sidecar, enabling council agents and the DMN to search the web independently without going through external AI APIs (Perplexity/Grok).

### ForensicsMCP (Future Project)

GhostMCP finds threats. ForensicsMCP (planned) analyzes them in sandboxes.

```
Discovery → Analysis → Intelligence
GhostMCP    ForensicsMCP    Unimind
(find it)   (understand it) (remember it)
```

**Key principle:** GhostMCP NEVER executes samples. It finds and lists them. ForensicsMCP will handle detonation in isolated, disposable environments.

---

## Roadmap

See [`docs/design/CAPABILITIES.md`](docs/design/CAPABILITIES.md) for the full 17-phase roadmap and [`docs/design/PHASE_ESTIMATES.md`](docs/design/PHASE_ESTIMATES.md) for effort estimates.

### What's Built

| Sprint | Capability | Status |
|--------|-----------|--------|
| 0 | DuckDuckGo Lite engine, proxy manager, fingerprint rotation, CLI | Done |
| 1 | Google scraper, Serper API, dorking builder + 12 templates, MCP interface | Done |
| 2 | Subdomain enumeration (crt.sh CT + DNS brute force) | Done |
| 2.5 | Vulnerability intelligence (NVD, OSV, CISA KEV, EPSS) | Done |
| 2.5b | Hash intelligence (CIRCL, MalwareBazaar, ThreatFox, VirusTotal) | Done |
| 2c | TLS certificate inspection (cert chain, expiry, SANs, ciphers) | Done |
| 3 | Headless Chromium rendering (Playwright, JS execution, console capture) | Done |
| 3.5 | Threat intelligence feeds (URLhaus, ThreatFox, RansomWatch, Feodo) | Done |
| 4 | Phone intelligence (validation, carrier, CNAM, reverse lookup) | Done |
| 5 | People search (IntelTechniques URL gen, VIN/NHTSA, IP geolocation) | Done |
| 6 | Email + username intelligence (EmailRep, Holehe, Hunter, enumeration) | Done |
| 7 | Breach + court records (HIBP, Snusbase, DeHashed, CourtListener) | Done |

### What's Next

| Sprint | Capability | Description |
|--------|-----------|-------------|
| 8 | Domain reputation | URLhaus, PhishTank, AbuseIPDB, WHOIS age |
| 9 | Social media OSINT | Profile scraping, activity timelines |
| 10 | Report export | PDF/HTML report generation with evidence chains |

---

## Known Issues

- **DDG rate limiting:** DuckDuckGo throttles aggressively (~10s cooldown after burst requests). The engine handles this with 202 retry + exponential backoff (5s/10s/15s), but rapid successive searches may return empty results. The `min_delay=2.0` setting prevents this in normal use.
- **Google CAPTCHA:** Google HTML scraping triggers CAPTCHAs under heavy use. Install `curl_cffi` for better stealth, or use Serper API for reliable Google results.
- **Python 3.9:** Tested on Python 3.9+. Some type hints use `X | Y` syntax that requires `from __future__ import annotations` (already included).
- **Playwright install:** `ghost_render` requires `playwright install chromium` — this downloads ~150MB on first run. Tool returns a clear error if Chromium is not installed.
- **Breach tools:** `ghost_breach` gracefully degrades — it queries whichever services have keys configured and reports which sources were skipped.

---

## License

Personal project. Not yet licensed for distribution.
