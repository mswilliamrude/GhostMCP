# GhostMCP

**Doesn't exist until it finds what it's looking for.**

---

## What Is This

GhostMCP is a standalone OSINT search and reconnaissance toolkit that exposes its capabilities via the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/). It enables AI coding agents (Claude, GPT, etc.) to search the web, build Google dork queries, fetch URL content, and perform passive domain reconnaissance — all without leaving the IDE.

Designed as both a **development workflow accelerator** (find answers faster) and an **OSINT/recon capability** (discover exposed infrastructure, sensitive files, and threat intelligence).

Can be called by any MCP client (opencode, Claude Desktop, VS Code Copilot, Cursor) or used standalone via CLI.

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

# Verify it works
python3 -m pytest tests/ -v    # 243 tests, all passing
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | python3 -m src
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
        "VT_API_KEY": "optional-for-virustotal"
      }
    }
  }
}
```

Restart your MCP client after adding the configuration.

---

## MCP Tools

GhostMCP exposes 4 tools via the Model Context Protocol:

### `ghost_search` — Anonymous Web Search

Search the web using multiple engines with automatic fallback. Engines are tried in order: Serper (if API key set) → Google (HTML scrape) → DuckDuckGo Lite.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `query` | string | (required) | Search query |
| `engine` | string | `"auto"` | Engine: `auto`, `serper`, `google`, `duckduckgo` |
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

### `ghost_dork` — Google Dorking

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

| Template | What It Finds | Example Query |
|----------|---------------|---------------|
| `exposed_configs` | Config files (.env, .yml, .ini, .conf) exposed on a domain | `site:example.com (filetype:env OR filetype:yml ...) -github.com` |
| `login_pages` | Admin panels, login pages, auth endpoints | `site:example.com (inurl:login OR inurl:admin ...)` |
| `directory_listing` | Open directory indexes (file listings) | `site:example.com intitle:"index of" (inurl:admin ...)` |
| `git_exposed` | Exposed .git directories and config | `site:example.com (inurl:".git" OR intitle:"index of /.git" ...)` |
| `env_files` | Environment files with credentials | `site:example.com (filetype:env ...) ("DB_PASSWORD" OR "API_KEY" ...)` |
| `api_docs` | API documentation pages (Swagger, GraphQL) | `site:example.com (inurl:api OR inurl:swagger ...)` |
| `error_messages` | Stack traces, SQL errors, debug output | `site:example.com ("fatal error" OR "stack trace" ...)` |
| `tech_stack` | Technology identification (WordPress, Node, etc.) | `site:example.com (inurl:wp-content OR "powered by" ...)` |
| `database_dumps` | Database exports (.sql, .db, .sqlite, .bak) | `site:example.com (filetype:sql OR filetype:db ...) -github.com` |
| `sensitive_docs` | Confidential documents (PDF, XLSX, DOCX) | `site:example.com (filetype:pdf ...) ("confidential" ...)` |
| `subdomains` | Subdomain discovery via search | `site:*.example.com -www.example.com` |
| `backup_files` | Backup files (.bak, .old, .zip, .tar.gz) | `site:example.com (filetype:bak ...) (inurl:backup ...)` |

**Background:** Google dorking (also called Google hacking) uses advanced search operators to find content that site owners didn't intend to be publicly accessible. The technique was pioneered by Johnny Long in the early 2000s and formalized in the Google Hacking Database (GHDB). GhostMCP's dorking module lets you build queries programmatically using operators (`site:`, `filetype:`, `inurl:`, `intitle:`, `intext:`, exclude with `-`) or use predefined templates for common OSINT scenarios.

**Example:**
```
"Find exposed config files on example.com"
→ ghost_dork(template="exposed_configs", domain="example.com")
→ Builds: site:example.com (filetype:env OR filetype:yml ...) -github.com
→ Executes search and returns results
```

---

### `ghost_fetch` — URL Content Extraction

Fetch a URL and extract its content in various formats. Uses stealth headers and supports proxy routing through the paranoia system.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `url` | string | (required) | URL to fetch |
| `extract` | string | `"text"` | Mode: `text` (readable), `html` (raw), `headers`, `links` |
| `paranoia` | string | `"cautious"` | OpSec level |

**Extraction modes:**
- `text` — Strips scripts, styles, and HTML tags. Returns readable text content (truncated at 20KB).
- `html` — Returns raw HTML (truncated at 50KB).
- `headers` — Returns HTTP response headers (server version, content type, security headers).
- `links` — Extracts and deduplicates all `href` URLs from the page.

**Background:** Unlike a simple `curl`, ghost_fetch applies browser fingerprinting (realistic User-Agent, Accept headers, language preferences) based on the paranoia level. In ghost/midnight modes, requests route through Tor with the Tor Browser's standard User-Agent for consistency with other Tor users. Content extraction strips JavaScript and CSS before returning text, making it suitable for feeding into AI context windows.

---

### `ghost_recon` — Domain Reconnaissance

Passive reconnaissance on a target domain. Runs dorking-based modules to discover subdomains, exposed configurations, and technology stack.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `domain` | string | (required) | Target domain |
| `modules` | array | `["subdomains"]` | Modules: `subdomains`, `configs`, `tech` |

**Modules:**
- `subdomains` — Finds subdomains via `site:*.domain.com` dorking (up to 20 results)
- `configs` — Searches for exposed configuration files (env, yml, ini, conf) on the domain
- `tech` — Identifies technology stack (WordPress, Node.js, vendor directories, "powered by" strings)

**Background:** Passive recon collects information about a target without directly interacting with it (no port scans, no vulnerability probes). All discovery is done through search engine queries — the target's web server never sees a request from GhostMCP. This makes it safe, legal, and undetectable. The modules are composable — run all three for a comprehensive overview, or just one for targeted intelligence.

---

## Additional Capabilities

### Hash Intelligence (`src/recon/hashes.py`)

Look up file hashes against multiple threat intelligence databases to determine if a file is known-good, malicious, or unknown.

**Services queried (all free, no API key required):**
- **CIRCL NSRL** — National Software Reference Library (known legitimate files)
- **MalwareBazaar** (abuse.ch) — Malware sample database (family, tags, first seen)
- **ThreatFox** (abuse.ch) — IOC database (C2 servers, campaigns)
- **VirusTotal** — AV detection aggregator (requires free API key, optional)

**Supported hash types:** MD5, SHA1, SHA256, SHA512 (auto-detected from length)

**Verdict logic:**
- MalwareBazaar or ThreatFox hit → `malicious`
- VirusTotal 11+ detections → `malicious`
- VirusTotal 1-10 detections → `suspicious`
- CIRCL NSRL known → `clean`
- Nothing found → `unknown`

This capability is currently available as a Python API (`HashLookup.lookup(hash)`) and will be exposed as an MCP tool in a future sprint.

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
├── src/
│   ├── __init__.py
│   ├── __main__.py              # Entry point: python3 -m src
│   ├── mcp.py                   # MCP server (4 tools, JSON-RPC stdio)
│   ├── cli.py                   # CLI interface
│   ├── engines/                 # Search engine implementations
│   │   ├── base.py              # SearchResult dataclass, SearchEngine ABC, rate limiter
│   │   ├── duckduckgo.py        # DDG Lite scraper (POST, 202 retry)
│   │   ├── google.py            # Google HTML SERP scraper (CAPTCHA detection)
│   │   └── serper.py            # Serper.dev REST API (requires key)
│   ├── dorking/                 # Google dork query builder
│   │   ├── builder.py           # build_dork() + from_template()
│   │   └── templates.py         # 12 predefined dork templates
│   ├── proxy/                   # Proxy and fingerprint management
│   │   ├── manager.py           # ProxyManager (paranoia → proxy selection)
│   │   └── fingerprint.py       # Browser header generation by paranoia level
│   ├── recon/                   # Reconnaissance modules
│   │   └── hashes.py            # Hash intelligence (CIRCL, MalwareBazaar, ThreatFox, VT)
│   └── utils/
│       └── config.py            # ParanoiaLevel enum, Config dataclass
├── tests/                       # 243 tests, 100% pass rate
│   ├── conftest.py              # Shared fixtures
│   ├── test_base.py             # SearchResult, exceptions, rate limiter (16 tests)
│   ├── test_dorking.py          # Dork builder + templates (33 tests)
│   ├── test_duckduckgo.py       # DDG Lite parser + search (21 tests)
│   ├── test_fingerprint.py      # Header generation, all paranoia levels (22 tests)
│   ├── test_google.py           # Google parser, CAPTCHA detection (21 tests)
│   ├── test_hashes.py           # Hash detection, verdicts, mocked lookups (29 tests)
│   ├── test_mcp.py              # MCP server registration + dispatch (12 tests)
│   ├── test_proxy.py            # Proxy selection, Tor health (19 tests)
│   └── test_serper.py           # Serper API parsing, mocked HTTP (22 tests)
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

| Variable | Default | Description |
|----------|---------|-------------|
| `GHOST_PARANOIA` | `casual` | Default paranoia level |
| `GHOST_MIN_DELAY` | `2.0` | Minimum seconds between requests (per engine) |
| `GHOST_TIMEOUT` | `30.0` | HTTP request timeout in seconds |
| `GHOST_MAX_RESULTS` | `10` | Default max results |
| `GHOST_ENGINES` | `duckduckgo` | Comma-separated engine preference |
| `GHOST_TOR_PROXY` | `socks5://127.0.0.1:9050` | Tor SOCKS5 address |
| `GHOST_OUTPUT` | `text` | Output format (`text`, `json`) |
| `SERPER_API_KEY` | (none) | Serper.dev API key (enables Google-quality results) |
| `VT_API_KEY` | (none) | VirusTotal API key (enables AV detection lookups) |

---

## API Key Configuration

All API keys are **optional**. Core functionality works without any keys.

| Key | Service | Free Tier | What It Enables |
|-----|---------|-----------|-----------------|
| `SERPER_API_KEY` | [Serper.dev](https://serper.dev) | 2,500 queries free | Google-quality structured search results |
| `VT_API_KEY` | [VirusTotal](https://virustotal.com) | 4 req/min free | AV detection scores for hash lookups |

**Future keys (planned phases):**

| Key | Service | What It Will Enable |
|-----|---------|---------------------|
| `OTX_API_KEY` | AlienVault OTX | Community threat intelligence feeds |
| `HIBP_API_KEY` | Have I Been Pwned | Breach monitoring |
| `SHODAN_API_KEY` | Shodan | Internet-wide device/service search |
| `LEAKIX_API_KEY` | LeakIX | Exposed service discovery |

---

## Running Tests

```bash
cd GhostMCP
python3 -m pytest tests/ -v          # Full suite (243 tests)
python3 -m pytest tests/ -v -x       # Stop on first failure
python3 -m pytest tests/test_dorking.py -v  # Single module
```

Test coverage by module:

| Module | Tests | What's Tested |
|--------|-------|---------------|
| `engines/base.py` | 16 | SearchResult creation, exceptions, async rate limiter timing |
| `engines/duckduckgo.py` | 21 | Lite HTML parser, DDG link filtering, mocked search |
| `engines/google.py` | 21 | SERP parsing, CAPTCHA/consent detection, mocked HTTP |
| `engines/serper.py` | 22 | API response parsing, key detection, error handling |
| `dorking/` | 33 | All operators, template rendering, edge cases |
| `recon/hashes.py` | 29 | Hash type detection, file hashing, verdict logic, mocked API lookups |
| `proxy/fingerprint.py` | 22 | Header generation for all paranoia levels |
| `proxy/manager.py` | 19 | Proxy selection, Tor health checks |
| `mcp.py` | 12 | Tool registration, JSON-RPC dispatch, error handling |

---

## Design Principles

- **Free by default** — All core functionality works without API keys
- **No footprint** — Stealth headers, proxy support, Tor integration
- **Standalone** — Runs independently, but callable from any MCP client
- **Modular engines** — Add new search engines without touching core
- **Configurable paranoia** — From "just search" to "full ghost mode"
- **Structured output** — Title, URL, snippet, metadata — ready for AI consumption
- **Mandatory provenance** — Every result includes source engine and timestamp
- **Dorking is first-class** — Not an afterthought, a core capability

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

### What's Built (Sprints 0, 1, 2.5b)

| Sprint | Capability | Status |
|--------|-----------|--------|
| 0 | DuckDuckGo Lite engine, proxy manager, fingerprint rotation, CLI | Done |
| 1 | Google scraper, Serper API, dorking builder + 12 templates, MCP interface | Done |
| 2.5b | Hash intelligence (CIRCL, MalwareBazaar, ThreatFox, VirusTotal) | Done |

### What's Next

| Sprint | Capability | Description |
|--------|-----------|-------------|
| 2 | Subdomain enumeration | crt.sh certificate transparency + DNS brute force |
| 2.5 | Vulnerability intelligence | NVD, OSV, CISA KEV, EPSS, ExploitDB |
| 2c | TLS certificate inspection | Connect, parse cert chain, expiry, SANs, ciphers |
| 3 | Browser automation (Playwright) | Tier 1 fallback for JS-heavy sites |
| 3.5 | Threat intelligence feeds | Abuse.ch, AlienVault OTX, RansomWatch |
| 4 | Domain reputation | URLhaus, PhishTank, AbuseIPDB, WHOIS age |

---

## Known Issues

- **DDG rate limiting:** DuckDuckGo throttles aggressively (~10s cooldown after burst requests). The engine handles this with 202 retry + exponential backoff (5s/10s/15s), but rapid successive searches may return empty results. The `min_delay=2.0` setting prevents this in normal use.
- **Google CAPTCHA:** Google HTML scraping triggers CAPTCHAs under heavy use. Install `curl_cffi` for better stealth, or use Serper API for reliable Google results.
- **Python 3.9:** Tested on Python 3.9+. Some type hints use `X | Y` syntax that requires `from __future__ import annotations` (already included).

---

## License

Personal project. Not yet licensed for distribution.
