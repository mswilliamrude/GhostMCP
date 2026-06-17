# GhostMCP

**Doesn't exist until it finds what it's looking for.**

---

## What Is This

A standalone Python search and reconnaissance tool that operates through rotating proxies, supports Google dorking, and presents results via MCP or CLI. Designed as both a development workflow accelerator (find answers faster) and an OSINT/recon capability.

Can be called by Unimind MCP or any other MCP client, but runs independently.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    GhostMCP                          │
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │              Search Interface                  │  │
│  │         MCP Tools / CLI / Python API           │  │
│  └──────────────────────┬────────────────────────┘  │
│                         │                           │
│  ┌──────────────────────▼────────────────────────┐  │
│  │            Query Builder                       │  │
│  │   Natural language → dorking syntax            │  │
│  │   Template library (recon, vuln, config, etc.) │  │
│  └──────────────────────┬────────────────────────┘  │
│                         │                           │
│  ┌──────────────────────▼────────────────────────┐  │
│  │           Engine Router                        │  │
│  │   Google │ DuckDuckGo │ Bing │ Serper API      │  │
│  │   Shodan │ Censys │ Custom                     │  │
│  └──────────────────────┬────────────────────────┘  │
│                         │                           │
│  ┌──────────────────────▼────────────────────────┐  │
│  │           Proxy Layer                          │  │
│  │   Tor │ SOCKS5 │ Residential │ Direct          │  │
│  │   Circuit rotation │ Jitter │ Fingerprinting   │  │
│  └──────────────────────┬────────────────────────┘  │
│                         │                           │
│  ┌──────────────────────▼────────────────────────┐  │
│  │           Result Parser                        │  │
│  │   HTML scraping │ JSON API │ Structured output  │  │
│  │   Dedup │ Ranking │ Content extraction          │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

---

## Capabilities

### A. Dev Workflow (find answers faster)
- Web search from inside the AI coding workflow
- No classification broker — searches don't go through Unimind's outbound sanitizer
- Results fed directly into context
- "stalwart v0.16 create user credentials CLI" → answer in 10 seconds

### B. OSINT / Recon
- Google dorking (site:, filetype:, inurl:, intitle:, intext:, ext:, etc.)
- Dork template library (exposed configs, login pages, file listings, etc.)
- Passive DNS / subdomain enumeration
- Certificate transparency log search
- Shodan / Censys integration (API keys optional)
- Technology fingerprinting from HTTP headers

### C. The Unknown Unknowns
- Whatever emerges when A and B start talking to each other

---

## Proxy Architecture

```
Request
    │
    ├─→ Proxy Selector (round-robin, random, least-used)
    │     ├── Tor SOCKS5 (tor:9050, circuit rotation via NEWNYM)
    │     ├── SOCKS5 pool (configurable list)
    │     ├── HTTP/HTTPS proxies
    │     ├── Residential proxies (API-based)
    │     └── Direct (no proxy, fallback)
    │
    ├─→ Fingerprint Manager
    │     ├── User-Agent rotation (realistic browser strings)
    │     ├── Accept-Language rotation
    │     ├── TLS fingerprint (JA3 variation)
    │     └── Header ordering randomization
    │
    └─→ Timing Controller
          ├── Request jitter (random delay between requests)
          ├── Rate limiting (per-engine, per-proxy)
          ├── Backoff on CAPTCHA / rate limit detection
          └── Human-like browsing patterns
```

---

## Dorking Module

### Built-in Operators

| Operator | Description | Example |
|----------|------------|---------|
| `site:` | Restrict to domain | `site:github.com stalwart credentials` |
| `filetype:` | File type | `filetype:toml stalwart config` |
| `inurl:` | URL contains | `inurl:admin login` |
| `intitle:` | Page title contains | `intitle:"index of" config` |
| `intext:` | Body contains | `intext:"DB_PASSWORD" filetype:env` |
| `ext:` | File extension | `ext:sql "INSERT INTO users"` |
| `cache:` | Cached version | `cache:example.com` |
| `-` | Exclude | `stalwart config -documentation` |
| `""` | Exact match | `"AccountPassword/set" stalwart` |
| `OR` | Boolean OR | `stalwart OR dovecot credentials CLI` |
| `*` | Wildcard | `"stalwart * credentials * CLI"` |

### Dork Templates

```python
DORK_TEMPLATES = {
    "exposed_configs": 'filetype:{ext} "{keyword}" site:{domain}',
    "login_pages": 'inurl:login OR inurl:signin site:{domain}',
    "directory_listing": 'intitle:"index of" site:{domain}',
    "error_messages": 'intext:"error" OR intext:"exception" site:{domain}',
    "api_docs": 'inurl:api OR inurl:swagger site:{domain}',
    "git_exposed": 'inurl:.git site:{domain}',
    "env_files": 'filetype:env "DB_" OR "API_" OR "SECRET_"',
    "config_files": 'filetype:yml OR filetype:yaml OR filetype:toml "password" OR "secret"',
    "tech_stack": 'site:{domain} "powered by" OR "server:" OR "x-powered-by:"',
}
```

---

## Search Engines

| Engine | Method | API Key | Dorking | Quality |
|--------|--------|---------|---------|---------|
| Google (scrape) | HTML parsing | No | Full | Best |
| DuckDuckGo | HTML/API | No | Partial | Good |
| Bing | HTML parsing | No | Partial | Good |
| Serper.dev | REST API | Yes (free tier) | Full Google | Best (structured) |
| Brave Search | REST API | Yes (free tier) | Partial | Good |
| Shodan | REST API | Yes | N/A (IoT/infra) | Unique |
| Censys | REST API | Yes | N/A (cert/host) | Unique |

---

## Project Structure

```
~/git/GhostMCP/
├── README.md
├── src/
│   ├── engines/          # Search engine implementations
│   │   ├── base.py       # Abstract engine interface
│   │   ├── google.py     # Google scraper
│   │   ├── duckduckgo.py # DDG scraper/API
│   │   ├── bing.py       # Bing scraper
│   │   ├── serper.py     # Serper.dev API
│   │   └── shodan.py     # Shodan API
│   ├── proxy/            # Proxy management
│   │   ├── manager.py    # Proxy selection and rotation
│   │   ├── tor.py        # Tor SOCKS5 + circuit rotation
│   │   ├── pool.py       # Generic proxy pool
│   │   └── fingerprint.py # Browser fingerprint rotation
│   ├── parsers/          # Result parsing
│   │   ├── html.py       # HTML SERP parsing
│   │   ├── json_api.py   # API response parsing
│   │   └── content.py    # Page content extraction
│   ├── dorking/          # Dorking query builder
│   │   ├── builder.py    # Query construction
│   │   ├── templates.py  # Dork template library
│   │   └── operators.py  # Operator definitions
│   ├── recon/            # OSINT modules
│   │   ├── subdomain.py  # Subdomain enumeration
│   │   ├── certs.py      # Certificate transparency
│   │   └── techstack.py  # Technology fingerprinting
│   ├── utils/            # Shared utilities
│   │   ├── config.py     # Configuration
│   │   ├── rate_limit.py # Rate limiting
│   │   └── ua.py         # User-Agent strings
│   ├── mcp.py            # MCP tool interface
│   └── cli.py            # CLI interface
├── tests/
├── docs/
│   ├── research/
│   ├── design/
│   ├── diagrams/
│   ├── status/
│   └── sprints/
├── scripts/
├── config/
│   ├── proxies.yml       # Proxy configuration
│   ├── engines.yml       # Engine configuration
│   └── dorks.yml         # Custom dork templates
└── docker/
```

---

## Design Principles

- **No footprint** — searches don't trace back to origin
- **No dependency on external AI APIs** — pure web scraping + optional API keys
- **Standalone** — runs without Unimind, but callable from Unimind
- **Modular engines** — add new search engines without touching core
- **Configurable paranoia** — from "just search" (direct, no proxy) to "full ghost" (Tor, rotation, jitter)
- **Results are structured** — title, URL, snippet, metadata — ready for AI consumption
- **Dorking is first-class** — not an afterthought, a core capability

---

## Paranoia Levels

```python
PARANOIA = {
    "casual": {
        # Direct connection, real UA, normal timing
        "proxy": "direct",
        "fingerprint": "static",
        "jitter": "none",
    },
    "cautious": {
        # Rotating proxies, rotating UA, mild jitter
        "proxy": "rotating",
        "fingerprint": "rotating",
        "jitter": "1-3s",
    },
    "ghost": {
        # Tor, full fingerprint rotation, human-like timing
        "proxy": "tor",
        "fingerprint": "full_rotation",
        "jitter": "3-8s",
    },
    "midnight": {
        # Tor with circuit rotation, randomized everything,
        # request splitting across multiple circuits
        "proxy": "tor_rotating",
        "fingerprint": "full_rotation",
        "jitter": "5-15s",
        "circuit_rotation": "per_request",
    },
}
```

---

## MCP Interface

```python
# Tools exposed via MCP
@tool
async def ghost_search(query: str, engine: str = "auto", paranoia: str = "cautious"):
    """Search the web. Returns structured results."""

@tool
async def ghost_dork(query: str, template: str = None, domain: str = None):
    """Google dorking search. Supports templates and operators."""

@tool
async def ghost_fetch(url: str, extract: str = "text"):
    """Fetch and extract content from a URL."""

@tool  
async def ghost_recon(domain: str, modules: list = ["subdomains", "techstack"]):
    """Passive reconnaissance on a domain."""
```
