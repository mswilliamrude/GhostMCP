# GhostMCP — System Architecture

**Version:** 0.1
**Date:** 2026-06-16

---

## 1. Overview

GhostMCP is a modular search and reconnaissance tool. Every component is independently replaceable. The core principle: the tool should be invisible to the target — searches leave no trace attributable to the operator.

```
┌─────────────────────────────────────────────────────────┐
│                    Interface Layer                        │
│              MCP Server │ CLI │ Python API                │
├─────────────────────────────────────────────────────────┤
│                    Query Layer                            │
│         Natural Language → Structured Query                │
│         Dorking Templates │ Operator Expansion             │
├─────────────────────────────────────────────────────────┤
│                    Engine Layer                            │
│    Google │ DDG │ Bing │ Serper │ Shodan │ Censys │ ...   │
├─────────────────────────────────────────────────────────┤
│                    Transport Layer                         │
│         Proxy Manager │ Fingerprint │ Timing │ Rotation   │
├─────────────────────────────────────────────────────────┤
│                    Parse Layer                             │
│         HTML Scraper │ JSON API │ Content Extractor        │
├─────────────────────────────────────────────────────────┤
│                    Output Layer                            │
│         Structured Results │ Dedup │ Ranking │ Export      │
└─────────────────────────────────────────────────────────┘
```

---

## 2. Engine Architecture

### 2.1 Base Interface

Every search engine implements a common interface:

```python
class SearchEngine(ABC):
    name: str               # "google", "duckduckgo", etc.
    supports_dorking: bool  # Can handle advanced operators
    requires_api_key: bool  # Needs configuration
    rate_limit: Rate        # Max requests per time window
    
    async def search(self, query: str, opts: SearchOptions) -> list[SearchResult]
    async def health_check(self) -> bool
```

### 2.2 Engine Router

The router selects which engine to use based on:

1. **Query type** — dorking queries go to Google/Serper; simple queries can use DDG
2. **Availability** — if an engine is rate-limited, fall to next
3. **Paranoia level** — at "midnight" level, avoid API-based engines (they log)
4. **User preference** — explicit engine selection overrides all

```python
class EngineRouter:
    async def route(self, query: str, paranoia: str) -> SearchEngine:
        if paranoia == "midnight":
            return self.scraper_only_engines()  # No APIs
        if has_dork_operators(query):
            return self.dorking_capable_engines()
        return self.least_loaded_engine()
```

### 2.3 Engine Implementations

| Engine | Implementation | Notes |
|--------|---------------|-------|
| DuckDuckGo | HTML scrape of `html.duckduckgo.com` | No JS needed, lite endpoint |
| Google | HTML scrape via `google.com/search` | Needs proxy rotation, CAPTCHA risk |
| Bing | HTML scrape via `bing.com/search` | Less aggressive anti-bot than Google |
| Serper | REST API to `google.serper.dev/search` | Structured JSON, 2500 free/month |
| Shodan | REST API to `api.shodan.io` | IoT/infrastructure search |
| Censys | REST API to `search.censys.io` | Certificate and host search |

---

## 3. Transport Layer (Proxy Architecture)

### 3.1 Proxy Manager

```
ProxyManager
├── ProxyPool
│   ├── TorProxy (SOCKS5 → localhost:9050)
│   ├── SOCKS5Proxy (configurable list)
│   ├── HTTPProxy (configurable list)
│   └── DirectConnection (no proxy)
│
├── ProxySelector
│   ├── RoundRobin
│   ├── Random
│   ├── LeastUsed
│   └── GeoTargeted (use proxy in specific country)
│
└── HealthChecker
    ├── Periodic connectivity test
    ├── Latency measurement
    └── Auto-remove dead proxies
```

### 3.2 Tor Integration

```
Tor Control Protocol (port 9051)
├── NEWNYM signal → new circuit (new exit IP)
├── Circuit rotation strategies:
│   ├── per_request — new circuit every request (slowest, most anonymous)
│   ├── per_engine — new circuit when switching engines
│   ├── timed — new circuit every N seconds
│   └── on_failure — new circuit on CAPTCHA/block detection
└── Exit node selection (by country code, if needed)
```

### 3.3 Fingerprint Manager

Every request looks like a different real browser:

```python
class FingerprintManager:
    def generate(self) -> Fingerprint:
        return Fingerprint(
            user_agent=random_ua(),        # Realistic browser UA
            accept_language=random_lang(),  # en-US, en-GB, etc.
            accept_encoding="gzip, deflate, br",
            sec_ch_ua=matching_ch_ua(),    # Must match UA
            sec_ch_ua_platform=matching_platform(),
            dnt=random.choice(["0", "1", None]),
            upgrade_insecure_requests="1",
            # Header ORDER matters — browsers have consistent ordering
            header_order=browser_header_order(),
        )
```

### 3.4 Timing Controller

```python
class TimingController:
    PROFILES = {
        "none":     {"min": 0,   "max": 0},      # As fast as possible
        "light":    {"min": 0.5, "max": 1.5},     # Quick but not instant
        "moderate": {"min": 1,   "max": 3},       # Normal browsing pace
        "human":    {"min": 3,   "max": 8},       # Realistic human timing
        "paranoid": {"min": 5,   "max": 15},      # Very cautious
    }
    
    async def wait(self, profile: str):
        cfg = self.PROFILES[profile]
        delay = random.uniform(cfg["min"], cfg["max"])
        # Add micro-jitter to avoid exact patterns
        delay += random.gauss(0, delay * 0.1)
        await asyncio.sleep(max(0, delay))
```

---

## 4. Dorking Module

### 4.1 Query Builder

Translates intent into dorking syntax:

```python
class DorkBuilder:
    def build(self, intent: str, context: dict) -> str:
        """
        intent: "find exposed config files on example.com"
        context: {"domain": "example.com", "file_types": ["env", "yml", "toml"]}
        
        Returns: 'site:example.com (filetype:env OR filetype:yml OR filetype:toml) 
                  ("password" OR "secret" OR "api_key")'
        """
```

### 4.2 Template Library

Pre-built dork templates organized by category:

```yaml
# config/dorks.yml
reconnaissance:
  subdomains: 'site:*.{domain} -site:www.{domain}'
  technologies: 'site:{domain} ("powered by" OR "built with" OR "running")'
  email_harvest: 'site:{domain} "@{domain}" (email OR contact)'

exposure:
  config_files: 'site:{domain} (filetype:env OR filetype:yml OR filetype:ini) ("password" OR "secret")'
  git_exposed: 'site:{domain} inurl:.git ("HEAD" OR "config")'
  directory_listing: 'intitle:"index of" site:{domain}'
  backup_files: 'site:{domain} (filetype:bak OR filetype:old OR filetype:sql)'
  log_files: 'site:{domain} (filetype:log) ("error" OR "exception" OR "stack trace")'

authentication:
  login_pages: 'site:{domain} (inurl:login OR inurl:signin OR inurl:auth)'
  admin_panels: 'site:{domain} (inurl:admin OR inurl:dashboard OR inurl:panel)'
  api_endpoints: 'site:{domain} (inurl:api OR inurl:swagger OR inurl:graphql)'

development:
  documentation: '"{query}" (site:github.com OR site:stackoverflow.com OR site:docs.rs)'
  source_code: '"{query}" (site:github.com OR site:gitlab.com) (filetype:py OR filetype:rs OR filetype:ts)'
  issues: '"{query}" (site:github.com/*/issues OR site:discuss.* OR site:forum.*)'
  config_examples: '"{query}" (filetype:toml OR filetype:yml OR filetype:json) "example" OR "sample"'
```

### 4.3 Dork Operator Reference

```python
OPERATORS = {
    # Google operators (full support)
    "site": "Restrict to domain/subdomain",
    "filetype": "File extension",
    "ext": "Alias for filetype",
    "inurl": "URL path contains",
    "intitle": "Page title contains",
    "intext": "Body text contains",
    "allintitle": "All words in title",
    "allinurl": "All words in URL",
    "allintext": "All words in body",
    "cache": "Cached version of page",
    "related": "Related sites",
    "info": "Info about a URL",
    "define": "Definition",
    "link": "Pages linking to URL (deprecated but sometimes works)",
    "AROUND(N)": "Words within N words of each other",
    "before:": "Results before date (YYYY-MM-DD)",
    "after:": "Results after date (YYYY-MM-DD)",
    
    # DDG operators (partial support)
    # site:, filetype:, intitle: work
    # inurl:, intext: may not work
    
    # Boolean
    "OR": "Boolean OR",
    "-": "Exclude term",
    '""': "Exact match",
    "*": "Wildcard",
    "()": "Grouping",
}
```

---

## 5. Result Model

### 5.1 SearchResult

```python
@dataclass
class SearchResult:
    title: str
    url: str
    snippet: str
    engine: str              # Which engine found this
    position: int            # Rank in results
    timestamp: datetime      # When found
    cached_url: str = None   # Cache link if available
    metadata: dict = None    # Engine-specific extras
    
    # Content (if fetched)
    content: str = None      # Extracted page content
    content_type: str = None # MIME type
    
    # Recon metadata
    headers: dict = None     # HTTP response headers
    technologies: list = None # Detected tech stack
    ip_address: str = None   # Resolved IP
```

### 5.2 Deduplication

Results from multiple engines are merged and deduplicated:

```python
class ResultDeduplicator:
    def dedup(self, results: list[SearchResult]) -> list[SearchResult]:
        """Merge by URL, keep highest-ranked version, note which engines found it."""
        seen = {}
        for r in results:
            normalized = normalize_url(r.url)
            if normalized in seen:
                seen[normalized].engines.append(r.engine)
                seen[normalized].score += 1  # Found by multiple engines = higher confidence
            else:
                seen[normalized] = r
                r.engines = [r.engine]
                r.score = 1
        return sorted(seen.values(), key=lambda r: r.score, reverse=True)
```

---

## 6. Anti-Detection Measures

### 6.1 What Gets You Detected

| Signal | Detection Risk | Mitigation |
|--------|---------------|------------|
| Same IP, many requests | High | Proxy rotation |
| Bot-like User-Agent | High | UA rotation from real browser pool |
| No cookies | Medium | Cookie jar per session |
| Consistent request timing | Medium | Jitter + human-like delays |
| Missing browser headers | Medium | Full header suite per fingerprint |
| TLS fingerprint (JA3) | Low-Medium | Library-level TLS config |
| Header order | Low | Browser-specific ordering |
| Missing Referer | Low | Add realistic referrer chain |
| JavaScript challenge | High | Playwright fallback (if needed) |

### 6.2 CAPTCHA Handling

```python
class CaptchaDetector:
    SIGNALS = [
        "unusual traffic",
        "captcha",
        "recaptcha",
        "challenge",
        "verify you are human",
        "blocked",
        "rate limit",
    ]
    
    async def handle(self, response, proxy_manager):
        if self.is_captcha(response):
            # 1. Rotate proxy
            await proxy_manager.rotate()
            # 2. Increase delay
            await timing.escalate()
            # 3. Switch engine
            return Action.RETRY_DIFFERENT_ENGINE
```

---

## 7. Paranoia Levels (Detailed)

| Level | Proxy | Fingerprint | Timing | Circuit | Use Case |
|-------|-------|-------------|--------|---------|----------|
| `casual` | Direct | Static real UA | None | N/A | Dev search, quick answers |
| `cautious` | Rotating pool | Rotating UA | 1-3s jitter | N/A | Regular OSINT, moderate volume |
| `ghost` | Tor | Full rotation | 3-8s jitter | Per-engine | Sensitive research |
| `midnight` | Tor rotating | Full rotation | 5-15s jitter | Per-request | Maximum anonymity |

Each level inherits and extends the previous:
- `cautious` adds proxy rotation to `casual`
- `ghost` adds Tor and full fingerprinting to `cautious`
- `midnight` adds per-request circuit rotation and maximum jitter to `ghost`

---

## 8. Integration Points

### 8.1 Unimind MCP

GhostMCP can be registered as an MCP server in Unimind's config:

```json
{
  "mcpServers": {
    "ghost": {
      "command": "python3",
      "args": ["/path/to/ghostmcp/src/mcp.py"],
      "env": {
        "GHOST_PARANOIA": "cautious",
        "GHOST_TOR_ENABLED": "true"
      }
    }
  }
}
```

### 8.2 CLI

```bash
# Simple search
ghost search "stalwart v0.16 create user credentials"

# Dorking
ghost dork --domain example.com --template exposed_configs

# Recon
ghost recon --domain example.com --modules subdomains,techstack,certs

# Full ghost mode
ghost search "sensitive query" --paranoia midnight --engine google
```

### 8.3 Python API

```python
from ghostmcp import Ghost

g = Ghost(paranoia="cautious")
results = await g.search("stalwart JMAP credential format")
for r in results:
    print(f"{r.title}: {r.url}")

# Dorking
results = await g.dork(
    domain="stalw.art",
    template="source_code",
    query="AccountPassword secret"
)

# Fetch and extract
content = await g.fetch("https://github.com/stalwartlabs/stalwart/blob/main/crates/...")
```

---

## 9. Security Considerations

### 9.1 What GhostMCP Does NOT Do
- Does not attack targets
- Does not exploit vulnerabilities
- Does not bypass authentication
- Does not store credentials found in results
- Does not perform active scanning

### 9.2 What GhostMCP DOES Do
- Searches public information sources
- Uses the same search queries a human would type into a browser
- Automates what a security researcher does manually
- Structures results for analysis
- Protects the researcher's identity while doing legal research

### 9.3 Legal Notice
This tool searches publicly available information using the same mechanisms as a web browser. The proxy and anonymization features protect the researcher's privacy, which is a legitimate security practice. The dorking templates target publicly indexed content — if it's in a search engine's index, it's public.

---

## 10. Development Phases

### Phase 1: Core (MVP)
- Base engine interface
- DuckDuckGo engine (no API key)
- Direct + Tor proxy support
- UA rotation
- HTML result parser
- CLI interface
- Basic tests

### Phase 2: Engines + Dorking
- Google scraper engine
- Serper.dev API engine
- Dorking query builder
- Template library
- Result deduplication
- MCP tool interface

### Phase 3: Stealth
- Full fingerprint rotation
- Timing controller
- CAPTCHA detection
- SOCKS5 proxy pool
- Rate limit handling
- Cookie management

### Phase 4: Recon
- Subdomain enumeration
- Certificate transparency
- Technology fingerprinting
- Shodan/Censys integration
- Result correlation

### Phase 5: Integration
- Unimind MCP registration
- Result caching in Redis
- Knowledge graph integration (discovered facts → KG)
- Docker deployment
