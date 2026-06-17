# Project Status

## Sprint 0: Foundation (Current)
**Goal:** Architecture, project structure, core engine

| Task | Status | Notes |
|------|--------|-------|
| Project structure | Done | Created 2026-06-16 |
| Architecture design | Done | README.md + design docs |
| Core search engine (base class) | Pending | |
| DuckDuckGo engine | Pending | No API key, first engine |
| Proxy manager (direct + Tor) | Pending | |
| User-Agent rotation | Pending | |
| Result parser (HTML) | Pending | |
| CLI interface | Pending | |
| Basic tests | Pending | |

## Backlog

- Google scraper engine
- Bing scraper engine
- Serper.dev API engine
- Dorking query builder + templates
- MCP tool interface
- Tor circuit rotation
- SOCKS5 proxy pool
- Residential proxy support
- Fingerprint manager (JA3, headers)
- Request jitter + timing
- Content extraction (fetch + parse pages)
- Subdomain enumeration
- Certificate transparency search
- Shodan integration
- Censys integration
- Technology fingerprinting
- Docker containerization
- Paranoia level presets
- Rate limit detection + backoff
- CAPTCHA detection + handling

## Decisions Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-06-16 | Python standalone | Same stack as Unimind/NewHotness, asyncio for concurrent searches |
| 2026-06-16 | Modular engine design | Swap/add engines without touching core |
| 2026-06-16 | Paranoia levels | Configurable from casual to midnight — user chooses their risk profile |
| 2026-06-16 | MCP + CLI dual interface | Callable from AI workflows AND standalone terminal use |
| 2026-06-16 | DuckDuckGo first engine | No API key needed, good dorking support, privacy-friendly |
| 2026-06-16 | Tor for ghost mode | Free, proven, circuit rotation for per-request IP changes |
| 2026-06-16 | No external AI dependency | Pure search tool — doesn't need LLM to function |
| 2026-06-16 | Classification: personal | Security research tool, personal use |

## Sprint 2.5: Vulnerability Intelligence (Free APIs)

| Task | Status | Notes |
|------|--------|-------|
| NVD CVE lookup (NIST API) | Pending | Full CVE details + severity + CPE |
| OSV.dev integration | Pending | Package vulns by ecosystem (Python/JS/Go/Rust) |
| GitHub Advisories (GHSA) | Pending | Security advisories via GraphQL |
| CISA KEV feed | Pending | Known actively exploited vulns (JSON) |
| EPSS scoring | Pending | Exploit likelihood probability |
| ExploitDB search | Pending | Public exploits + PoC lookup |
| pip-audit integration | Pending | Scan requirements.txt / pyproject.toml |
| Tech stack → CVE mapping | Pending | Fingerprint domain → find vulns for detected stack |

### CLI Interface
```
ghost vuln python flask              # Package CVEs from OSV + GHSA
ghost vuln cve CVE-2024-1234         # Full CVE details + EPSS + KEV status
ghost vuln scan requirements.txt     # Audit Python dependencies
ghost vuln domain example.com        # Tech fingerprint → known CVEs
ghost vuln exploit CVE-2024-1234     # Check ExploitDB for public PoCs
ghost vuln kev                       # List currently exploited vulns (CISA)
```

### Free API Endpoints
- NVD: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={id}`
- OSV: `https://api.osv.dev/v1/query` (POST)
- GHSA: GitHub GraphQL API (free token)
- CISA KEV: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- EPSS: `https://api.first.org/data/v1/epss?cve={id}`
- ExploitDB: searchsploit CLI or `https://www.exploit-db.com/search?cve={id}`
