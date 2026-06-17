# GhostMCP — Project Status

**Last updated:** 2026-06-17

## Current State

- **Lines of code:** ~2,650 (src/) + ~1,800 (tests/)
- **Test count:** 243 tests, 100% pass rate, 1.7s execution
- **MCP tools:** 4 (ghost_search, ghost_dork, ghost_fetch, ghost_recon)
- **Search engines:** 3 (DuckDuckGo Lite, Google HTML, Serper API)
- **Dork templates:** 12 predefined OSINT templates
- **Hash intelligence:** 4 services (CIRCL, MalwareBazaar, ThreatFox, VirusTotal)

## Sprint History

### Sprint 0: Foundation (Complete — 2026-06-16)

| Task | Status |
|------|--------|
| Project structure + architecture docs | Done |
| SearchResult dataclass + SearchEngine ABC | Done |
| DuckDuckGo Lite engine (POST, 202 retry) | Done |
| Proxy manager (direct + Tor routing) | Done |
| Browser fingerprint rotation (4 paranoia levels) | Done |
| CLI interface | Done |
| Config system (env vars + YAML) | Done |
| ParanoiaLevel enum (casual/cautious/ghost/midnight) | Done |
| Unit tests for base + DDG + proxy + fingerprint | Done |

### Sprint 1: Search + Dorking (Complete — 2026-06-16)

| Task | Status |
|------|--------|
| Google HTML scraper (CAPTCHA + consent detection) | Done |
| Serper.dev API engine (key detection, structured results) | Done |
| Google dork query builder (6 operators) | Done |
| Dork template library (12 templates) | Done |
| MCP server (JSON-RPC 2.0 stdio, 4 tools) | Done |
| Auto-fallback engine routing (Serper → Google → DDG) | Done |
| ghost_search, ghost_dork, ghost_fetch, ghost_recon tools | Done |
| Unit tests for Google, Serper, dorking, MCP | Done |

### Sprint 2.5b: Hash Intelligence (Complete — 2026-06-16)

| Task | Status |
|------|--------|
| Hash type auto-detection (MD5/SHA1/SHA256/SHA512) | Done |
| Local file hash computation (MD5 + SHA1 + SHA256) | Done |
| CIRCL NSRL lookup (known legitimate files) | Done |
| MalwareBazaar lookup (malware family, tags, first seen) | Done |
| ThreatFox lookup (C2, campaign associations) | Done |
| VirusTotal lookup (AV detections, optional key) | Done |
| Verdict logic (malicious/suspicious/clean/unknown) | Done |
| Unit tests for hash detection, verdicts, mocked lookups | Done |

### DDG Lite Fix (2026-06-17)

| Task | Status |
|------|--------|
| Switch from html.duckduckgo.com → lite.duckduckgo.com | Done |
| Rewrite parser for Lite table-based HTML format | Done |
| Add 202 throttle retry with exponential backoff | Done |
| Add proper browser User-Agent header | Done |
| Filter duckduckgo.com internal links from results | Done |
| Update test fixtures to DDG Lite format | Done |

### Regression Test Suite Buildout (2026-06-17)

| Task | Status |
|------|--------|
| conftest.py shared fixtures | Done |
| test_base.py (16 tests) | Done |
| test_dorking.py (33 tests) | Done |
| test_fingerprint.py (22 tests) | Done |
| test_google.py (21 tests) | Done |
| test_hashes.py (29 tests) | Done |
| test_mcp.py (12 tests) | Done |
| test_proxy.py (19 tests) | Done |
| test_serper.py (22 tests) | Done |
| Full suite validation (243/243 pass) | Done |

## Backlog (Prioritized)

| Priority | Sprint | Capability |
|----------|--------|-----------|
| Next | 2 | Subdomain enumeration (crt.sh + DNS) |
| Next | 2.5 | Vulnerability intelligence (NVD, OSV, CISA KEV, EPSS) |
| Medium | 2c | TLS certificate inspection |
| Medium | 3 | Browser automation (Playwright, Tier 1 fallback) |
| Medium | 3.5 | Threat intelligence feeds (Abuse.ch, OTX, RansomWatch) |
| Low | 4 | Domain reputation scoring |
| Low | 4b | Email verification (SMTP probing) |
| Future | 5c | People intelligence (phone/name/address) |
| Future | 6 | Wireless/Bluetooth intelligence (WiGLE) |
| Future | 6b | Cellular intelligence (IMSI/IMEI/tower) |

## Decisions Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-06-16 | Python standalone | Same stack as Unimind, asyncio for concurrent searches |
| 2026-06-16 | Modular engine design | Swap/add engines without touching core |
| 2026-06-16 | DuckDuckGo first engine | No API key needed, privacy-friendly |
| 2026-06-16 | MCP + CLI dual interface | Callable from AI workflows AND standalone terminal |
| 2026-06-16 | Free by default, paid optional | Core works without any API keys |
| 2026-06-16 | Mandatory provenance | Every finding includes source, URL, timestamp |
| 2026-06-17 | DDG Lite over DDG HTML | html.duckduckgo.com returns 202; Lite endpoint works with POST |
| 2026-06-17 | No browser automation yet | HTTP-only for now; Playwright deferred to Sprint 3 |
| 2026-06-17 | ForensicsMCP is separate project | GhostMCP finds, ForensicsMCP analyzes in sandbox |

## Known Issues

| Issue | Severity | Workaround |
|-------|----------|------------|
| DDG rate limits after burst requests | Low | min_delay=2.0 prevents in normal use; 202 retry handles transient |
| Google CAPTCHA on heavy scraping | Medium | Use Serper API (SERPER_API_KEY) or install curl_cffi |
| Hash lookup not yet exposed as MCP tool | Low | Available as Python API; MCP tool planned |

## Feature Backlog (Ideas / Future)

| Feature | Description | Priority |
|---------|-------------|----------|
| Reverse Tickle Tunnel | WebSocket-based reverse proxy: dev box client connects outbound to GhostMCP container, GhostMCP sends HTTP requests back through the WS to reach localhost services on the dev box. Eliminates Docker networking issues for ghost_render hitting localhost SPAs. Same architecture as ngrok/Cloudflare Tunnel. Client script (~150 lines) runs on dev box, consents to be "tickled" on specified ports. | Medium |
| Ghost Sprint 4: Domain reputation | URLhaus, PhishTank, AbuseIPDB, WHOIS age scoring | Low |
| Ghost Sprint 4b: Email verification | SMTP probing, SPF/DKIM/DMARC checks | Low |
| Ghost Sprint 5c: People intelligence | Phone/name/address OSINT (libphonenumber, public directories) | Low |
| Ghost Sprint 6: Wireless intel | WiGLE API, BSSID/SSID lookup, Bluetooth tracking | Low |
| Ghost Sprint 6b: Cellular intel | IMSI/IMEI decode, OpenCelliD tower geolocation | Low |
| ACR deployment | Push to wdrcentralus.azurecr.io, ACI container group, persistent daemon mode | When stable |

## Research (OSINT Tool Integration)

Evaluated 2026-06-17. These are candidate integrations — not committed to sprints yet.

| Tool | What It Does | API Type | Cost | Integration Assessment |
|------|-------------|----------|------|----------------------|
| **HIBP** | Email/domain breach lookups — "has this email been in a data breach?" | REST API, clean JSON | Free single lookups, $3.50/mo for API key (bulk) | **BUILD** — Easy integration, high value, clean API. `ghost_breach` tool. Already planned for Sprint 4. |
| **IntelTechniques** | Michael Bazzell's OSINT search aggregator — generates search URLs across dozens of engines per input type (email, phone, username, name, address) | No API — URL template logic | Free (we replicate the logic) | **BUILD** — Zero API cost. Build a URL template library: given email/phone/username, generate 30+ search URLs across Google, social media, public records, court records. Same pattern as our dork templates. `ghost_osint_urls` tool. |
| **Dehashed** | Leaked credential database search — email, username, IP, hash, password lookups against breach data | REST API with key | $5/week subscription | **BUILD (optional key)** — Very powerful for incident response. `ghost_breach_search` tool with DEHASHED_API_KEY env var. Similar pattern to Serper (works great with key, disabled without). Legally gray — results are from leaked databases. |
| **Epieos** | Email → Google account info, linked services, profile pics | No public API — web scraping | Free | **DEFER** — Fragile scraping target, limited value vs HIBP. Could break anytime. Revisit if they release an API. |
| **Maltego** | Graph-based OSINT correlation with visual link analysis | Paid transforms, Community Edition limited | $999/yr (Pro) | **SKIP** — Maltego is a GUI visualization tool. We don't need it — Unimind's Knowledge Graph + GhostMCP's data feeds already replicate what Maltego transforms do, minus the GUI. Building transforms is what we're already doing with each `ghost_*` tool. |
| **PimEyes** | Reverse face image search — upload photo, find matches across the internet | Paid API only | $30+/month | **SKIP** — Ethical and legal concerns with unsanctioned face search. Powerful but risky to include. Revisit only if there's a specific authorized use case (e.g., security team identity verification). |

### Priority for Integration
1. HIBP (Sprint 4 — easy win, clean API)
2. IntelTechniques URL generator (Sprint 5 — zero cost, high OSINT value)
3. Dehashed (Sprint 5+ — powerful but requires paid key + legal awareness)
