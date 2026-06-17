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
