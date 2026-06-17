# GhostMCP — OSINT APIs, Libraries, and Data Sources

**Date:** 2026-06-16
**Source:** Perplexity research (3 iterations)
**Purpose:** Comprehensive inventory of tools, APIs, and libraries needed to implement GhostMCP

---

## Executive Summary

GhostMCP needs 4 layers of tooling:
1. **Search engines** (find information) — Serper API, DDG scrape, crt.sh
2. **Network libraries** (make requests safely) — httpx, curl_cffi, PySocks
3. **OSINT data sources** (enrich findings) — Shodan, Censys, SecurityTrails
4. **Parsing + detection** (extract meaning) — selectolax, Wappalyzer rules, dnspython

The **free-by-default** design principle means: everything works without API keys
in "casual" mode, paid APIs add capability in higher paranoia levels.

---

## 1. Python Libraries by Category

### Web Scraping (Anti-Detection Priority)

| Library | Async | Detection Avoidance | Best For |
|---------|-------|-------------------|----------|
| **httpx** | ✅ | Low-Medium | Clean HTTP, production default |
| **aiohttp** | ✅ | Low-Medium | High concurrency scraping |
| **curl_cffi** | ❌ (sync) | **HIGH** (JA3/TLS mimicry) | Bypassing TLS fingerprinting |
| **playwright** | ✅ | **HIGH** (stealth mode) | JS-rendered pages, CAPTCHA bypass |
| **undetected-chromedriver** | ❌ | HIGH | Chromium automation when playwright fails |

**Recommendation:** `httpx` default → escalate to `curl_cffi` if fingerprinted → `playwright` for JS-heavy targets.

### Proxy / Transport

| Library | Purpose | Notes |
|---------|---------|-------|
| **PySocks** | SOCKS5/Tor transport | Core dependency for ghost/midnight modes |
| **stem** | Tor control protocol | Circuit rotation via NEWNYM signal |
| **httpx** (built-in) | HTTP proxy support | Supports SOCKS5 via socksio |

**Recommendation:** PySocks + stem for Tor. Build rotation logic in our own orchestration layer.

### DNS / Network Recon

| Library | Purpose | Async |
|---------|---------|-------|
| **dnspython** | Full DNS toolkit (all record types) | Partial |
| **aiodns** | Async DNS resolution | ✅ |
| **python-whois** | Domain WHOIS lookup | ❌ |
| **ipwhois** | IP → ASN/org lookup | ❌ |

### HTML Parsing

| Library | Speed | Best For |
|---------|-------|----------|
| **selectolax** | Fastest | SERP HTML parsing (speed critical) |
| **parsel** | Fast | Selector-oriented extraction (Scrapy-style) |
| **beautifulsoup4** | Slowest | Flexibility, forgiving of malformed HTML |

**Recommendation:** selectolax for SERP parsing (speed matters), BS4 as fallback.

### Anti-Detection

| Library | Purpose |
|---------|---------|
| **fake-useragent** | Realistic UA string rotation |
| **curl_cffi** | JA3/TLS fingerprint spoofing |
| **playwright-stealth** | Browser automation anti-detection |

---

## 2. Free OSINT Data Sources (No API Key Required)

### Subdomain Discovery

| Source | Endpoint | Rate Limit | Client |
|--------|----------|-----------|--------|
| **crt.sh** | `https://crt.sh/?q=%25.{domain}&output=json` | Unspecified (add backoff) | httpx + JSON |
| **HackerTarget** | `https://api.hackertarget.com/hostsearch/?q={domain}` | Light limits | httpx |
| **RapidDNS** | `https://rapiddns.io/subdomain/{domain}` | Scrape HTML | httpx + selectolax |
| **urlscan.io** | `https://urlscan.io/api/v1/search/?q=domain:{domain}` | Free tier with token | httpx |

### IP / ASN Intelligence

| Source | Endpoint | Client |
|--------|----------|--------|
| **BGPView** | `https://api.bgpview.io/ip/{ip}` | httpx |
| **RIPEstat** | `https://stat.ripe.net/data/{endpoint}/data.json?resource={ip}` | httpx |
| **ipinfo.io** | `https://ipinfo.io/{ip}/json` | httpx (50K/month free) |
| **ipapi.co** | `https://ipapi.co/{ip}/json/` | httpx |

### DNS Records (Public, No Key)

| Source | Endpoint | Client |
|--------|----------|--------|
| **Google DoH** | `https://dns.google/resolve?name={domain}&type={type}` | httpx |
| **Cloudflare DoH** | `https://cloudflare-dns.com/dns-query?name={domain}&type={type}` | httpx |
| **Direct resolvers** | UDP/TCP to 1.1.1.1, 8.8.8.8 | dnspython |

### Technology Detection (Free, Local)

| Source | Method | Client |
|--------|--------|--------|
| **Wappalyzer rules** | Local rule matching (no API needed) | Wappalyzer Python package |
| **HTTP headers** | Server, X-Powered-By, etc. | httpx response headers |
| **HTML meta tags** | Generator, framework signatures | selectolax parsing |

### Certificate Transparency

| Source | Endpoint | Client |
|--------|----------|--------|
| **crt.sh** | Same as subdomain discovery | httpx + JSON |
| **Censys** (free tier) | `https://search.censys.io/api` | censys Python package |
| **Google CT** | Public CT log search | httpx |

---

## 3. Paid APIs (Optional, Higher Capability)

### Tier 1: Affordable / Free Tiers

| Service | Free Tier | What It Adds | API Key Env Var |
|---------|-----------|-------------|-----------------|
| **Serper.dev** | 2,500 searches/month free | Structured Google results, no scraping risk | SERPER_API_KEY |
| **Shodan** | Limited free queries | IoT/infrastructure scanning, banners | SHODAN_API_KEY |
| **Censys** | 250 queries/month free | Certificates, hosts, services | CENSYS_API_ID + CENSYS_API_SECRET |
| **VirusTotal** | 4 lookups/minute free | Domain/IP intelligence, relationships | VT_API_KEY |
| **urlscan.io** | Free tier with account | URL analysis, screenshots, DOM | URLSCAN_API_KEY |
| **Hunter.io** | 25 searches/month free | Email finder, domain emails | HUNTER_API_KEY |

### Tier 2: Paid (Significant Value)

| Service | Cost | What It Adds |
|---------|------|-------------|
| **SecurityTrails** | ~$50/month | Passive DNS history, subdomain API, WHOIS |
| **DomainTools** | Enterprise | Deep domain intelligence, risk scoring |
| **SpiderFoot HX** | Paid | 200+ OSINT sources automated |
| **Farsight DNSDB** | Paid | Deep passive DNS history |
| **BinaryEdge** | Paid | Internet-wide scanning data |

---

## 4. Skills / Modules to Build

Based on the research, here's what GhostMCP needs organized by sprint:

### Sprint 0 (Foundation) — No API keys needed

| Module | Dependencies | What It Does |
|--------|-------------|-------------|
| `engines/duckduckgo.py` | httpx, selectolax | DDG HTML scraping |
| `proxy/manager.py` | PySocks | Proxy selection + rotation |
| `proxy/tor.py` | PySocks, stem | Tor SOCKS5 + circuit rotation |
| `proxy/fingerprint.py` | fake-useragent, curl_cffi | UA + TLS rotation |
| `parsers/html.py` | selectolax | SERP result extraction |
| `utils/rate_limit.py` | asyncio | Rate limiting + jitter |
| `cli.py` | argparse/click | CLI interface |
| `mcp.py` | fastmcp | MCP tool interface |

### Sprint 1 (Search Engines) — Optional API keys

| Module | Dependencies | What It Does |
|--------|-------------|-------------|
| `engines/google.py` | curl_cffi, selectolax | Google scraping (cautious+) |
| `engines/serper.py` | httpx | Serper.dev API (structured) |
| `engines/brave.py` | httpx | Brave Search API |
| `dorking/builder.py` | — | Query construction with operators |
| `dorking/templates.py` | — | Dork template library |

### Sprint 2 (OSINT / Recon) — Free APIs

| Module | Dependencies | What It Does |
|--------|-------------|-------------|
| `recon/subdomain.py` | httpx | crt.sh + HackerTarget + RapidDNS |
| `recon/certs.py` | httpx | Certificate transparency search |
| `recon/dns_history.py` | dnspython, httpx | DNS records + DoH queries |
| `recon/techstack.py` | Wappalyzer rules, httpx | Technology fingerprinting |
| `recon/ip_intel.py` | httpx, ipwhois | BGPView + RIPEstat + ipinfo |

### Sprint 3 (Advanced) — Paid API integration

| Module | Dependencies | What It Does |
|--------|-------------|-------------|
| `engines/shodan.py` | shodan | Infrastructure search |
| `engines/censys.py` | censys | Certificate + host search |
| `recon/email.py` | httpx | Hunter.io + emailrep |
| `recon/vt_intel.py` | vt-py | VirusTotal domain/IP intel |

---

## 5. Paranoia Level → Library Mapping

| Level | HTTP Client | Proxy | Fingerprint | Timing |
|-------|------------|-------|-------------|--------|
| casual | httpx (direct) | None | Static UA | None |
| cautious | httpx (proxy) | Rotating SOCKS5 | Rotating UA | 1-3s jitter |
| ghost | curl_cffi (Tor) | Tor SOCKS5 | Full rotation (JA3+UA+headers) | 3-8s jitter |
| midnight | curl_cffi (Tor rotating) | Tor per-request circuit | Full + header randomization | 5-15s + human patterns |

---

## 6. Key Dependencies (requirements.txt)

```
# Core
httpx[socks]>=0.27
selectolax>=0.3
fake-useragent>=1.5
dnspython>=2.6
pysocks>=1.7

# Anti-detection (ghost+ modes)
curl-cffi>=0.7
stem>=1.8

# Optional APIs
shodan>=1.31
censys>=2.2
vt-py>=0.18

# MCP interface
fastmcp>=0.4

# CLI
click>=8.1

# Testing
pytest>=8.0
pytest-asyncio>=0.23
```

---

## 7. Architecture Decisions (from research)

1. **httpx as default HTTP client** — production-grade, async, SOCKS5 support via httpx[socks]
2. **curl_cffi for anti-detection** — only library that spoofs JA3/TLS fingerprint in Python
3. **selectolax for HTML parsing** — 10-20x faster than BS4, critical for SERP parsing
4. **Serper.dev as primary Google** — structured results, no scraping risk, 2500/month free
5. **crt.sh + HackerTarget for free subdomain** — no API key, reliable, JSON output
6. **dnspython for DNS** — full control, all record types, widely used
7. **PySocks + stem for Tor** — proven stack, circuit rotation via control port
8. **Build proxy rotation ourselves** — no good library exists, our orchestration layer
9. **Wappalyzer rules local** — no API call needed for tech detection, runs offline
10. **Paranoia levels in config** — one setting controls entire request pipeline behavior
