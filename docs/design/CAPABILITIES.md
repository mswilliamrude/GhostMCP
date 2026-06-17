# GhostMCP — Complete Capabilities & Phase Roadmap

**Date:** 2026-06-16
**Status:** Sprint 0 + 2.5b built, all others designed
**Principle:** Free by default. Paid adds depth, never gates functionality.

---

## Phase Overview

| Phase | Name | Focus | Status |
|-------|------|-------|--------|
| 0 | Foundation | Search + proxy + fingerprint + CLI | ✅ Built |
| 1 | Dorking & MCP | Google dorking + templates + MCP interface | Designed |
| 2 | Infrastructure Recon | Subdomain + DNS + tech fingerprint + IP/ASN | Designed |
| 2c | Certificate Intel | TLS inspection + chain validation + expiry | Designed |
| 2.5 | Vulnerability Intel | CVE + package vulns + EPSS + exploits | Designed |
| 2.5b | Hash Intel | File identification via hash across 4 services | ✅ Built |
| 3 | Deep Intel | Shodan + Censys + email OSINT | Designed |
| 3.5 | Threat Intel | Malware feeds + ransomware + breaches + IOCs | Designed |
| 4 | Domain Reputation | Reputation scoring + security research | Designed |
| 4b | Email Verification | SMTP probing + SPF/DKIM/DMARC | Designed |
| 5 | Identity & Code | Username correlation + repo mining + metadata | Designed |
| 5b | Monitoring | Change detection + alerting over time | Designed |
| 6 | Wireless Intel | WiGLE BSSID/Bluetooth + wardriving data | Designed |
| 6b | Cellular Intel | IMSI/IMEI/tower lookup + carrier decode | Designed |
| 7 | Graph & Geo | Attack surface graph + geolocation enrichment | Designed |
| 8 | Cloud Enum | AWS/Azure/GCP bucket + service discovery | Designed |
| 9+ | ForensicsMCP | Sandbox integration (future separate project) | Future |

---

## Phase 0: Foundation ✅ BUILT

**What:** Core search engine with privacy-first proxy architecture.

| Feature | Implementation | Deps |
|---------|---------------|------|
| DuckDuckGo HTML search | Regex SERP parser, async httpx | httpx |
| Proxy manager | 4 paranoia levels (casual/cautious/ghost/midnight) | PySocks |
| Fingerprint rotation | UA + headers + Accept-Language | fake-useragent |
| Rate limiting | Per-engine, built into base class | asyncio |
| CLI interface | argparse, search + status commands | stdlib |
| Search result model | SearchResult dataclass (title, url, snippet, source, ts) | stdlib |

**Tests:** 21 passing | **Lines:** 931 | **Paid deps:** None

---

## Phase 1: Dorking & MCP Interface

**What:** Targeted search with Google dorking operators + MCP tool exposure.

| Feature | Method | Free? |
|---------|--------|-------|
| Google dork operators | site:, filetype:, inurl:, intitle:, intext:, ext: | ✅ |
| Dork template library | exposed_configs, login_pages, git_exposed, env_files, etc. | ✅ |
| Query builder | Natural language → dork syntax construction | ✅ |
| Serper.dev API engine | Structured Google results without scraping risk | ✅ (2500/mo free) |
| Google scraper (fallback) | curl_cffi for TLS fingerprint bypass | ✅ |
| MCP tool interface | ghost_search, ghost_dork, ghost_fetch, ghost_recon | ✅ |
| Google AI Overview interaction | Parse/interact with AI-generated answers | Experimental |

**MCP Tools:**
```python
ghost_search(query, engine="auto", paranoia="cautious")
ghost_dork(query, template=None, domain=None)
ghost_fetch(url, extract="text")
ghost_recon(domain, modules=["subdomains", "techstack"])
```

---

## Phase 2: Infrastructure Reconnaissance

**What:** Map a target's internet-facing infrastructure passively.

| Feature | Source | Free? | Endpoint |
|---------|--------|-------|----------|
| Subdomain enumeration | crt.sh | ✅ no key | `https://crt.sh/?q=%25.{domain}&output=json` |
| Subdomain enumeration | HackerTarget | ✅ no key | `https://api.hackertarget.com/hostsearch/?q={domain}` |
| Subdomain enumeration | RapidDNS | ✅ no key | `https://rapiddns.io/subdomain/{domain}` |
| Certificate transparency | crt.sh + Censys | ✅ / freemium | JSON endpoints |
| DNS records (all types) | dnspython + DoH | ✅ no key | Direct resolution + Google/Cloudflare DoH |
| DNS history | SecurityTrails | ⚠️ paid | REST API |
| Technology fingerprinting | Wappalyzer rules (local) | ✅ no key | Offline rule matching |
| IP/ASN intelligence | BGPView | ✅ no key | `https://api.bgpview.io/ip/{ip}` |
| IP/ASN intelligence | RIPEstat | ✅ no key | `https://stat.ripe.net/data/...` |
| IP geolocation | ipinfo.io | ✅ (50K/mo) | `https://ipinfo.io/{ip}/json` |

---

## Phase 2c: Certificate Intelligence

**What:** TLS certificate inspection equivalent to `openssl s_client`.

| Feature | Method | Free? |
|---------|--------|-------|
| Connect + pull TLS cert | Python ssl + socket (stdlib) | ✅ |
| Parse subject, issuer, SANs, dates | cryptography lib (optional) | ✅ |
| Expiry alerting (< 30 days) | Date comparison | ✅ |
| Full chain validation | Verify leaf → intermediate → root | ✅ |
| Protocol/cipher enumeration | TLS 1.2/1.3, cipher suites | ✅ |
| Self-signed detection | Issuer == Subject check | ✅ |
| OCSP stapling check | Revocation status | ✅ |
| CT log cross-reference | Was cert publicly logged? | ✅ |
| Wildcard detection | SAN pattern matching | ✅ |

**No external dependencies required.** Pure Python ssl + socket.

---

## Phase 2.5: Vulnerability Intelligence

**What:** CVE lookup, package scanning, exploit availability, risk scoring.

| Feature | Source | Free? | Endpoint |
|---------|--------|-------|----------|
| CVE lookup by ID | NVD (NIST) | ✅ no key | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={id}` |
| Package vulns (Python/JS/Go/Rust) | OSV.dev (Google) | ✅ no key | `https://api.osv.dev/v1/query` (POST) |
| GitHub Security Advisories | GHSA GraphQL | ✅ (free token) | GitHub GraphQL API |
| Actively exploited vulns | CISA KEV | ✅ no key | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| Exploit probability | EPSS | ✅ no key | `https://api.first.org/data/v1/epss?cve={id}` |
| Public exploits/PoCs | ExploitDB | ✅ no key | searchsploit / web search |
| Dependency scanning | pip-audit (local) | ✅ | CLI tool |
| Android Security Bulletins | Google source.android.com | ✅ | Scrape monthly bulletin |
| Tech stack → CVE mapping | Fingerprint + NVD query | ✅ | Combined modules |

---

## Phase 2.5b: Hash Intelligence ✅ BUILT

**What:** Identify unknown files by querying hash against threat intel databases.

| Feature | Source | Free? | Endpoint |
|---------|--------|-------|----------|
| Known-file identification | CIRCL hashlookup | ✅ no key | `https://hashlookup.circl.lu/lookup/sha256/{hash}` |
| Malware family detection | MalwareBazaar | ✅ no key | `POST https://mb-api.abuse.ch/api/v1/` |
| C2/campaign association | ThreatFox | ✅ no key | `POST https://threatfox-api.abuse.ch/api/v1/` |
| Multi-AV scan results | VirusTotal | ⚠️ free tier (4/min) | `GET https://www.virustotal.com/api/v3/files/{hash}` |
| Auto hash type detection | Length-based (32/40/64/128 hex) | ✅ local | — |
| File hashing | Compute MD5/SHA1/SHA256 from file | ✅ local | hashlib |
| Verdict scoring | Aggregate: clean/unknown/suspicious/malicious | ✅ local | — |

**Tests:** Syntax verified | **Lines:** 238 | **Paid deps:** None (VT optional)

---

## Phase 3: Deep Intelligence (Paid APIs)

**What:** Infrastructure scanning and deep domain/IP analysis.

| Feature | Source | Free Tier | Key Env Var |
|---------|--------|-----------|-------------|
| Infrastructure search | Shodan | Limited free | SHODAN_API_KEY |
| Certificate + host search | Censys | 250 queries/mo | CENSYS_API_ID, CENSYS_API_SECRET |
| Email OSINT | Hunter.io | 25 searches/mo | HUNTER_API_KEY |
| Deep domain analysis | VirusTotal | 4/min | VT_API_KEY |
| Exposed services/leaks | LeakIX | Free tier | LEAKIX_API_KEY |

---

## Phase 3.5: Threat Intelligence

**What:** Real-time attack monitoring, malware feeds, breach tracking.

| Feature | Source | Free? | Endpoint |
|---------|--------|-------|----------|
| Malware C2 infrastructure | ThreatFox (Abuse.ch) | ✅ no key | `https://threatfox-api.abuse.ch/api/v1/` |
| Malware distribution URLs | URLhaus (Abuse.ch) | ✅ no key | `https://urlhaus-api.abuse.ch/v1/` |
| Malware samples | MalwareBazaar (Abuse.ch) | ✅ no key | `https://mb-api.abuse.ch/api/v1/` |
| Botnet C2 IPs | Feodo Tracker (Abuse.ch) | ✅ no key | JSON feed |
| Community threat pulses | AlienVault OTX | ✅ free key | REST API |
| Ransomware victim tracking | RansomWatch | ✅ no key | GitHub JSON |
| Breach announcements | HIBP | ⚠️ free tier | REST API |
| Malware samples by CVE | MalwareBazaar tag search | ✅ no key | POST API |
| Active exploit campaigns | CISA KEV (cross-ref) | ✅ no key | JSON feed |

---

## Phase 4: Domain Reputation

**What:** Is this domain trustworthy? Aggregate signals into risk score.

| Feature | Source | Free? | Endpoint |
|---------|--------|-------|----------|
| Domain age (WHOIS) | python-whois | ✅ no key | Library |
| Malware distribution | URLhaus | ✅ no key | `https://urlhaus-api.abuse.ch/v1/host/{domain}` |
| Phishing detection | PhishTank | ✅ free key | `https://checkurl.phishtank.com/` |
| Phishing feed | OpenPhish | ✅ no key | `https://openphish.com/feed.txt` |
| Abuse reports | AbuseIPDB | ✅ free key | `https://api.abuseipdb.com/api/v2/check` |
| Domain analysis | URLScan.io | ✅ free key | `https://urlscan.io/api/v1/search/` |
| Multi-engine reputation | VirusTotal | ⚠️ free tier | `https://www.virustotal.com/api/v3/domains/{domain}` |
| Relationship mapping | ThreatCrowd | ✅ no key | `https://www.threatcrowd.org/searchApi/v2/domain/report/` |

**Verdict scoring:** 0-100 risk scale based on aggregate signals.

---

## Phase 4b: Email Verification

**What:** SMTP probing to verify email address existence + auth posture.

| Feature | Method | Free? |
|---------|--------|-------|
| MX record lookup | dnspython | ✅ |
| SMTP connect + banner grab | asyncio socket | ✅ |
| VRFY command probe | Direct SMTP | ✅ |
| RCPT TO probe | MAIL FROM + RCPT TO verification | ✅ |
| Catch-all detection | Random address test | ✅ |
| SPF record check | DNS TXT lookup | ✅ |
| DKIM record check | DNS selector lookup | ✅ |
| DMARC record check | DNS _dmarc TXT lookup | ✅ |
| Disposable email detection | Known domain list | ✅ |

**No external APIs.** Direct SMTP connection + DNS queries.

---

## Phase 5: Identity & Code Intelligence

**What:** Username correlation, code repo mining, document metadata extraction.

| Feature | Source/Tool | Free? |
|---------|-------------|-------|
| Username search across platforms | sherlock, maigret | ✅ |
| Code repo secret hunting | TruffleHog, gitleaks, GitHub Search API | ✅ |
| Document metadata extraction | exiftool, PyPDF2, python-docx | ✅ |
| EXIF GPS from images | Pillow EXIF parser | ✅ |
| Author/path extraction from Office docs | python-docx, openpyxl | ✅ |
| Leaked credential search | HIBP, breach-parse | ✅/⚠️ |

---

## Phase 5b: Change Detection & Monitoring

**What:** Track changes over time — new subdomains, certs, leaks, mentions.

| Feature | Method | Free? |
|---------|--------|-------|
| Subdomain diff (new/removed) | Periodic crt.sh + HackerTarget scans | ✅ |
| Certificate change alerting | CT log monitoring | ✅ |
| DNS record change detection | Periodic resolution + diff | ✅ |
| Repo mention monitoring | GitHub search polling | ✅ |
| Breach notification | HIBP subscription | ✅ |
| Keyword alerting (paste sites) | RSS/feed polling | ✅ |

**Implementation:** cron/scheduler + local SQLite for historical state + diff alerting.

---

## Phase 6: Wireless Intelligence

**What:** WiFi/Bluetooth device tracking via wardriving community data.

| Feature | Source | Free? | Endpoint |
|---------|--------|-------|----------|
| BSSID lookup (WiFi AP) | WiGLE | ✅ free key | `https://api.wigle.net/api/v2/network/search` |
| SSID search | WiGLE | ✅ free key | Same API |
| Bluetooth device search | WiGLE | ✅ free key | `https://api.wigle.net/api/v2/bluetooth/search` |
| GPS bounding box search | WiGLE | ✅ free key | Area query params |
| BSSID geolocation (backup) | Mylnikov | ✅ no key | `https://api.mylnikov.org/geolocation/wifi?bssid={bssid}` |
| MAC manufacturer lookup | IEEE OUI database | ✅ local | Offline DB |
| Sighting timeline | WiGLE history | ✅ free key | Multiple queries |

---

## Phase 6b: Cellular Intelligence

**What:** IMSI/IMEI/cell tower analysis and carrier identification.

| Feature | Source | Free? | Endpoint/Tool |
|---------|--------|-------|---------------|
| MCC/MNC decode (IMSI → carrier) | mccmnc package | ✅ local | `pip install mccmnc` |
| IMEI → device model (TAC) | TAC database | ✅ local | Offline SQLite |
| IMEI Luhn validation | Local computation | ✅ | hashlib |
| Cell tower geolocation | OpenCelliD / UnwiredLabs | ✅ free key | REST API |
| Tower area search | OpenCelliD | ✅ free key | Coordinate query |
| Google Geolocation (tower → GPS) | Google API | ✅ free tier | `googleapis.com/geolocation/v1/geolocate` |
| HLR lookup (number active?) | Telnyx/Vonage/Twilio | ⚠️ PAID | REST API |
| Number portability | Carrier APIs | ⚠️ PAID | Varies |

---

## Phase 7: Graph Mapping & Geolocation

**What:** Build entity relationship graphs + physical world enrichment.

| Feature | Method | Free? |
|---------|--------|-------|
| Entity graph (domain↔IP↔cert↔ASN↔email) | NetworkX + all prior data | ✅ |
| Relationship visualization | Graph export (GEXF, GraphML) | ✅ |
| Pivot path discovery | Graph traversal algorithms | ✅ |
| IP geolocation | ipinfo.io + MaxMind GeoLite2 | ✅ |
| EXIF GPS extraction | Pillow + piexif | ✅ |
| Timezone inference | IP location + language artifacts | ✅ |

---

## Phase 8: Cloud Infrastructure Enumeration

**What:** Discover exposed cloud assets (buckets, services, misconfigs).

| Feature | Method | Free? |
|---------|--------|-------|
| S3 bucket enumeration | DNS brute + HTTP probe | ✅ |
| Azure blob discovery | DNS pattern matching | ✅ |
| GCP bucket discovery | DNS pattern matching | ✅ |
| Cloud service fingerprinting | HTTP headers + DNS CNAME | ✅ |
| Misconfigured bucket detection | Permission check (public-read) | ✅ |

---

## Phase 9+: ForensicsMCP Integration (Future Project)

**What:** GhostMCP finds threats → ForensicsMCP detonates in sandboxes.

| Sandbox | OS | Purpose |
|---------|-----|---------|
| Windows 10/11 | Disposable VM | Malware behavior, registry, process tree |
| Linux (Ubuntu/RHEL) | Disposable VM | Server malware, rootkits |
| macOS | VM | macOS-specific malware |
| iOS | Emulator | Mobile malware |
| Android | Emulator | APK analysis, mobile threats |

**Analysis outputs:** Network IOCs, file changes, YARA matches, MITRE ATT&CK mapping.

---

## Cross-Cutting Features (All Phases)

| Feature | Description |
|---------|-------------|
| **Paranoia levels** | casual → cautious → ghost → midnight (controls proxy, fingerprint, timing) |
| **Provenance on all findings** | source, source_url, first_reported, last_updated, reason |
| **Staleness indicators** | 🔴 fresh, 🟠 recent, 🟡 aging, ⚪ stale, ⬜ historical |
| **API key management** | opencode.json environment section (same as Perplexity) |
| **No-key-required baseline** | Core functionality works without ANY paid subscriptions |
| **MCP + CLI dual interface** | Callable from AI workflows AND standalone terminal |
| **Async throughout** | asyncio + httpx for concurrent operations |
| **Rate limiting** | Per-engine, per-API, built into base class |
| **Result caching** | Don't re-query same target within TTL |

---

## API Key Configuration (Complete)

```json
{
  "mcp": {
    "ghostmcp": {
      "type": "local",
      "command": ["python3", "-m", "src.mcp"],
      "environment": {
        "GHOST_PARANOIA": "cautious",
        "SERPER_API_KEY": "optional — Google search without scraping",
        "SHODAN_API_KEY": "optional — infrastructure scanning",
        "CENSYS_API_ID": "optional — certificate/host search",
        "CENSYS_API_SECRET": "optional — certificate/host search",
        "VT_API_KEY": "optional — VirusTotal multi-AV",
        "OTX_API_KEY": "optional — AlienVault threat intel",
        "HIBP_API_KEY": "optional — breach monitoring",
        "LEAKIX_API_KEY": "optional — exposed services",
        "HUNTER_API_KEY": "optional — email OSINT",
        "WIGLE_API_KEY": "optional — wireless/Bluetooth lookup",
        "OPENCELLID_API_KEY": "optional — cell tower geolocation",
        "GOOGLE_GEOLOCATION_KEY": "optional — tower → GPS",
        "HLR_API_KEY": "optional — number validation (paid)",
        "HA_API_KEY": "optional — Hybrid Analysis sandbox",
        "MALSHARE_API_KEY": "optional — malware samples",
        "ABUSEIPDB_API_KEY": "optional — abuse reports",
        "URLSCAN_API_KEY": "optional — domain analysis"
      }
    }
  }
}
```

---

## Dependencies (Complete)

```
# Core (Sprint 0) — REQUIRED
httpx[socks]>=0.27       # HTTP client + SOCKS5 proxy support
fake-useragent>=1.5      # UA rotation

# DNS/Network (Sprint 2)
dnspython>=2.6           # DNS resolution
python-whois>=0.9        # WHOIS lookups
ipwhois>=1.2             # IP/ASN lookups

# Anti-detection (ghost+ modes)
curl-cffi>=0.7           # TLS/JA3 fingerprint spoofing
stem>=1.8                # Tor control protocol
pysocks>=1.7             # SOCKS5 transport

# Parsing
selectolax>=0.3          # Fast HTML parsing for SERPs

# Certificate inspection (Sprint 2c)
cryptography>=42.0       # x509 parsing (optional, stdlib ssl works too)

# Identity (Sprint 5)
# sherlock-project        # Username search (install separately)

# Cellular (Sprint 6b)
mccmnc>=0.1              # MCC/MNC offline database

# Graphing (Sprint 7)
networkx>=3.2            # Entity relationship graphs

# API integrations (optional)
shodan>=1.31             # Shodan API
censys>=2.2              # Censys API
vt-py>=0.18             # VirusTotal API

# MCP interface
fastmcp>=0.4             # MCP tool exposure

# CLI
# argparse (stdlib)      # Already using

# Testing
pytest>=8.0
pytest-asyncio>=0.23
```
