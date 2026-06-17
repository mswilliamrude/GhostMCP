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

## Sprint 3.5: Threat Intelligence (Clearnet APIs, No Tor)

| Task | Status | Notes |
|------|--------|-------|
| Abuse.ch integration (ThreatFox, URLhaus, MalwareBazaar, Feodo) | Pending | Malware C2s, IOCs, samples |
| AlienVault OTX pulses | Pending | Community threat intel, IOC feeds |
| RansomWatch/Ransomware.live | Pending | Ransomware victim tracking |
| HIBP breach monitoring | Pending | Recent breach announcements |
| CISA KEV active exploits | Pending | Already in Sprint 2.5, cross-ref here |
| LeakIX integration | Pending | Exposed services, leaked data |
| Malware sample lookup by CVE | Pending | MalwareBazaar + URLhaus → top 10 sample URLs |

### CLI Interface
```
ghost threat live                    # Last 72hrs: Abuse.ch + OTX IOCs
ghost threat ransomware              # Recent ransomware victim postings
ghost threat breaches                # HIBP recent breaches
ghost threat exploits-sold           # ThreatFox tagged "exploit" + OTX
ghost threat campaign "emotet"       # Filter by malware family
ghost threat samples CVE-2024-1234   # Top 10 malware sample URLs matching CVE
```

### API Keys (added to opencode.json environment)
```json
{
  "environment": {
    "OTX_API_KEY": "your-otx-key",
    "HIBP_API_KEY": "your-hibp-key",
    "LEAKIX_API_KEY": "your-leakix-key",
    "SHODAN_API_KEY": "your-shodan-key"
  }
}
```
Keys are OPTIONAL — Abuse.ch, RansomWatch, CISA KEV work without keys.
Keys stored in opencode.json environment section (same pattern as PERPLEXITY_API_KEY).

### Free API Endpoints (no key)
- Abuse.ch ThreatFox: `https://threatfox-api.abuse.ch/api/v1/`
- Abuse.ch URLhaus: `https://urlhaus-api.abuse.ch/v1/`
- Abuse.ch MalwareBazaar: `https://mb-api.abuse.ch/api/v1/`
- Abuse.ch Feodo: `https://feodotracker.abuse.ch/downloads/ipblocklist.json`
- RansomWatch: `https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json`
- CISA KEV: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

### Malware Sample Lookup (CVE → Samples)
```
Query flow:
  1. User asks: ghost threat samples CVE-2024-1234
  2. GhostMCP queries MalwareBazaar: tag=CVE-2024-1234
  3. Also queries URLhaus for URLs distributing exploits for that CVE
  4. Returns top 10 sample URLs + hashes + first_seen dates
  5. WARNING: these are LIVE malware URLs — display only, no auto-download
```

---

## Future: ForensicsMCP Integration (Sprint 5+)

### Vision
GhostMCP finds the threat → ForensicsMCP analyzes it in a sandbox.

```
GhostMCP                          ForensicsMCP (future)
─────────                         ────────────────────
ghost threat samples CVE-2024-x   
  → top 10 malware URLs           → forensics sandbox submit <url>
  → sample hashes                 → forensics detonate <hash>
                                  → forensics analyze <sample>
                                  
                                  Sandbox environments:
                                  • Windows 10/11 (VM)
                                  • Linux (Ubuntu/RHEL)
                                  • macOS (VM)
                                  • iOS (emulator)
                                  • Android (emulator)
                                  
                                  Analysis output:
                                  • Network IOCs (C2, DNS, beacons)
                                  • File system changes
                                  • Registry modifications (Windows)
                                  • Process tree
                                  • Memory artifacts
                                  • YARA rule matches
                                  • MITRE ATT&CK mapping
```

### Architecture (Future)
```
┌─────────────┐     MCP calls      ┌──────────────────┐
│  GhostMCP   │ ──────────────────→ │  ForensicsMCP    │
│  (recon)    │                     │  (analysis)      │
│             │ ←────────────────── │                  │
│  "find it"  │     results         │  "understand it" │
└─────────────┘                     └──────────────────┘
                                           │
                                    ┌──────┴──────┐
                                    │  Sandbox    │
                                    │  Cluster    │
                                    │             │
                                    │ Win │ Lin   │
                                    │ Mac │ iOS   │
                                    │ Android     │
                                    └─────────────┘
```

### ForensicsMCP Design Notes (for future development)
- Separate container/VM with isolated network
- Samples NEVER execute on the analysis host — always in disposable VMs
- VM snapshots reset after each detonation
- Network traffic captured (pcap) + analyzed
- Results fed back to Unimind knowledge store (lessons learned)
- Integration: GhostMCP discovers → ForensicsMCP analyzes → Unimind stores intelligence
- MITRE ATT&CK auto-mapping from observed behaviors
- Classification: all forensics data at level 3+ (sensitive)

## Sprint 2.5b: Hash Intelligence

| Task | Status | Notes |
|------|--------|-------|
| CIRCL hashlookup (known file identification) | Pending | Free, no key, identifies legit vs unknown files |
| MalwareBazaar hash lookup | Pending | Free, no key, malware family + tags |
| ThreatFox hash search | Pending | Free, no key, C2 + campaign associations |
| VirusTotal hash lookup | Pending | Free tier (4/min), 70+ AV results |
| Hybrid Analysis hash lookup | Pending | Free with key, sandbox results |

### CLI Interface
```
ghost hash <md5|sha1|sha256|sha384|sha512>    # Identify a file by hash
ghost hash --file /path/to/file               # Compute hash + lookup
ghost hash --batch hashes.txt                 # Bulk lookup from file
```

### Output Format
```
Hash: abc123def456...
Type: SHA256

CIRCL NSRL:      UNKNOWN (not a known legitimate file)
MalwareBazaar:   Family=Emotet | Tags=[banker,trojan] | First seen: 2024-03-15
ThreatFox:       C2=185.x.x.x:443 | Campaign=Emotet-E5
VirusTotal:      47/72 detections | Name=Trojan.GenericKD.46789
Hybrid Analysis: Threat score 95/100 | Sandbox: Win10-64

Verdict: MALICIOUS (high confidence)
```

### Free API Endpoints (no key)
- CIRCL: `https://hashlookup.circl.lu/lookup/sha256/{hash}`
- MalwareBazaar: `POST https://mb-api.abuse.ch/api/v1/` body: `query=get_info&hash={hash}`
- ThreatFox: `POST https://threatfox-api.abuse.ch/api/v1/` body: `query=search_hash&hash={hash}`

### Keyed APIs (optional, adds depth)
- VirusTotal: `GET https://www.virustotal.com/api/v3/files/{hash}` (VT_API_KEY)
- Hybrid Analysis: `GET https://www.hybrid-analysis.com/api/v2/search/hash` (HA_API_KEY)
- Malshare: `GET https://malshare.com/api.php?action=details&hash={hash}` (MALSHARE_API_KEY)
