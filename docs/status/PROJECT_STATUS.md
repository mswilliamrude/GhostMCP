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

## Sprint 4: Domain Reputation & Security Research

| Task | Status | Notes |
|------|--------|-------|
| Domain age check (WHOIS creation date) | Pending | Newly registered = suspicious |
| URLhaus domain lookup | Pending | Known malware distribution (free, no key) |
| PhishTank check | Pending | Known phishing (free with key) |
| OpenPhish feed check | Pending | Phishing URLs (free) |
| AbuseIPDB lookup | Pending | IP/domain abuse reports (free tier) |
| URLScan.io domain analysis | Pending | Screenshots, DOM, tech, category |
| VirusTotal domain reputation | Pending | 70+ engine reputation (free tier) |
| ThreatCrowd relationships | Pending | Domain → IP, email, subdomain graph |
| Verdict scoring (new + reports + abuse = suspicious) | Pending | Aggregate signals |
| MITRE ATT&CK technique lookup | Pending | "How is this attack performed?" |
| Security research dorking | Pending | Query StackExchange, GitHub, PacketStorm for techniques |
| GTFOBins / LOLBAS lookup | Pending | Living off the land technique reference |

### CLI Interface
```
ghost domain example.com             # Full reputation check
ghost domain example.com --age       # Just WHOIS age check
ghost domain --batch domains.txt     # Bulk domain reputation

ghost research "pyarmor deobfuscation forensics"  # Find techniques/papers
ghost research --attack T1059.001    # MITRE ATT&CK technique details
ghost research --lolbas certutil     # Windows living-off-the-land lookup
```

### Domain Verdict Logic
```
Score starts at 0 (neutral)

+30  WHOIS created < 30 days ago (newly registered)
+20  URLhaus has malware reports
+20  PhishTank lists as phishing
+15  AbuseIPDB > 10 reports in 30 days
+10  VirusTotal > 3 engines flag it
+5   No HTTPS / invalid cert
+5   Domain name looks generated (high entropy)

0-10:   CLEAN
11-30:  LOW RISK
31-50:  SUSPICIOUS
51+:    HIGH RISK / LIKELY MALICIOUS
```

### Free API Endpoints
- WHOIS: python-whois library (no key)
- URLhaus: `https://urlhaus-api.abuse.ch/v1/host/{domain}` (no key)
- OpenPhish: `https://openphish.com/feed.txt` (no key)
- ThreatCrowd: `https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}` (no key)
- AbuseIPDB: `https://api.abuseipdb.com/api/v2/check` (free key required)
- URLScan: `https://urlscan.io/api/v1/search/?q=domain:{domain}` (free key)
- PhishTank: `https://checkurl.phishtank.com/` (free key)
- VirusTotal: `https://www.virustotal.com/api/v3/domains/{domain}` (free key)
- MITRE ATT&CK: `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json`
- GTFOBins: `https://gtfobins.github.io/` (scrape or GitHub API)
- LOLBAS: `https://lolbas-project.github.io/api/lolbas.json`

## Sprint 2c: Certificate Verification (TLS Inspection)

| Task | Status | Notes |
|------|--------|-------|
| Connect and pull TLS cert from host:port | Pending | Pure Python ssl module, no openssl needed |
| Parse certificate fields (subject, issuer, SANs, dates) | Pending | x509 parsing via ssl/cryptography lib |
| Expiry check (days until expiration) | Pending | Alert if < 30 days |
| Chain validation (intermediate + root) | Pending | Verify full chain of trust |
| SAN extraction (all hostnames covered) | Pending | Subject Alternative Names |
| Issuer identification (Let's Encrypt, DigiCert, etc) | Pending | Who issued it |
| Certificate pinning detection | Pending | HPKP / expect-CT headers |
| Self-signed detection | Pending | Flag untrusted certs |
| Certificate transparency lookup (crt.sh cross-ref) | Pending | Was this cert logged publicly |
| Wildcard detection | Pending | *.example.com coverage |
| Protocol/cipher enumeration | Pending | TLS 1.2/1.3, cipher suites |
| OCSP stapling check | Pending | Revocation status |

### CLI Interface
```
ghost cert example.com                  # Full cert inspection (port 443 default)
ghost cert example.com:8443             # Custom port
ghost cert example.com --chain          # Show full certificate chain
ghost cert example.com --expiry         # Just days until expiration
ghost cert example.com --sans           # Just SANs (all covered hostnames)
ghost cert example.com --json           # Machine-readable output
```

### Example Output
```
ghost cert example.com

TLS Certificate: example.com:443
═══════════════════════════════════════════════════════
Subject:      CN=example.com
Issuer:       CN=R3, O=Let's Encrypt, C=US
Valid from:   2024-01-15 00:00:00 UTC
Valid until:  2024-04-14 23:59:59 UTC
Expires in:   47 days ✅

SANs (Subject Alternative Names):
  • example.com
  • www.example.com
  • api.example.com
  • *.dev.example.com (wildcard)

Chain:
  [0] CN=example.com (leaf)
  [1] CN=R3, O=Let's Encrypt (intermediate)
  [2] CN=ISRG Root X1 (root, trusted)

Protocol:     TLS 1.3
Cipher:       TLS_AES_256_GCM_SHA384
Key:          EC 256-bit (P-256)
Serial:       0A:1B:2C:3D:4E:5F...
Fingerprint:  SHA256:ab:cd:ef:12:34...

OCSP:         Stapled ✅ (status: good)
CT Logged:    Yes (3 logs)
Self-signed:  No
Wildcard:     Yes (*.dev.example.com)

Provenance:
  Source:     Direct TLS connection
  Checked:    2024-02-27T15:30:00Z (live query)
```

### Implementation
```python
# Pure Python — no openssl binary needed
import ssl
import socket
from cryptography import x509  # for detailed parsing
from cryptography.hazmat.backends import default_backend

# Connect and grab cert
context = ssl.create_default_context()
with socket.create_connection((host, port)) as sock:
    with context.wrap_socket(sock, server_hostname=host) as tls:
        cert_der = tls.getpeercert(binary_form=True)
        cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
        cert_info = tls.getpeercert()  # parsed dict
        cipher = tls.cipher()
        version = tls.version()
```

### Dependencies
- `ssl` (stdlib — always available)
- `socket` (stdlib)
- `cryptography` (optional, for detailed x509 parsing + chain validation)
- No external services needed — direct connection to target

## Sprint 4b: Email Verification (SMTP Probing)

| Task | Status | Notes |
|------|--------|-------|
| MX record lookup for domain | Pending | dnspython → find mail servers |
| SMTP connect + banner grab | Pending | asyncio SMTP, identify server software |
| VRFY command probe | Pending | Direct user verification (often disabled) |
| RCPT TO probe | Pending | Send MAIL FROM + RCPT TO, check 250 vs 550 |
| Catch-all detection | Pending | Test with random address — if accepts all, can't verify |
| Rate limiting / politeness | Pending | Don't hammer mail servers, 1 probe per 5s |
| Multiple address batch check | Pending | Verify list of addresses against same domain |
| SPF/DKIM/DMARC record check | Pending | DNS-based email auth posture |
| Disposable email detection | Pending | Check against known disposable domains list |

### CLI Interface
```
ghost email verify user@example.com          # Single address verification
ghost email verify --batch emails.txt        # Bulk verification
ghost email mx example.com                   # MX records + mail server info
ghost email auth example.com                 # SPF + DKIM + DMARC check
ghost email disposable user@tempmail.xyz     # Is this a throwaway?
```

### Example Output
```
ghost email verify admin@example.com

Email Verification: admin@example.com
══════════════════════════════════════════════
Domain:       example.com
MX Records:   mx1.example.com (pri 10), mx2.example.com (pri 20)
Mail Server:  mx1.example.com:25
Banner:       220 mx1.example.com ESMTP Postfix

Verification:
  VRFY:       disabled (252 response)
  RCPT TO:    250 OK ✅ — address EXISTS
  Catch-all:  No (random address rejected with 550)

Verdict:      VALID — address exists on this mail server

Email Auth Posture:
  SPF:        v=spf1 include:_spf.google.com -all ✅
  DKIM:       selector1._domainkey.example.com → found ✅
  DMARC:      v=DMARC1; p=reject; rua=mailto:dmarc@example.com ✅

Provenance:
  Source:     Direct SMTP connection to mx1.example.com:25
  Checked:    2024-02-27T15:45:00Z (live probe)
  Method:     RCPT TO verification (VRFY disabled on server)
```

### SMTP Probe Flow
```python
# Pseudocode — async SMTP probing
async def verify_email(address: str) -> EmailVerifyResult:
    user, domain = address.split('@')
    
    # Step 1: Find MX
    mx_records = await dns_lookup(domain, 'MX')
    mx_host = mx_records[0].exchange
    
    # Step 2: Connect
    reader, writer = await asyncio.open_connection(mx_host, 25)
    banner = await reader.readline()  # 220 greeting
    
    # Step 3: HELO
    writer.write(b'HELO ghost.local\r\n')
    await reader.readline()  # 250
    
    # Step 4: Try VRFY first
    writer.write(f'VRFY {address}\r\n'.encode())
    vrfy_resp = await reader.readline()
    # 250 = exists, 252 = can't verify, 550 = doesn't exist
    
    # Step 5: RCPT TO probe (more reliable)
    writer.write(b'MAIL FROM:<probe@ghost.local>\r\n')
    await reader.readline()  # 250
    writer.write(f'RCPT TO:<{address}>\r\n'.encode())
    rcpt_resp = await reader.readline()
    # 250 = exists, 550 = doesn't exist, 452 = try later
    
    # Step 6: Catch-all detection
    writer.write(f'RCPT TO:<{random_string}@{domain}>\r\n'.encode())
    catchall_resp = await reader.readline()
    # If 250 → catch-all (can't trust RCPT TO results)
    
    # Step 7: QUIT
    writer.write(b'QUIT\r\n')
    writer.close()
```

### Ethics / Legality Notes
- SMTP probing is a GRAY AREA — some servers consider it abuse
- Always: use realistic HELO, don't probe same server > 5 times/hour
- Never: actually SEND email, forge headers, or relay through the server
- Respect 421/452 responses (server asking you to slow down)
- Ghost/midnight modes: probe through Tor to avoid IP reputation damage
- Paranoia level affects probe aggressiveness:
  - casual: direct connection, real-ish HELO
  - cautious: rotating source IP, realistic HELO
  - ghost: Tor, minimal probes, longer delays
  - midnight: single probe then disconnect, maximum stealth

## Sprint 6: Wireless / Bluetooth Intelligence (WiGLE)

| Task | Status | Notes |
|------|--------|-------|
| WiGLE API integration | Pending | Free account, API key required |
| BSSID search (WiFi AP lookup) | Pending | Location + SSID + encryption + sightings |
| SSID search (find all APs with name) | Pending | Rogue AP detection, corporate tracking |
| Bluetooth device search | Pending | BLE device location history |
| GPS bounding box search | Pending | "What networks exist in this area?" |
| OUI/MAC manufacturer lookup | Pending | Free, IEEE database (no API needed) |
| Sighting timeline (device movement) | Pending | Where has this device been seen over time? |
| Nearby network correlation | Pending | What else was seen at same time/place? |
| Mylnikov BSSID geolocation | Pending | Free, no key backup for location |

### CLI Interface
```
ghost wireless --bssid AA:BB:CC:DD:EE:FF     # WiFi AP lookup + location history
ghost wireless --ssid "CorpNet"              # Find all APs broadcasting this name
ghost wireless --bluetooth AA:BB:CC:DD:EE:FF # Bluetooth device tracking
ghost wireless --area 30.27,-97.74 --radius 1km  # What's in this area?
ghost wireless --oui AA:BB:CC               # Manufacturer lookup (free, local)
```

### API Endpoints
- WiGLE: `https://api.wigle.net/api/v2/network/search` (free key: WIGLE_API_KEY)
- WiGLE Bluetooth: `https://api.wigle.net/api/v2/bluetooth/search`
- Mylnikov (backup): `https://api.mylnikov.org/geolocation/wifi?bssid={bssid}` (no key)
- IEEE OUI: local database lookup (download once, query offline)

### Use Cases
- Track device movement over time (BSSID seen in multiple cities)
- Detect rogue APs (corporate SSID appearing in unexpected locations)
- Correlate wireless presence with physical location
- Identify device manufacturer from MAC prefix
- Map wireless infrastructure for a physical location

## Sprint 6b: Cellular Intelligence (IMSI/IMEI/Tower)

| Task | Status | Notes |
|------|--------|-------|
| MCC/MNC decode (IMSI → country + carrier) | Pending | Free: mccmnc Python package, offline DB |
| OpenCelliD tower geolocation | Pending | Free with key: tower ID → GPS coordinates |
| IMEI → device model (TAC lookup) | Pending | Free: offline TAC database |
| IMEI Luhn validation | Pending | Local computation, no API |
| Cell tower area search | Pending | "What towers are near this location?" |
| OUI/manufacturer from IMEI TAC | Pending | GSMA TAC prefix → brand/model |
| HLR lookup (is number active?) | Pending | PAID: hlrlookup.com, Telnyx, various |
| Number portability check | Pending | PAID: carrier APIs |
| Google Geolocation API (tower → coords) | Pending | Free tier available |

### CLI Interface
```
ghost cellular --imsi 310260123456789       # Decode IMSI → country + carrier
ghost cellular --imei 353456789012345       # IMEI → device model + validation
ghost cellular --tower 310 260 1234 5678    # Cell tower → GPS location
ghost cellular --area 30.27,-97.74 --radius 5km  # Towers in area
ghost cellular --mcc-mnc 310 260            # Just carrier lookup
ghost cellular --validate-imei 353456789012345  # Luhn check only
```

### Example Output
```
ghost cellular --imsi 310260123456789

IMSI Analysis: 310260123456789
══════════════════════════════════════════
MCC:          310 → United States
MNC:          260 → T-Mobile USA
MSIN:         123456789 (subscriber ID)
Network:      T-Mobile US (GSM/LTE/5G)
Network type: Commercial mobile

Carrier info:
  Brand:      T-Mobile
  Country:    United States
  Technology: GSM 850/1900, LTE, 5G NR
  Status:     Active network

Note: Live status (active/roaming/ported) requires HLR lookup (paid API)

Provenance:
  Source:     mccmnc database (ITU/GSMA derived)
  Updated:    2024-02 (database version)
  Method:     Offline MCC/MNC prefix matching
```

### Free Resources
- **mccmnc** Python package: `pip install mccmnc` — offline MCC/MNC database
  ```python
  from mccmnc import find_matches
  results = find_matches(mcc="310", mnc="260")
  # → [{'mcc': '310', 'mnc': '260', 'operator': 'T-Mobile USA', 'country': 'US'}]
  ```
- **OpenCelliD**: `https://opencellid.org/` — free account + API token
  - Endpoint: `https://us1.unwiredlabs.com/v2/process.php` (UnwiredLabs hosts it)
  - Free tier: limited lookups/day
  - Data: cell_id + lac + mcc + mnc → latitude, longitude, accuracy
- **TAC database**: downloadable from GSMA or community mirrors
  - First 8 digits of IMEI → device manufacturer + model
  - Python: split IMEI, validate Luhn, lookup TAC in local SQLite
- **Google Geolocation API**: `https://www.googleapis.com/geolocation/v1/geolocate`
  - Free tier available (requires API key)
  - Input: cell tower IDs → output: GPS coordinates
- **mcc-mnc-list** (GitHub): community-maintained CSV of all MCC/MNC pairs
  - `https://github.com/musalbas/mcc-mnc-table`

### Paid APIs (Optional)
- **HLR Lookup** (is number active/roaming/ported):
  - hlrlookup.com — per-query pricing
  - Telnyx — carrier-grade, enterprise pricing
  - Vonage (Nexmo) Number Insight — tiered free/paid
  - Twilio Lookup — $0.005/lookup for carrier info
  - Key env var: HLR_API_KEY + HLR_PROVIDER
- **Number Portability**:
  - Carrier-specific APIs
  - Some HLR providers include porting status

### Legal / Ethical Notes
- MCC/MNC decoding: completely legal (public ITU data)
- IMEI lookup: legal (public TAC database)
- OpenCelliD: legal (community-contributed data)
- HLR lookup: LEGAL but requires legitimate purpose (fraud prevention, KYC)
- SS7/Diameter interception: ILLEGAL without carrier authorization
- IMSI catching (Stingray): ILLEGAL without law enforcement authority
- GhostMCP will NEVER implement active cellular interception
