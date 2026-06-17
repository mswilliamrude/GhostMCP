# GhostMCP — Phase Estimates & Level of Effort

**Date:** 2026-06-16
**Estimation basis:** Sprint 0 took ~400 lines in ~1 agent dispatch. Each subsequent
sprint scaled by complexity, API count, and test requirements.

---

## Summary Table

| Phase | Name | LOE | Time Est | Deps | Lines Est | Tests Est |
|-------|------|-----|----------|------|-----------|-----------|
| **0** | Foundation | Low | ✅ Done | httpx, fake-useragent | 931 | 21 |
| **1** | Dorking + MCP | Low-Med | 4-6 hrs | curl_cffi, fastmcp | ~600 | ~15 |
| **2** | Infrastructure Recon | Medium | 8-12 hrs | dnspython, python-whois, ipwhois | ~800 | ~25 |
| **2c** | Certificate Intel | Low | 3-4 hrs | cryptography (optional) | ~300 | ~12 |
| **2.5** | Vulnerability Intel | Medium | 8-10 hrs | None (all HTTP) | ~700 | ~20 |
| **2.5b** | Hash Intel | Low | ✅ Done | httpx | 238 | — |
| **3** | Deep Intel (paid APIs) | Low-Med | 4-6 hrs | shodan, censys, vt-py | ~500 | ~15 |
| **3.5** | Threat Intel | Medium | 6-8 hrs | None (all HTTP) | ~600 | ~18 |
| **4** | Domain Reputation | Medium | 8-10 hrs | python-whois | ~700 | ~20 |
| **4b** | Email Verification | Medium | 6-8 hrs | dnspython | ~400 | ~15 |
| **5** | Identity + Code | High | 12-16 hrs | sherlock, gitleaks, Pillow | ~1000 | ~30 |
| **5b** | Change Detection | Medium | 8-10 hrs | SQLite for state | ~500 | ~15 |
| **5c** | People Intel | Med-High | 10-14 hrs | phonenumbers | ~700 | ~20 |
| **6** | Wireless Intel | Low-Med | 4-6 hrs | None (all HTTP) | ~400 | ~12 |
| **6b** | Cellular Intel | Low-Med | 4-6 hrs | mccmnc, phonenumbers | ~350 | ~12 |
| **7** | Graph + Geolocation | High | 12-16 hrs | networkx, Pillow | ~800 | ~20 |
| **8** | Cloud Enumeration | Med-High | 10-12 hrs | None (all HTTP + DNS) | ~600 | ~18 |
| **9+** | ForensicsMCP | Very High | 40+ hrs | VMs, YARA, separate project | ~3000+ | ~50+ |

**Totals (excluding Phase 9):**
- Estimated lines: ~9,100
- Estimated tests: ~278
- Estimated time: ~110-140 hours (agent-delegated, ~30-40 hours with parallelism)
- Built so far: 1,169 lines, 21 tests

---

## Detailed Phase Descriptions

### Phase 0: Foundation ✅ COMPLETE

**Level of Effort:** Low
**Time:** Complete (single agent dispatch + review)
**Lines:** 931 | **Tests:** 21

Phase 0 establishes the core architecture that all subsequent phases build upon.
It implements the DuckDuckGo HTML search engine with asynchronous HTTP requests
via httpx, a proxy management layer supporting four paranoia levels (casual through
midnight), browser fingerprint rotation with realistic User-Agent strings and
header randomization, rate limiting baked into the base search engine class, and
a command-line interface using argparse. The design is async-first throughout,
uses no paid dependencies, and includes 21 unit tests that validate SERP parsing,
URL unwrapping, and mocked search operations without making live network calls.
This phase proves the architecture works and provides the foundation (base classes,
config system, proxy layer) that every other phase inherits from.

---

### Phase 1: Dorking & MCP Interface

**Level of Effort:** Low-Medium
**Time Estimate:** 4-6 hours
**Lines Estimate:** ~600 | **Tests Estimate:** ~15
**Dependencies:** curl_cffi (TLS spoofing), fastmcp (MCP tools)
**Blocked by:** Nothing (Sprint 0 provides all prerequisites)

Phase 1 transforms GhostMCP from a simple search tool into a precision
reconnaissance instrument by adding Google dorking support and exposing all
capabilities as MCP tools callable from AI coding agents. The dorking module
implements query construction with all standard Google operators (site:, filetype:,
inurl:, intitle:, intext:, ext:), a template library of pre-built reconnaissance
queries (exposed configurations, login pages, directory listings, git repositories,
environment files, API documentation), and a natural-language-to-dork translator
that converts plain English descriptions into effective dork syntax. The MCP
interface exposes four tools (ghost_search, ghost_dork, ghost_fetch, ghost_recon)
that make GhostMCP callable from Unimind, opencode, or any other MCP client.
Additionally, this phase adds the Google scraper engine using curl_cffi for TLS
fingerprint mimicry (essential for avoiding Google's bot detection) and optionally
integrates with Serper.dev's API for structured, scrape-free Google results on
the free tier (2,500 searches/month). The experimental Google AI Overview
interaction feature would parse and allow follow-up queries against Google's
AI-generated answer summaries, though this is fragile and may require ongoing
maintenance as Google changes their markup.

---

### Phase 2: Infrastructure Reconnaissance

**Level of Effort:** Medium
**Time Estimate:** 8-12 hours
**Lines Estimate:** ~800 | **Tests Estimate:** ~25
**Dependencies:** dnspython, python-whois, ipwhois
**Blocked by:** Phase 0 (needs proxy + HTTP client)

Phase 2 enables passive mapping of a target's entire internet-facing
infrastructure without sending a single packet to the target itself. Subdomain
enumeration queries three free sources (crt.sh certificate transparency logs,
HackerTarget host search, and RapidDNS) and merges results with deduplication.
DNS history provides full record resolution (A, AAAA, MX, NS, TXT, SOA, CNAME)
via dnspython against public resolvers and Google/Cloudflare DNS-over-HTTPS
endpoints, capturing the current state of a domain's DNS configuration.
Technology fingerprinting uses Wappalyzer's open-source rule database (run
locally, no API call needed) to identify web servers, frameworks, CMS platforms,
JavaScript libraries, analytics tools, and other technology indicators from HTTP
response headers, HTML content, and JavaScript files. IP and ASN intelligence
queries BGPView and RIPEstat (both free, no key required) to map IP addresses to
organizations, autonomous systems, network blocks, and upstream providers. All
results include full provenance (which source provided which finding, when it was
retrieved, and the raw API response for audit purposes). The combination of
subdomains + DNS + technology + IP mapping produces a comprehensive picture of
a target's infrastructure topology from entirely public data.

---

### Phase 2c: Certificate Intelligence

**Level of Effort:** Low
**Time Estimate:** 3-4 hours
**Lines Estimate:** ~300 | **Tests Estimate:** ~12
**Dependencies:** cryptography (optional, stdlib ssl works for basics)
**Blocked by:** Phase 0 (needs socket connectivity)

Phase 2c provides TLS certificate inspection equivalent to running `openssl
s_client -connect` followed by `openssl x509 -text`, but implemented entirely
in Python without requiring the OpenSSL binary. The module connects to a target
host and port, performs the TLS handshake, captures the peer certificate in both
DER and parsed formats, and extracts all relevant fields: subject Common Name,
issuer chain (intermediate and root CAs), Subject Alternative Names (all hostnames
the certificate covers), validity period with expiry alerting (warning if less
than 30 days remain), key type and size (RSA/EC + bit length), serial number and
fingerprint (SHA-256), the negotiated TLS protocol version (1.2 or 1.3) and
cipher suite, and OCSP stapling status for revocation checking. Additional checks
include self-signed detection (issuer equals subject), wildcard SAN detection,
certificate pinning header detection (HPKP/expect-CT), and cross-referencing
against crt.sh certificate transparency logs to verify the certificate was
publicly logged. The implementation uses Python's stdlib ssl and socket modules
for connection and basic parsing, with the optional cryptography library providing
deeper x509 field extraction when available.

---

### Phase 2.5: Vulnerability Intelligence

**Level of Effort:** Medium
**Time Estimate:** 8-10 hours
**Lines Estimate:** ~700 | **Tests Estimate:** ~20
**Dependencies:** None (all HTTP-based API calls)
**Blocked by:** Phase 0 (needs HTTP client)

Phase 2.5 provides comprehensive vulnerability research capabilities by querying
multiple free databases. The National Vulnerability Database (NVD/NIST) API
enables CVE lookup by ID, keyword search across all CVEs, and vendor/product
filtering to find all vulnerabilities affecting specific software. Google's
OSV.dev provides package-level vulnerability data for all major ecosystems
(Python/PyPI, JavaScript/npm, Go, Rust/crates.io, Java/Maven, .NET/NuGet)
enabling dependency scanning without local tools. GitHub Security Advisories
(GHSA) via the GraphQL API provides curated vulnerability information with
affected version ranges and patch versions for open-source packages. CISA's Known
Exploited Vulnerabilities (KEV) catalog provides a continuously updated list of
CVEs confirmed to be actively exploited in the wild — the highest-priority
vulnerabilities that require immediate attention. EPSS (Exploit Prediction
Scoring System) from FIRST.org provides probability scores (0-1) indicating how
likely a CVE is to be exploited in the next 30 days, enabling risk-based
prioritization. ExploitDB integration searches for publicly available exploit
code and proof-of-concept demonstrations. The Android Security Bulletin scraper
parses Google's monthly security patches to identify Android-specific
vulnerabilities by patch level, component, and severity. The combined pipeline
enables queries like "find all actively-exploited Python package vulnerabilities
with public exploits, sorted by exploitation probability" — crossing data from
NVD + OSV + CISA KEV + EPSS + ExploitDB in a single query.

---

### Phase 2.5b: Hash Intelligence ✅ COMPLETE

**Level of Effort:** Low
**Time:** Complete (single agent dispatch + review)
**Lines:** 238 | **Tests:** Syntax verified

Phase 2.5b identifies unknown files by querying their cryptographic hash (MD5,
SHA-1, SHA-256, or SHA-512) against multiple threat intelligence databases
simultaneously. CIRCL's hashlookup service determines whether a file is known
legitimate software (present in the NIST National Software Reference Library) or
unknown (potentially suspicious). Abuse.ch's MalwareBazaar identifies known
malware by family, tags, file type, and first-seen date. Abuse.ch's ThreatFox
correlates hashes with command-and-control infrastructure and active campaigns.
VirusTotal (when an API key is provided) returns scan results from 70+ antivirus
engines. The module auto-detects hash type from string length (32=MD5, 40=SHA-1,
64=SHA-256, 128=SHA-512), validates format, and can also compute hashes from
local files. All services are queried in parallel via asyncio.gather with
independent 5-second timeouts — if one service is slow or down, others still
return. Results are aggregated into a verdict (clean/unknown/suspicious/malicious)
based on the combined signals across all responding services.

---

### Phase 3: Deep Intelligence (Paid APIs)

**Level of Effort:** Low-Medium
**Time Estimate:** 4-6 hours
**Lines Estimate:** ~500 | **Tests Estimate:** ~15
**Dependencies:** shodan, censys, vt-py (pip packages wrapping paid APIs)
**Blocked by:** Phase 2 (context from infrastructure recon makes this more useful)

Phase 3 integrates with premium threat intelligence platforms that provide depth
beyond what free sources offer. Shodan provides banner-level data on every
internet-facing device it has scanned — open ports, service versions, SSL
certificate details, HTTP response headers, and organization/ASN attribution,
enabling queries like "find all Apache 2.4.49 servers in this ASN" or "how many
Linksys routers running firmware 1.0.4 are exposed." Censys provides similar
internet-wide scanning data with stronger certificate and host-service indexing,
supporting queries across the full certificate transparency ecosystem. Hunter.io
provides email address discovery for domains — finding all publicly associated
email addresses, their sources, and verification status. VirusTotal's deep
analysis provides complete domain reputation (70+ engines), IP reputation,
historical DNS/WHOIS data, file behavioral analysis, and relationship graphs
between entities. LeakIX aggregates exposed services and leaked data found across
the internet. All integrations are optional — controlled by API key environment
variables. When keys are absent, the tools gracefully degrade with messages
indicating what additional data would be available with credentials.

---

### Phase 3.5: Threat Intelligence

**Level of Effort:** Medium
**Time Estimate:** 6-8 hours
**Lines Estimate:** ~600 | **Tests Estimate:** ~18
**Dependencies:** None (all HTTP-based, free APIs)
**Blocked by:** Phase 0 (needs HTTP client)

Phase 3.5 provides real-time visibility into active threats by consuming free
threat intelligence feeds from the clearnet. The Abuse.ch ecosystem provides four
complementary feeds: ThreatFox (malware-associated indicators of compromise
including IPs, domains, and URLs linked to specific malware families and
campaigns), URLhaus (actively distributing malware URLs with payload hashes and
hosting information), MalwareBazaar (malware sample metadata including family
classification, YARA signatures, and behavioral tags), and Feodo Tracker (botnet
command-and-control IP addresses for banking trojans). AlienVault OTX provides
community-created "pulses" — curated collections of indicators tagged by campaign,
malware family, or threat actor. RansomWatch aggregates victim postings from
ransomware gang leak sites (scraped from Tor by the community and published as
JSON on GitHub), enabling tracking of which organizations are being extorted and
by which groups. Have I Been Pwned provides breach notification — alerting when
email addresses or domains appear in newly disclosed data breaches. The malware
sample lookup feature queries MalwareBazaar by CVE tag to find samples exploiting
specific vulnerabilities, returning the top 10 sample URLs with hashes and
first-seen dates (displayed only, never auto-downloaded — GhostMCP finds threats
but never executes them).

---

### Phase 4: Domain Reputation

**Level of Effort:** Medium
**Time Estimate:** 8-10 hours
**Lines Estimate:** ~700 | **Tests Estimate:** ~20
**Dependencies:** python-whois
**Blocked by:** Phase 0 (needs HTTP client + DNS)

Phase 4 answers the question "is this domain trustworthy?" by aggregating
multiple independent signals into a quantified risk score. WHOIS age detection
identifies newly registered domains (a strong indicator of phishing and malware
infrastructure — legitimate businesses rarely operate from domains created days
ago). URLhaus checks whether the domain has been reported distributing malware.
PhishTank and OpenPhish check against community-maintained databases of confirmed
phishing URLs. AbuseIPDB aggregates community abuse reports for the domain's
hosting IP, indicating spam, scanning, or malware distribution activity.
URLScan.io provides rich domain analysis including screenshots, DOM content, HTTP
transactions, and technology detection. VirusTotal provides reputation from 70+
security engines. ThreatCrowd maps relationships between the domain and other
entities (associated IPs, email addresses, subdomains, and related domains). All
signals are combined into a 0-100 risk score with clearly defined thresholds:
0-10 clean, 11-30 low risk, 31-50 suspicious, 51+ high risk/likely malicious.
Each contributing signal adds documented points to the score, and every finding
includes full provenance (which service reported it, when it was first seen, when
last confirmed, and the specific reason for the flag). Security research dorking
is also included in this phase — the ability to search StackExchange, GitHub,
PacketStorm, and other knowledge bases for techniques, procedures, and analysis
methodologies (e.g., "how to analyze PyArmor protected files"). MITRE ATT&CK
technique lookup and GTFOBins/LOLBAS reference provide standardized attack
technique documentation accessible from the CLI.

---

### Phase 4b: Email Verification

**Level of Effort:** Medium
**Time Estimate:** 6-8 hours
**Lines Estimate:** ~400 | **Tests Estimate:** ~15
**Dependencies:** dnspython
**Blocked by:** Phase 2 (needs DNS resolution for MX records)

Phase 4b verifies whether an email address exists on a domain's mail server
without sending actual email, using the same SMTP protocol that mail servers use
to communicate with each other. The process begins with MX record lookup via
dnspython to identify the domain's mail servers, then establishes a direct TCP
connection to port 25 and reads the SMTP banner (which often reveals the mail
server software and version). The VRFY command is attempted first (directly asks
the server if a user exists), though many servers disable this for security. The
more reliable approach uses RCPT TO probing — issuing a MAIL FROM followed by
RCPT TO for the target address and checking whether the server responds with 250
(exists) or 550 (doesn't exist). Catch-all detection tests with a random
nonexistent address — if the server accepts everything, RCPT TO results are
unreliable. Additionally, this phase checks the domain's email authentication
posture by querying DNS for SPF records (TXT), DKIM selectors
(selector._domainkey), and DMARC policy (_dmarc TXT), providing a picture of how
well the domain protects against spoofing. Disposable email detection checks
against a maintained list of known throwaway email providers. The module respects
server rate limits (421/452 responses), never sends actual email, and adjusts
probe aggressiveness based on paranoia level — midnight mode performs a single
RCPT TO through Tor and immediately disconnects.

---

### Phase 5: Identity & Code Intelligence

**Level of Effort:** High
**Time Estimate:** 12-16 hours
**Lines Estimate:** ~1000 | **Tests Estimate:** ~30
**Dependencies:** sherlock (or maigret), gitleaks/TruffleHog, Pillow, PyPDF2
**Blocked by:** Phase 0 + Phase 2 (needs HTTP + some domain context)

Phase 5 addresses identity correlation, code repository intelligence, and
document metadata extraction — three capabilities that professional OSINT
practitioners consider essential for building complete target profiles. Username
correlation searches a persona or handle across hundreds of platforms (social
media, developer sites, forums, gaming, dating, etc.) using tools like sherlock
or maigret, building a cross-platform presence map that reveals which services a
person uses under a given alias. Code repository mining searches GitHub, GitLab,
and Bitbucket for organization names, internal hostnames, API keys, tokens, cloud
bucket names, CI/CD configurations, and accidentally committed secrets using
established tools (TruffleHog for regex+entropy secret detection, gitleaks for
pattern-based scanning, GitHub Search API for targeted queries). Document metadata
extraction downloads publicly accessible files (PDF, Word, Excel, PowerPoint,
images) and extracts hidden metadata — author names, software versions used to
create the document, internal file paths (revealing internal server names and
directory structures), printer names, revision history, GPS coordinates from
image EXIF data, and embedded timestamps. This metadata frequently reveals
organizational intelligence that the document's actual content was never intended
to disclose. Leaked credential searching queries Have I Been Pwned and similar
aggregators to determine which email addresses associated with a target domain
have appeared in known data breaches, providing both a risk assessment and
potential credential material for authorized penetration testing.

---

### Phase 5b: Change Detection & Monitoring

**Level of Effort:** Medium
**Time Estimate:** 8-10 hours
**Lines Estimate:** ~500 | **Tests Estimate:** ~15
**Dependencies:** SQLite (for historical state), schedule/cron
**Blocked by:** Phase 2 (needs subdomain/cert/DNS modules to monitor)

Phase 5b transforms GhostMCP from a point-in-time scanner into a continuous
monitoring system that detects changes over time. New subdomain detection
periodically re-runs subdomain enumeration and diffs against previously known
results — a new subdomain appearing on a target domain often indicates new
services being deployed, development/staging environments being exposed, or
infrastructure changes that create attack surface. Certificate change monitoring
watches for new certificates being issued for a domain via certificate
transparency logs, alerting when unexpected certificates appear (which could
indicate unauthorized issuance or subdomain takeover). DNS record change
detection periodically resolves all record types and alerts on modifications —
MX changes might indicate email compromise, NS changes could signal domain
hijacking, and new A records reveal infrastructure expansion. Repository mention
monitoring polls GitHub search for target domain names, internal terminology, or
employee identifiers appearing in public code — often catching accidental commits
of credentials or internal documentation. All historical state is stored in a
local SQLite database with timestamps, enabling trend analysis and timeline
reconstruction. Alerting is configurable — console output, file logging, or
webhook notifications for integration with external systems.

---

### Phase 5c: People Intelligence

**Level of Effort:** Medium-High
**Time Estimate:** 10-14 hours
**Lines Estimate:** ~700 | **Tests Estimate:** ~20
**Dependencies:** phonenumbers (Google libphonenumber port)
**Blocked by:** Phase 0 (needs HTTP client)

Phase 5c provides person-centric OSINT capabilities — the ability to pivot from
a phone number, name, email address, or physical address to associated
information across public data sources. The core dependency is Google's
libphonenumber library (via the phonenumbers Python package), which provides
phone number validation, carrier identification, number type classification
(mobile/fixed-line/VoIP/toll-free), and geographic region inference — all from
local computation without any API calls. Reverse phone lookup queries public
directories and community databases to find names associated with phone numbers.
Name search aggregates results from public records, social media profiles, and
business filings to find addresses, phone numbers, and online accounts associated
with a person's name (with geographic filtering to reduce false positives).
Address search identifies current and historical residents of a physical location
using public property records and directory services. The module supports global
lookups with region-specific sources (US, UK, Australia, EU) while documenting
GDPR and local privacy law constraints — EU results are inherently limited by
regulation, and the tool clearly communicates when data is unavailable due to
legal restrictions rather than technical limitations. All results carry confidence
scores (single source = low confidence, multiple independent sources = high
confidence) and never present unverified associations as confirmed facts.

---

### Phase 6: Wireless Intelligence

**Level of Effort:** Low-Medium
**Time Estimate:** 4-6 hours
**Lines Estimate:** ~400 | **Tests Estimate:** ~12
**Dependencies:** None (all HTTP to WiGLE API)
**Blocked by:** Phase 0 (needs HTTP client)

Phase 6 leverages the global wardriving community's data (primarily WiGLE.net,
which indexes over 1 billion wireless networks) to provide location intelligence
for WiFi and Bluetooth devices. BSSID lookup takes a WiFi access point's MAC
address and returns every location where wardrivers have observed it — revealing
whether a device is stationary (always seen at one location) or mobile (seen in
multiple cities over time). SSID search finds all access points broadcasting a
specific network name, useful for detecting rogue access points impersonating
corporate networks or tracking how widely a particular network name is deployed.
Bluetooth device search provides similar capabilities for Bluetooth/BLE devices,
which many personal electronics (watches, earbuds, fitness trackers) broadcast
continuously. GPS bounding box search answers "what wireless networks exist in
this physical area?" — useful for site surveys and understanding the RF
environment of a location. The IEEE OUI database provides manufacturer
identification from the first three octets of any MAC address, implemented as
an offline lookup requiring no API calls. The Mylnikov API serves as a backup
geolocation service for BSSID-to-coordinates mapping when WiGLE is unavailable.
A free WiGLE account provides API access; the core OUI lookup works entirely
offline.

---

### Phase 6b: Cellular Intelligence

**Level of Effort:** Low-Medium
**Time Estimate:** 4-6 hours
**Lines Estimate:** ~350 | **Tests Estimate:** ~12
**Dependencies:** mccmnc, phonenumbers
**Blocked by:** Phase 0 (needs HTTP client for tower APIs)

Phase 6b provides cellular network intelligence by decoding mobile identifiers
and locating cellular infrastructure. IMSI (International Mobile Subscriber
Identity) analysis decodes the MCC (Mobile Country Code) and MNC (Mobile Network
Code) prefix to identify the subscriber's home country and carrier, using an
offline database (the mccmnc Python package) that requires no API calls. IMEI
(International Mobile Equipment Identity) analysis validates the 15-digit
equipment identifier using Luhn checksum verification and maps the TAC (Type
Allocation Code — first 8 digits) to a specific device manufacturer and model
using an offline TAC database. Cell tower geolocation uses OpenCelliD (community-
contributed tower database) and Google's Geolocation API to convert cell tower
identifiers (MCC + MNC + LAC + Cell ID) into GPS coordinates, and area search
finds all known towers within a radius of specified coordinates. HLR (Home
Location Register) lookup — which determines if a phone number is currently
active, which network it's on, whether it's roaming, and if it's been ported —
is available as an optional paid integration through providers like Telnyx, Vonage,
or Twilio, controlled by environment variables. The module explicitly documents
legal boundaries: MCC/MNC decoding, IMEI validation, and OpenCelliD queries are
legal public data operations; HLR lookup is legal with legitimate purpose; SS7
interception and IMSI catching are illegal without law enforcement authority and
will never be implemented.

---

### Phase 7: Graph Mapping & Geolocation

**Level of Effort:** High
**Time Estimate:** 12-16 hours
**Lines Estimate:** ~800 | **Tests Estimate:** ~20
**Dependencies:** networkx, Pillow (for EXIF)
**Blocked by:** Phases 2-6 (needs data from prior phases to build graph)

Phase 7 synthesizes findings from all prior phases into a unified entity
relationship graph and enriches results with physical-world context. The entity
graph connects all discovered artifacts — domains, subdomains, IP addresses, ASN
numbers, certificates, email addresses, MX/NS records, technologies, and people —
into a navigable network using NetworkX. Relationship types include resolves_to,
hosted_by, issued_for, administers, uses_technology, associated_with, and
belongs_to. Graph traversal algorithms identify pivot paths (how to get from one
entity to another through relationships), hub nodes (highly connected entities
that represent key infrastructure), and cluster detection (groups of related
entities that likely belong to the same organization). Export formats include
GEXF (for Gephi visualization), GraphML, JSON, and DOT (for Graphviz rendering).
Geolocation enrichment maps entities to physical locations using IP geolocation
(ipinfo.io, MaxMind GeoLite2), EXIF GPS extraction from images (using Pillow's
EXIF parser), timezone inference from IP location and language artifacts, and
correlation of wireless sightings (Phase 6) with physical addresses. The
combination produces a comprehensive view that connects digital infrastructure
to physical geography.

---

### Phase 8: Cloud Infrastructure Enumeration

**Level of Effort:** Medium-High
**Time Estimate:** 10-12 hours
**Lines Estimate:** ~600 | **Tests Estimate:** ~18
**Dependencies:** None (DNS + HTTP probing)
**Blocked by:** Phase 2 (needs DNS resolution)

Phase 8 discovers exposed cloud assets across major providers without requiring
authenticated access to any cloud account. S3 bucket enumeration uses DNS-based
probing (checking if {target}-backup.s3.amazonaws.com resolves) combined with
HTTP permission checks (does the bucket allow public listing or reading?). Azure
blob storage discovery follows similar DNS patterns
({target}.blob.core.windows.net) with accessibility probing. GCP storage uses the
storage.googleapis.com pattern. Beyond storage, cloud service fingerprinting
identifies targets hosted on cloud platforms by examining DNS CNAME records
(pointing to cloudfront.net, azurewebsites.net, herokuapp.com, etc.) and HTTP
response headers (x-amz-*, x-ms-*, x-goog-*). Misconfiguration detection probes
discovered resources for common security issues: publicly readable buckets,
directory listing enabled, exposed backup files, and default credentials on cloud
management interfaces. The module does NOT perform brute-force enumeration of
bucket names (which would be noisy and potentially illegal) — instead it derives
candidate names from discovered subdomains, organization names, project names
found in code repositories, and naming patterns observed in DNS records, then
checks only those specific candidates.

---

### Phase 9+: ForensicsMCP Integration (Future Separate Project)

**Level of Effort:** Very High
**Time Estimate:** 40+ hours (separate project)
**Lines Estimate:** ~3000+
**Dependencies:** Virtualization (KVM/QEMU), YARA, Volatility, network capture
**Blocked by:** GhostMCP Phases 0-3.5 (needs threat finding capability first)

ForensicsMCP is envisioned as a separate MCP server project that receives
samples and URLs discovered by GhostMCP and analyzes them in isolated sandbox
environments. The sandbox cluster provides disposable virtual machines for each
major operating system — Windows 10/11 for analyzing Windows malware, PE
executables, Office macros, and PowerShell payloads; Linux (Ubuntu/RHEL) for
server-side malware, ELF binaries, and rootkits; macOS for Mac-specific threats;
and emulated mobile environments for iOS and Android APK analysis. Each
detonation resets the VM from a clean snapshot, captures all file system changes,
registry modifications (Windows), process creation trees, network traffic (full
PCAP), DNS queries, and API calls. YARA rule matching identifies known malware
signatures. Volatility memory analysis extracts artifacts from RAM dumps. MITRE
ATT&CK mapping automatically classifies observed behaviors into standardized
technique categories. Results are fed back to Unimind's knowledge store with
appropriate classification levels (level 3+ for malware analysis results),
creating a feedback loop where GhostMCP discovers threats, ForensicsMCP
understands them, and Unimind remembers the intelligence for future sessions.
The key architectural principle is separation: GhostMCP NEVER executes samples
(it only finds and lists them), ForensicsMCP handles all execution in isolated
environments, and neither touches the analyst's workstation directly.

---

## Implementation Strategy

**Recommended build order (maximizing value per sprint):**

1. ✅ Phase 0 — Foundation (DONE)
2. ✅ Phase 2.5b — Hash Intel (DONE)
3. Phase 1 — Dorking + MCP (unlocks AI workflow integration)
4. Phase 2c — Cert Intel (quick win, high daily utility)
5. Phase 2.5 — Vuln Intel (high value for security work)
6. Phase 2 — Infrastructure Recon (comprehensive target mapping)
7. Phase 4 — Domain Reputation (answers "is this safe?")
8. Phase 3.5 — Threat Intel (real-time awareness)
9. Phase 4b — Email Verification (targeted probing)
10. Phase 6 + 6b — Wireless + Cellular (specialized intelligence)
11. Phase 5 — Identity + Code (deep OSINT)
12. Phase 3 — Deep Intel (when free sources aren't enough)
13. Phase 5b — Monitoring (continuous ops)
14. Phase 5c — People Intel (person-centric pivoting)
15. Phase 7 — Graph (synthesis of everything)
16. Phase 8 — Cloud (modern infrastructure)
17. Phase 9+ — ForensicsMCP (separate project)

**Agent delegation strategy:**
- Each phase can be built by a single agent dispatch (~4-16 hrs)
- Review + testing adds ~2-4 hrs per phase
- Phases 1, 2c, 6, 6b are "quick wins" (low LOE, high value)
- Phases 5, 7, 9+ are "deep work" (high LOE, transformative value)
