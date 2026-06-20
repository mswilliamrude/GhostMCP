# GhostMCP Tier 1 Expanded: Full Passive Intelligence from Headers, DNS, and TLS

**Date:** 2026-06-19
**Purpose:** Document ALL intelligence obtainable from passive HTTP, DNS, and TLS interactions — no attack payloads, no authorization required.

---

## 1. ghost_headers — Complete HTTP Response Intelligence

### 1.1 Security Headers (Grade A+ through F)

| Header | What It Controls | Missing = |
|---|---|---|
| `Strict-Transport-Security` | HTTPS enforcement + preload | MitM downgrade attacks |
| `Content-Security-Policy` | Script/style/media sources | XSS succeeds |
| `X-Frame-Options` | Iframe embedding policy | Clickjacking |
| `X-Content-Type-Options` | MIME sniffing prevention | Drive-by downloads |
| `Referrer-Policy` | Referrer leakage control | URL information disclosure |
| `Permissions-Policy` | Browser feature access (camera, mic, geo, payment) | Feature abuse |
| `Cross-Origin-Resource-Policy` | Cross-origin resource loading | Data leakage |
| `Cross-Origin-Opener-Policy` | Browsing context isolation | Spectre attacks |
| `Cross-Origin-Embedder-Policy` | Resource embedding | Side-channel attacks |

### 1.2 Server Fingerprinting (Information Disclosure)

A single HTTP response often reveals the entire technology stack:

| Header | Example Value | Intelligence |
|---|---|---|
| `Server` | `Apache/2.4.52 (Ubuntu)` | Web server + OS version → CVE mapping |
| `X-Powered-By` | `PHP/8.2.1` | Backend language + version → CVE mapping |
| `X-AspNet-Version` | `4.0.30319` | .NET framework version |
| `X-Runtime` | `0.042135` | Ruby/Python (reveals language by presence) |
| `X-Generator` | `WordPress 6.4.2` | CMS + exact version → CVE mapping |
| `X-Drupal-Cache` | `HIT` | Confirms Drupal |
| `X-Shopify-Stage` | `production` | Confirms Shopify |
| `X-Varnish` | `12345678` | Varnish caching proxy |
| `X-Cache` | `HIT from cloudfront` | CDN provider + cache status |
| `CF-Ray` | `8a1b2c3d4e5f-DFW` | Cloudflare + datacenter (DFW = Dallas) |
| `X-Amz-Cf-Id` | `...` | AWS CloudFront |
| `X-Azure-Ref` | `...` | Azure Front Door |
| `X-Fastly-Request-ID` | `...` | Fastly CDN |
| `X-Served-By` | `cache-dfw18640` | CDN/server node identifier |
| `Via` | `1.1 vegur` | Proxy chain (Heroku uses vegur) |
| `X-Request-ID` | `uuid-here` | Internal request tracing (microservices) |
| `X-Correlation-ID` | `uuid-here` | Distributed system correlation |
| `X-Backend-Server` | `app-server-03` | Internal server name leak |

### 1.3 Cookie Analysis

| Attribute | Check | Security Implication |
|---|---|---|
| `Secure` flag | Present on all cookies? | Without: cookies sent over HTTP (interceptable) |
| `HttpOnly` flag | Present on session cookies? | Without: JavaScript can steal sessions (XSS → session hijack) |
| `SameSite` | Strict / Lax / None | None + no Secure = CSRF vulnerability |
| `__Secure-` prefix | Cookie name prefix | Modern secure cookie pattern |
| `__Host-` prefix | Strictest cookie pattern | Domain-locked, path=/, Secure, no domain attribute |
| Cookie names | JSESSIONID, PHPSESSID, ASP.NET_SessionId, _session_id, connect.sid | Technology fingerprinting from session cookie name |
| Cookie paths | `/api/`, `/admin/` | Reveals application routing structure |
| Expiration | Session vs persistent | Data retention policy indicator |

### 1.4 CORS Policy Analysis

| Header | Dangerous Value | Risk |
|---|---|---|
| `Access-Control-Allow-Origin` | `*` (wildcard) | Any origin can read responses |
| `Access-Control-Allow-Credentials` | `true` with wildcard origin | Credential theft across origins |
| `Access-Control-Allow-Methods` | `PUT, DELETE, PATCH` exposed | Unexpected mutation methods available |
| `Access-Control-Allow-Headers` | `Authorization, X-API-Key` exposed | API auth headers cross-origin accessible |
| `Access-Control-Max-Age` | Very large value | Stale CORS policy cached long-term |
| Reflected origin | Echoes `Origin` header back | Same as wildcard but bypasses browser protections |

### 1.5 Caching Analysis

| Header | Issue | Impact |
|---|---|---|
| `Cache-Control: public` on auth pages | Sensitive responses cached publicly | Credential leakage |
| Missing `no-store` on API responses | Responses cached by CDN/proxy | Stale/leaked data |
| `ETag` with predictable value | inode-based ETags on Apache | Server information disclosure |
| `Age` header | Time since cached | Reveals caching infrastructure timing |
| `Vary` header (or lack thereof) | What triggers different cache versions | Cache poisoning risk |

### 1.6 Rate Limiting Discovery

| Header | Intelligence |
|---|---|
| `X-RateLimit-Limit` | Maximum requests per window |
| `X-RateLimit-Remaining` | Current capacity |
| `X-RateLimit-Reset` | Window reset time |
| `Retry-After` | When to retry (seconds or HTTP-date) |
| `RateLimit-Policy` | Draft standard rate limit policy |

These headers reveal the API's capacity — useful for understanding operational limits and planning automation.

---

## 2. ghost_dns — Full Zone Intelligence via DoH

### 2.1 DNS over HTTPS (DoH) — Zero Dependency Implementation

Instead of requiring `dnspython`, use Cloudflare/Google DoH JSON APIs:

```
GET https://cloudflare-dns.com/dns-query?name={domain}&type={type}
Accept: application/dns-json

Response:
{
  "Status": 0,           ← NOERROR
  "AD": true,            ← DNSSEC validated
  "Answer": [
    {"name": "...", "type": 16, "TTL": 3600, "data": "v=spf1 ..."}
  ]
}
```

**Advantages:**
- Works from any container (just HTTPS, no UDP/TCP DNS)
- Bypasses corporate DNS filtering/monitoring
- Encrypted — network observers can't see queries
- Returns DNSSEC validation status (`AD` flag)
- No pip dependency needed — just httpx
- Cloudflare is fast (~10ms) and allows 10K queries/day free

### 2.2 All DNS Record Types

| Type | What It Reveals | Ghost Intelligence Use |
|---|---|---|
| **A** | IPv4 address(es) | Hosting provider identification, multi-server detection |
| **AAAA** | IPv6 addresses | IPv6 support, sometimes reveals origin behind CDN |
| **CNAME** | Canonical name alias | CDN/SaaS provider, subdomain takeover targets |
| **MX** | Mail servers + priority | Email infrastructure (Google Workspace, M365, on-prem) |
| **NS** | Authoritative nameservers | DNS provider (Cloudflare, Route53, GoDaddy) |
| **TXT** | SPF, DKIM, DMARC, verification tokens | Email security + service discovery (see below) |
| **SOA** | Zone authority, admin email, serial, timers | Zone freshness, admin contact disclosure |
| **SRV** | Service discovery records | Internal services exposed (_sip, _xmpp, _ldap, _kerberos) |
| **CAA** | Certificate Authority Authorization | Which CAs are allowed to issue certs |
| **PTR** | Reverse DNS (IP → hostname) | Hostname verification, infrastructure mapping |
| **NAPTR** | Naming Authority Pointer | VoIP/SIP infrastructure |
| **TLSA** | DANE TLS Authentication | Certificate pinning via DNS |
| **HTTPS** / **SVCB** | Service binding (RFC 9460) | ECH support, ALPN, alternative ports, priority |
| **DNSKEY** / **DS** | DNSSEC keys and delegation signer | Zone signing verification |
| **NSEC** / **NSEC3** | Next Secure record (DNSSEC) | Zone walking for record enumeration |
| **LOC** | Geographic location | Physical server coordinates (rare but useful when present) |

### 2.3 TXT Record Intelligence — Service Discovery

TXT records are a goldmine. Organizations leave verification tokens that reveal which services they use:

| TXT Pattern | Service Revealed |
|---|---|
| `v=spf1 include:_spf.google.com` | Google Workspace |
| `v=spf1 include:spf.protection.outlook.com` | Microsoft 365 |
| `v=spf1 include:amazonses.com` | AWS SES (sending email via AWS) |
| `v=spf1 include:sendgrid.net` | SendGrid / Twilio |
| `v=spf1 include:mailgun.org` | Mailgun |
| `google-site-verification=...` | Google Search Console |
| `MS=ms12345678` | Microsoft 365 domain verification |
| `docusign=...` | DocuSign |
| `atlassian-domain-verification=...` | Atlassian (Jira, Confluence) |
| `_github-pages-challenge=...` | GitHub Pages |
| `stripe-verification=...` | Stripe payments |
| `hubspot-developer-verification=...` | HubSpot |
| `adobe-idp-site-verification=...` | Adobe |
| `apple-domain-verification=...` | Apple |
| `zoom-domain-verification=...` | Zoom |
| `protonmail-verification=...` | ProtonMail |
| `slack-domain-verification=...` | Slack |
| `_globalsign-domain-verification=...` | GlobalSign CA |

### 2.4 Recursive Zone Discovery

**The key insight:** You don't just check the apex domain. You recursively discover infrastructure by following references in DNS records:

```
Start: example.com
  │
  ├─ SPF includes: _spf.google.com, mail.example.com, marketing.example.com
  │     └─ Discovers: marketing.example.com (subdomain)
  │
  ├─ MX records: mx1.example.com, mx2.example.com, alt.protonmail.ch
  │     └─ Discovers: mx1, mx2 subdomains + ProtonMail usage
  │
  ├─ NS records: ns1.cloudflare.com → Cloudflare is DNS provider
  │
  ├─ CNAME records found via CT/subdomain enum:
  │     ├─ app.example.com → app.herokuapp.com (Heroku)
  │     ├─ docs.example.com → example-docs.readthedocs.io (ReadTheDocs)
  │     ├─ status.example.com → stats.uptimerobot.com (UptimeRobot)
  │     └─ mail.example.com → ghs.googlehosted.com (Google Workspace)
  │
  ├─ Certificate Transparency (crt.sh): all certs ever issued
  │     ├─ *.example.com (wildcard)
  │     ├─ api.example.com
  │     ├─ staging.example.com
  │     ├─ dev.example.com
  │     └─ internal.example.com (interesting!)
  │
  ├─ SRV records:
  │     ├─ _sip._tcp.example.com → VoIP infrastructure
  │     ├─ _xmpp-server._tcp.example.com → XMPP/Jabber
  │     └─ _autodiscover._tcp.example.com → Exchange/M365
  │
  └─ Follow discovered subdomains recursively:
        ├─ api.example.com → A record → 10.0.10.50 (internal? VPN?)
        ├─ staging.example.com → A record → same IP as prod? different?
        └─ internal.example.com → NXDOMAIN (decommissioned but cert exists)
```

### 2.5 Dangling CNAME / Subdomain Takeover Detection

When a CNAME points to a service that no longer exists, anyone can claim that service and serve content on the subdomain:

| CNAME Target | Service | Takeover Indicator |
|---|---|---|
| `*.herokuapp.com` | Heroku | "No such app" page / NXDOMAIN |
| `*.s3.amazonaws.com` | AWS S3 | "NoSuchBucket" XML |
| `*.azurewebsites.net` | Azure App Service | Azure 404 page |
| `*.cloudfront.net` | AWS CloudFront | "Bad Request" CloudFront error |
| `*.github.io` | GitHub Pages | GitHub 404 page |
| `*.ghost.io` | Ghost CMS | Ghost 404 |
| `*.shopify.com` | Shopify | "Sorry, this shop is unavailable" |
| `*.wordpress.com` | WordPress.com | WP 404 |
| `*.pantheon.io` | Pantheon | 404 |
| `*.surge.sh` | Surge | "project not found" |
| `*.netlify.app` | Netlify | "Not Found" Netlify page |
| `*.vercel.app` | Vercel | Vercel 404 |
| `*.fly.dev` | Fly.io | Connection refused |
| `*.render.com` | Render | Render 404 |

**Detection method:**
1. Resolve CNAME → get target
2. Resolve target A record → check for NXDOMAIN or known error pages
3. If NXDOMAIN or known takeover fingerprint → flag as HIGH risk

### 2.6 Zone Walking (DNSSEC NSEC/NSEC3)

If a zone uses DNSSEC with NSEC (not NSEC3), you can enumerate ALL records without brute force:

```
Query: example.com NSEC
Response: example.com NSEC admin.example.com A NS SOA MX TXT RRSIG NSEC DNSKEY
                         ↑ next name in zone

Query: admin.example.com NSEC  
Response: admin.example.com NSEC api.example.com A RRSIG NSEC
                                 ↑ next name

... continue until wrapping back to apex
```

NSEC3 uses hashed names to prevent this, but many zones still use NSEC.

---

## 3. ghost_cert — Complete TLS Intelligence

### 3.1 mTLS (Mutual TLS) Detection

**Yes, we can detect if a server requires client certificates — passively.**

During TLS handshake, if the server requires client authentication, it sends a `CertificateRequest` message (TLS 1.2) or `certificate_request` extension in `EncryptedExtensions` (TLS 1.3). The behaviors we can observe:

| Server Behavior | What It Means | How We Detect It |
|---|---|---|
| **Connection succeeds normally** | No client cert required | Standard — most servers |
| **Server sends CertificateRequest** | mTLS optional or required | Our TLS library receives the request |
| **Connection terminates after ClientHello** | Likely mTLS hard-required (no cert = reject) | `ssl.SSLError` or connection reset |
| **HTTP 403/401 after TLS succeeds** | mTLS at application layer (optional at TLS) | HTTP response code after TLS handshake |
| **TLS alert: `handshake_failure` (40)** | Client cert required but not provided | Alert code analysis |
| **TLS alert: `certificate_required` (116)** | TLS 1.3 explicit cert required | Alert code analysis |
| **TLS renegotiation triggered** | Path-specific mTLS (TLS 1.2 renegotiation) | Detect renegotiation after HTTP request |

**What mTLS detection reveals:**
- This endpoint requires authentication at the transport layer (not just HTTP auth)
- Zero-trust architecture indicator
- Service mesh detection (Istio, Linkerd use mTLS between services)
- Internal API vs public API distinction
- Certificate Authority names from `CertificateRequest` → which CA issued client certs (internal PKI?)

**CertificateRequest message contains:**
- `certificate_types` — which key types are acceptable (RSA, ECDSA, Ed25519)
- `signature_algorithms` — acceptable signature schemes
- `certificate_authorities` — Distinguished Names of acceptable CAs (reveals internal PKI!)

### 3.2 JARM Fingerprinting

JARM sends 10 specially crafted TLS ClientHello packets and hashes the server's responses:

```
Probe 1: TLS 1.2, all ciphers, all extensions
Probe 2: TLS 1.2, all ciphers, no extensions
Probe 3: TLS 1.2, only forward secrecy ciphers
Probe 4: TLS 1.2, only non-FS ciphers
Probe 5: TLS 1.2, exotic ciphers
...
Probe 10: TLS 1.1, specific cipher set

Result: 62-character fingerprint (5 chars per probe × 10 probes + 2 char hash suffix)
```

**Known JARM fingerprints:**
| JARM | Server |
|---|---|
| `27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d` | Cobalt Strike C2 (default) |
| `07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1` | Metasploit Framework |
| `29d29d00029d29d21c41d41d00041d741011a7be03d7498e0df1581f08b4827` | Apache httpd |
| `27d3ed3ed0003ed00042d43d00041d6183ff1bfae51ebd88d70474e88c62fd3` | nginx |
| `2ad2ad0002ad2ad00041d41d000000e1c90dc8c4dfa1a34f10ccc5cc7e7d29c` | IIS |
| Various | Cloudflare, Akamai, AWS ALB, Google Front End |

This is pure gold for threat hunting — known C2 infrastructure has distinctive JARM fingerprints.

### 3.3 Certificate Transparency Deep Dive

Beyond basic CT lookup (which `ghost_subdomains` already does via crt.sh), we can extract:

| CT Data | Intelligence |
|---|---|
| **All SANs across all certs** | Complete subdomain inventory (historical + current) |
| **Issuance dates** | When infrastructure was deployed |
| **CA diversity** | Single CA = automated, multiple = organizational complexity |
| **Wildcard usage** | `*.example.com` = can't enumerate from CT alone |
| **Pre-certificates vs final** | Pre-cert without final = issuance was aborted |
| **Cert validity periods** | 90-day = Let's Encrypt/automated, 1-year = commercial CA |
| **Key reuse** | Same public key across certs = poor rotation practice |
| **Organization field** | Legal entity name, address, jurisdiction (EV/OV certs) |

### 3.4 Additional Passive TLS Intelligence

| Check | What We Learn | Method |
|---|---|---|
| **ALPN negotiation** | HTTP/2, HTTP/3, ACME-TLS/1 support | Part of TLS handshake |
| **Server Name Indication (SNI)** | Virtual hosting detection (multiple sites on one IP) | Try different SNI values |
| **OCSP stapling** | Certificate revocation response included | Check for stapled OCSP |
| **Extended Master Secret** | Downgrade attack protection | TLS extension check |
| **Encrypt-then-MAC** | Better CBC mode security | TLS extension check |
| **Session resumption** | Session tickets / session IDs | Performance vs PFS tradeoff |
| **0-RTT support (TLS 1.3)** | Early data acceptance | Replay attack surface |
| **Supported groups** | Which elliptic curves/DH groups | Crypto strength indicator |
| **Signature algorithms** | RSA-PSS, ECDSA, Ed25519 | Modern vs legacy crypto |
| **Post-handshake auth** | TLS 1.3 post-handshake client cert | Advanced mTLS pattern |
| **Encrypted Client Hello (ECH)** | Privacy-preserving SNI (via HTTPS DNS record) | Detects modern privacy setup |
| **Key share** | Which group was used for key exchange | Crypto strength actually negotiated |

---

## 4. Recursive Infrastructure Mapping — The Big Picture

### 4.1 The Discovery Chain

Starting from a single domain, we can passively map the entire infrastructure:

```
INPUT: target.com

PHASE 1: DNS Records (ghost_dns)
├─ A/AAAA → IP addresses → geolocation, ASN, hosting provider
├─ MX → mail infrastructure → email provider identification
├─ NS → DNS provider → Cloudflare, Route53, GoDaddy, etc.
├─ TXT → SPF/DMARC/DKIM + verification tokens → service inventory
├─ SRV → service discovery → internal services exposed
├─ CAA → allowed CAs → cert issuance policy
└─ SOA → admin contact → potential OSINT lead

PHASE 2: Certificate Transparency (ghost_subdomains, enhanced)
├─ crt.sh query → all subdomains ever certified
├─ Historical certs → infrastructure timeline
├─ Wildcard detection → coverage gaps
└─ Pre-certs without finals → abandoned deployments

PHASE 3: Subdomain Resolution (ghost_dns recursive)
├─ For each discovered subdomain:
│   ├─ A record → IP → same server? different? cloud?
│   ├─ CNAME → third-party service (Heroku, S3, Netlify...)
│   │   └─ Takeover check → is the target service alive?
│   └─ TXT on subdomain → additional verification tokens
├─ IP clustering → which subdomains share infrastructure
└─ CNAME graph → dependency map on third-party services

PHASE 4: TLS Analysis (ghost_cert per host)
├─ Certificate SANs → cross-reference with DNS findings
├─ JARM fingerprint → server software identification
├─ mTLS detection → zero-trust / internal API identification
├─ ALPN → protocol support (HTTP/2, gRPC)
└─ Cipher/protocol → security posture

PHASE 5: Header Analysis (ghost_headers per site)
├─ Technology fingerprinting → server, language, CMS, CDN
├─ Security posture → header grades
├─ Cookie analysis → session management technology
└─ CORS policy → API accessibility

OUTPUT: Complete infrastructure map
├─ All subdomains (discovered via DNS + CT + SPF + MX + SRV)
├─ IP address inventory (with geolocation + ASN + hosting)
├─ Technology stack per host (from headers + JARM + cookies)
├─ Third-party dependencies (from CNAMEs + TXT tokens + SPF includes)
├─ Email infrastructure (from MX + SPF + DKIM + DMARC)
├─ Security posture grades (headers + TLS + DNS per host)
├─ Takeover risks (dangling CNAMEs)
├─ mTLS/internal API endpoints
└─ Historical timeline (from CT logs + cert validity dates)
```

### 4.2 Data Correlation

The power is in cross-referencing:

| Source A | Source B | Correlation |
|---|---|---|
| CT log shows `internal.example.com` | DNS returns NXDOMAIN | Decommissioned but cert still valid — stale infrastructure |
| CNAME → `app.herokuapp.com` | Heroku returns 404 | **Subdomain takeover** — HIGH risk |
| SPF includes `sendgrid.net` | TXT has `_dmarc p=none` | Organization sends email via SendGrid but has NO enforcement — spoofable |
| Header `Server: Apache/2.4.41` | CVE-2021-44790 affects < 2.4.52 | Known vulnerability in running version |
| JARM matches Cobalt Strike | IP in threat feeds | Confirmed C2 infrastructure |
| mTLS required on `api.example.com` | No mTLS on `staging-api.example.com` | Staging API missing auth — potential bypass |
| Multiple subdomains resolve to same IP | Only one has HSTS | Inconsistent security policy across hosts |

### 4.3 What GhostMCP Already Has vs What's New

| Capability | Already Built | New for Tier 1 |
|---|---|---|
| Subdomain discovery (CT) | `ghost_subdomains` (crt.sh) | ✓ exists |
| DNS records | — | `ghost_dns` (DoH-based, all types) |
| Certificate analysis | `ghost_cert` (basic) | + grading, JARM, mTLS detection |
| Security headers | — | `ghost_headers` (full analysis) |
| IP geolocation | `ghost_ip` (ip-api.com) | ✓ exists |
| Threat feeds | `ghost_threat` (4 feeds) | ✓ exists |
| Technology fingerprinting | `ghost_recon` (partial) | Enhanced via headers |
| Subdomain takeover | — | `ghost_dns` CNAME + resolution check |
| Infrastructure mapping | — | `ghost_recon` upgrade (orchestrates all above) |

---

## 5. Proposed Tool Specifications (Expanded)

### ghost_headers (Full Specification)

```python
@dataclass
class HeaderReport:
    url: str
    status_code: int
    
    # Security grading
    security_grade: str          # A+ through F
    security_score: int          # 0-100
    
    # Security headers (individual grades)
    security_headers: list[HeaderCheck]  # each with present/value/rating/recommendation
    
    # Server fingerprinting
    server_info: dict            # {server, version, os, powered_by, cms, cdn, framework}
    
    # Cookie analysis
    cookies: list[CookieCheck]   # each with name, secure, httponly, samesite, issues
    
    # CORS analysis
    cors: dict | None            # {origin_policy, credentials, methods, headers, issues}
    
    # Caching analysis
    caching: dict                # {public_sensitive, missing_no_store, etag_leak, issues}
    
    # Rate limit info
    rate_limits: dict | None     # {limit, remaining, reset, policy}
    
    # Information disclosure
    disclosures: list[str]       # headers that reveal too much
    
    # Raw data
    raw_headers: dict[str, str]
    response_time_ms: float
    search_urls: dict[str, str]
    error: str | None = None
```

### ghost_dns (Full Specification)

```python
@dataclass
class DNSReport:
    domain: str
    
    # All record types
    records: dict[str, list]     # {A: [...], AAAA: [...], MX: [...], etc.}
    
    # Email security
    spf: SPFAnalysis             # {record, valid, mechanisms, includes, policy, issues}
    dmarc: DMARCAnalysis         # {record, policy, pct, rua, ruf, issues}
    dkim: DKIMAnalysis | None    # {selectors_found, valid, issues}
    email_grade: str             # A through F
    
    # DNS security
    dnssec: DNSSECStatus         # {enabled, validated, algorithm, issues}
    zone_transfer: bool          # True = vulnerable (AXFR succeeded)
    wildcard_detected: bool      # *.domain resolves
    
    # Infrastructure mapping
    nameservers: list[str]       # NS records
    mail_servers: list[dict]     # MX with priority
    services_discovered: list[dict]  # SRV records parsed
    caa_policy: list[str]        # allowed CAs
    
    # Service discovery (from TXT records)
    services_detected: list[str]  # "Google Workspace", "SendGrid", "Stripe", etc.
    verification_tokens: dict     # {service: token}
    
    # Subdomain takeover
    dangling_cnames: list[DanglingCNAME]  # {subdomain, target, status, risk}
    
    # Zone walking (if NSEC available)
    nsec_walk_results: list[str] | None   # all names discovered via NSEC
    
    # Metadata
    soa: dict                    # {primary_ns, admin_email, serial, refresh, retry, expire}
    query_method: str            # "doh_cloudflare", "doh_google", "udp"
    search_urls: dict[str, str]
    error: str | None = None
```

### ghost_cert (Expanded Specification)

```python
@dataclass
class CertReport:
    # ... existing fields ...
    
    # NEW: TLS Grading
    tls_grade: str              # A through F
    protocol_version: str       # TLS 1.2, 1.3
    protocol_warnings: list[str]  # "TLS 1.0 supported", "weak cipher", etc.
    
    # NEW: JARM fingerprint
    jarm_hash: str | None       # 62-character JARM fingerprint
    jarm_match: str | None      # known software match if any ("Cobalt Strike", "nginx", etc.)
    
    # NEW: JA3S fingerprint
    ja3s_hash: str | None       # MD5 of ServerHello parameters
    
    # NEW: mTLS detection
    mtls_required: bool         # True if CertificateRequest was sent
    mtls_optional: bool         # True if accepted but not required
    mtls_ca_names: list[str]    # Distinguished Names of acceptable client cert CAs
    mtls_cert_types: list[str]  # Acceptable key types (RSA, ECDSA, etc.)
    
    # NEW: Protocol features
    alpn_protocols: list[str]   # ["h2", "http/1.1", "h3"]
    ocsp_stapled: bool          # Server provides OCSP response
    session_tickets: bool       # Session resumption support
    early_data_0rtt: bool       # TLS 1.3 0-RTT support (replay risk)
    ech_supported: bool         # Encrypted Client Hello
    
    # NEW: Cipher analysis
    cipher_suite: str           # Already exists
    cipher_strength: str        # "strong", "acceptable", "weak"
    pfs_supported: bool         # Perfect Forward Secrecy
    
    # NEW: CT analysis
    ct_logs_present: int        # Number of CT log SCTs embedded
    ct_logged: bool             # Cert found in CT logs
    
    # NEW: Certificate chain
    chain_depth: int
    chain_issues: list[str]     # "missing intermediate", "cross-signed", etc.
    
    # Existing
    search_urls: dict[str, str]
    error: str | None = None
```

---

## 6. Implementation Notes

### DoH for ghost_dns — No New Dependencies

```python
async def _doh_query(domain: str, record_type: str) -> dict:
    """Query DNS via Cloudflare DoH (HTTPS, no dnspython needed)."""
    url = f"https://cloudflare-dns.com/dns-query?name={domain}&type={record_type}"
    headers = {"Accept": "application/dns-json"}
    async with httpx.AsyncClient(timeout=5.0) as client:
        resp = await client.get(url, headers=headers)
        return resp.json()
```

Query all record types in parallel:
```python
types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "SRV", "CAA", "CNAME", "HTTPS"]
results = await asyncio.gather(*[_doh_query(domain, t) for t in types])
```

### JARM Implementation

JARM requires sending 10 custom TLS ClientHello packets. This needs raw socket access (not httpx). The reference implementation is in Python:
- https://github.com/salesforce/jarm (official, by the JA3 team)
- ~200 lines of Python
- Uses `socket` directly, not `ssl` module

### mTLS Detection

```python
import ssl, socket

def detect_mtls(host: str, port: int = 443) -> dict:
    """Connect without client cert, observe if CertificateRequest is sent."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Don't provide a client cert
    
    try:
        sock = socket.create_connection((host, port), timeout=10)
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        # If we get here, connection succeeded WITHOUT client cert
        # Server either doesn't require mTLS, or it's optional
        peer_cert = ssock.getpeercert(binary_form=True)
        ssock.close()
        return {"mtls_required": False, "connection": "success"}
    except ssl.SSLError as e:
        if "certificate required" in str(e) or "handshake failure" in str(e):
            return {"mtls_required": True, "error": str(e)}
        return {"mtls_required": False, "error": str(e)}
```

### Subdomain Takeover Fingerprints

```python
TAKEOVER_FINGERPRINTS = {
    "herokuapp.com": ["No such app", "no-such-app", "herokucdn.com/error-pages"],
    "s3.amazonaws.com": ["NoSuchBucket", "The specified bucket does not exist"],
    "azurewebsites.net": ["Error 404 - Web app not found"],
    "cloudfront.net": ["Bad Request", "ERROR: The request could not be satisfied"],
    "github.io": ["There isn't a GitHub Pages site here"],
    "shopify.com": ["Sorry, this shop is currently unavailable"],
    "netlify.app": ["Not Found - Request ID"],
    "vercel.app": ["The deployment could not be found"],
    "surge.sh": ["project not found"],
    "ghost.io": ["The thing you were looking for is no longer here"],
}
```

---

## 7. Effort Estimate (Revised)

| Tool | Original Estimate | Revised (full scope) | New Dependency |
|---|---|---|---|
| `ghost_headers` | 1 day (150 lines) | 2 days (~350 lines) | None |
| `ghost_dns` | 2 days (250 lines) | 3 days (~500 lines) | None (DoH via httpx) |
| `ghost_cert` upgrade | 0.5 day (100 lines) | 2 days (~400 lines) | JARM (~200 lines) |
| **Total** | **3.5 days** | **7 days** | **Zero new pip deps** |

The expanded scope more than doubles the effort but also more than doubles the intelligence value. And critically, we eliminated the `dnspython` dependency entirely by using DoH.

---

## 8. Perplexity Deep Research Findings (June 2026)

### 8.1 JARM Fingerprinting — Practical Reality

**Key finding: JARM is a clustering signal, NOT a product identifier.**

Sources: DFIR Report, Salesforce blog, HiveSecurity, Censys, ProjectDiscovery, C2-JARM repo, HITB conferences.

#### Known Cobalt Strike JARM Hashes

| Configuration | JARM Hash | Notes |
|---|---|---|
| Default (pre-Java 11 TLS change) | `07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1` | Legacy Java TLS stack |
| Default (post-Java 11) | `07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2` | Most commonly seen in wild |

**Critical caveat:** Cobalt Strike operators can change JARM by:
- Using different malleable C2 profiles (alter TLS behavior)
- Running behind Cloudflare/CDN (gets CDN's JARM instead)
- Domain fronting (gets fronting provider's JARM)
- Custom TLS certificates / cipher configuration
- Different Java versions (JDK 8 vs 11 vs 17 produce different JARMs)
- JARM Randomizer tool exists (HITB 2021, Dagmawi Mulugeta) — defeats JARM entirely

**Sliver C2:** No single consistent JARM hash. Varies per deployment because Sliver uses Go's crypto/tls which the operator can configure. Treat as clusterable, not universal.

**Other C2 frameworks:** The `cedowens/C2-JARM` GitHub repo maintains a community-sourced list. No comprehensive database exists — this is the closest.

#### JARM for Infrastructure Identification

| Use Case | Reliability |
|---|---|
| Clustering "same software stack" across IPs | Good |
| Detecting default C2 configs (operator didn't customize) | Moderate |
| Identifying specific web server product/version | Poor — too many variables |
| CDN identification | Poor — CDN configs change frequently |
| Pivoting from known-bad to unknown-bad | Good (when combined with other signals) |

#### JARM Scan Performance

- 10 TLS ClientHello probes per target
- Each probe = 1 TCP connection + partial TLS handshake
- Estimated time per host: 2-5 seconds (depends on latency + timeout on non-responsive probes)
- **100 subdomains = ~3-8 minutes** (sequential) or ~30-60 seconds (parallel with 10 workers)
- Lower noise than full port scan — only sends TLS ClientHellos, no HTTP
- Can trigger WAF/IDS if many subdomains resolve to same front-end (CDN sees burst of malformed hellos)
- Best practice: pace at 1 probe/second, randomize order, cache by IP (skip duplicate IPs)

### 8.2 mTLS Passive Detection — Expanded

**TLS 1.2 flow:**
```
Client → ServerHello
Client ← Server Certificate
Client ← CertificateRequest     ← THIS IS THE mTLS SIGNAL
Client ← ServerHelloDone
Client → (empty) Certificate     ← We don't have one, so send empty
Client → ClientKeyExchange
Server → Alert: handshake_failure (or continues with empty cert if optional)
```

**TLS 1.3 flow:**
```
Client → ClientHello
Client ← ServerHello
Client ← {EncryptedExtensions}
Client ← {CertificateRequest}   ← THIS IS THE mTLS SIGNAL (encrypted!)
Client ← {Certificate}
Client ← {CertificateVerify}
Client ← {Finished}
```

**Key difference in TLS 1.3:** The CertificateRequest is inside the encrypted handshake. This means:
- A **passive network observer** cannot see it (encrypted)
- An **active prober** (our scanner) CAN see it because we're the TLS endpoint
- Post-handshake client auth (TLS 1.3 feature) also uses CertificateRequest but after Finished

**What CertificateRequest reveals (internal PKI intel):**

| Field | Intelligence Value |
|---|---|
| `certificate_authorities` (list of X.501 DNs) | Internal CA names — reveals AD domain structure, PKI vendor, org hierarchy |
| `signature_algorithms` | Crypto policy — modern (Ed25519, RSA-PSS) vs legacy (SHA-1) |
| `certificate_types` (TLS 1.2) | Acceptable key types (RSA, ECDSA, DSA) |
| `extensions` (TLS 1.3) | Additional requirements (OID filters, etc.) |

**Example leaked CA DN:** `CN=ACME-Corp-Internal-CA-G2, O=Acme Corporation, DC=corp, DC=acme, DC=com`
This reveals: company name, AD domain (corp.acme.com), CA generation (G2 = second generation).

**Existing tools for mTLS detection:**
- **testssl.sh** — reports if server requests client cert
- **sslyze** — Python library, reports CertificateRequest
- **Nmap ssl-cert script** — notes client auth
- **Zeek** — passive TLS logging, records CertificateRequest presence
- **Suricata** — TLS event logging

### 8.3 DNS over HTTPS — Operational Details

#### Cloudflare vs Google for Recon

| Feature | Cloudflare DoH | Google DoH |
|---|---|---|
| **Endpoint** | `https://cloudflare-dns.com/dns-query` | `https://dns.google/resolve` |
| **Format** | RFC 8484 wireformat + JSON | Custom JSON only |
| **HTTPS/SVCB (type 65/64)** | Supported | Gradually added, less polished |
| **DNSSEC AD flag** | Yes — reliable | Yes — reliable |
| **Rate limits** | Unpublished, generous (~10K/day practical) | Unpublished, generous |
| **HTTP/2 multiplexing** | Yes — use persistent connections | Yes |
| **NSEC records in responses** | Sometimes (for negative answers) | Sometimes |
| **Best for** | Maximum protocol fidelity, modern RR types | Simpler JSON parsing |

**Recommendation for GhostMCP:** Use Cloudflare primary, Google as fallback. Both support parallel queries over HTTP/2 multiplexed connections.

#### Zone Walking via DoH

- Works only against zones using NSEC (not NSEC3)
- DoH resolvers **may not always expose intermediate NSEC records** — they can synthesize negative responses
- For reliable zone walking, query **authoritative nameservers directly** (TCP)
- Practical approach: try via DoH first (free, encrypted), fall back to direct NS query if NSEC data is incomplete

#### NSEC3 Reality Check

Most security-conscious zones use NSEC3 (hashed names), which prevents zone walking. However:
- NSEC3 with opt-out still leaks some information
- Many smaller zones still use NSEC (government, education, older configs)
- NSEC3 doesn't prevent subdomain enumeration via CT logs or brute force — just prevents complete zone dumps

### 8.4 Subdomain Takeover — 2026 Reality

**Key finding: Provider mitigations are improving, but misconfigs still create takeover opportunities.**

#### Platform Takeover Status (based on community research)

| Service | Takeover Risk | Mitigation Method | Notes |
|---|---|---|---|
| **Heroku** | Decreasing — domain verification added | TXT verification on new custom domains | Legacy apps without verification still vulnerable |
| **AWS S3** | Still possible | No automatic verification | "NoSuchBucket" = takeover opportunity |
| **GitHub Pages** | Low — domain verification required | TXT record proof | Hard to takeover now |
| **Azure App Service** | Possible (edge cases) | Domain verification on newer setups | Older configs without verification still exist |
| **Vercel** | Low-Moderate | Domain verification via DNS | Misconfigs still possible when project deleted without domain release |
| **Netlify** | Low-Moderate | Domain verification | "Not Found" page = potential |
| **Cloudflare Pages** | Low | Strict ownership verification | Rare but possible if worker route deleted |
| **Firebase Hosting** | Low | Project-level domain claim | Orphaned projects possible |
| **Google Cloud Run** | Varies | Load balancer + domain mapping | Depends on cleanup of domain mappings |
| **Render** | Moderate | Custom domain claim | App deletion may leave dangling records |
| **Fly.io** | Moderate | Certificate-based domain claim | App deletion without CNAME cleanup |
| **Railway** | Moderate | Domain verification | Newer platform, less battle-tested |
| **AWS Amplify** | Possible | No inherent domain verification | "This site can't be reached" patterns |
| **Surge.sh** | High | No verification | "project not found" = easy takeover |
| **Ghost.io** | Moderate | Domain claim | "The thing you were looking for" |

#### Detection Methodology

```
For each discovered CNAME:
  1. Extract CNAME target domain
  2. Match against known service patterns:
     - *.herokuapp.com → Heroku
     - *.s3.amazonaws.com → S3
     - *.vercel-dns.com or cname.vercel-dns.com → Vercel
     - *.netlify.app → Netlify
     - *.web.app / *.firebaseapp.com → Firebase
     - *.fly.dev → Fly.io
     - *.onrender.com → Render
     - *.up.railway.app → Railway
     - *.cloudflaressl.com → Cloudflare
     - *.amplifyapp.com → AWS Amplify
  3. Resolve the CNAME target:
     - NXDOMAIN → likely dangling (HIGH risk)
     - Resolves but HTTP returns known "unclaimed" page → likely takeover
     - Resolves and serves content → legitimate (no takeover)
  4. If potentially dangling:
     - Fetch HTTP response from the subdomain
     - Match body against fingerprint database
     - Classify: CONFIRMED / LIKELY / POSSIBLE / FALSE_POSITIVE
```

#### Reference Projects

- **can-i-take-over-xyz** (GitHub, EdOverflow/can-i-take-over-xyz) — canonical reference, community-maintained
- **subjack** — automated takeover detection tool
- **subzy** — Go-based subdomain takeover checker
- **nuclei** templates (`http/takeovers/`) — YAML-based detection rules
- **dnsreaper** — Python-based, checks 40+ providers

### 8.5 HTTP Header Grading — Best Practices 2026

**Scoring philosophy (Hardenize-style, recommended):**

| Dimension | Weight | What It Scores |
|---|---|---|
| HSTS | 20% | Presence, max-age >= 1 year, includeSubDomains, preload |
| CSP | 25% | Nonce/hash-based (no unsafe-inline), tight default-src, object-src none |
| Frame protection | 10% | X-Frame-Options or CSP frame-ancestors |
| Content-Type | 10% | X-Content-Type-Options: nosniff |
| Referrer | 10% | strict-origin-when-cross-origin or stricter |
| Permissions | 10% | Permissions-Policy restricting camera, mic, geo, payment |
| CORS | 10% | No wildcard with credentials |
| Bonus | +5% | Reporting-Endpoints configured, COOP, COEP |

**CSP scoring evolution (2025-2026):**
- `unsafe-inline` = automatic cap at B (never gets A)
- Nonce-based = full score potential
- Hash-based (sha256-...) = full score potential
- `report-only` CSP = half credit (shows intent but no enforcement)
- `script-src 'self'` without nonce = moderate (blocks inline but not injected same-origin)
- Wildcard in script-src (`*.example.com`) = weak
- `Reporting-Endpoints` header = bonus points (replaces deprecated `report-uri` and `Report-To`)

### 8.6 Certificate Transparency — Beyond crt.sh

| Service | API | Cost | Features |
|---|---|---|---|
| **crt.sh** (Sectigo) | Free web + PostgreSQL access | Free | Largest public CT aggregator, search by domain/cert |
| **Censys** | REST API | Free tier + paid | CT + host scanning combined, rich search |
| **Shodan** | REST API | Free tier + paid | CT data + port scanning combined |
| **Google CT log search** | Transparency Report | Free | Google-operated logs |
| **Facebook CT monitoring** | Internal (was public) | N/A | Used to monitor for FB domain abuse |
| **Netlas** | REST API | Free tier + paid | CT + JARM + HTTP fingerprinting combined |
| **Custom CT watchers** | certstream, certspotter | Free/OSS | Real-time CT log streaming |

**Detecting unauthorized certificates:**
- Compare newly issued certs against expected CA list (from CAA records)
- Flag certs from unexpected issuers
- Flag wildcards not in your inventory
- Flag internal hostnames appearing in public CT logs
- Flag certs with very short validity (often used for ephemeral C2)

**Merkle tree proofs — practical value:**
- Proves a certificate IS in the log (inclusion proof)
- Proves the log hasn't been tampered with (consistency proof)
- Useful for: detecting log equivocation (showing different views to different clients)
- For OSINT toolkit: optional — trust crt.sh/Censys to verify for you unless building a CT monitor

---

## 9. Revised Architecture — Full Intelligence Stack

```
ghost_headers (1 GET request)
├── Security header grading (A+ to F)
├── Server fingerprinting (server, tech, CDN, CMS, framework)
├── Cookie security analysis (Secure, HttpOnly, SameSite per cookie)
├── CORS policy analysis (wildcard, credentials, methods)
├── Caching policy analysis (sensitive data cached?)
├── Rate limit discovery (X-RateLimit-* headers)
└── Information disclosure audit (headers revealing too much)

ghost_dns (DoH queries via httpx — zero deps)
├── All record types (A/AAAA/MX/NS/TXT/SOA/SRV/CAA/CNAME/HTTPS/SVCB)
├── Email security grading (SPF + DKIM + DMARC)
├── DNSSEC validation status (AD flag via DoH)
├── Service discovery from TXT records (Google, M365, Stripe, etc.)
├── Infrastructure mapping (IP clustering, CNAME graph)
├── Dangling CNAME / subdomain takeover detection (40+ provider fingerprints)
├── Zone transfer attempt (AXFR to authoritative NS)
├── NSEC zone walking (when available)
├── Wildcard detection (random subdomain query)
└── Recursive discovery (follow SPF includes, MX hosts, SRV targets)

ghost_cert (TLS handshake — enhanced)
├── Certificate analysis (SANs, issuer, validity, key strength, CT SCTs)
├── TLS grading (protocol version, cipher strength, PFS)
├── JARM fingerprinting (10-probe server fingerprint → C2/software clustering)
├── mTLS detection (CertificateRequest presence + CA DN extraction)
├── ALPN protocols (HTTP/2, HTTP/3, gRPC)
├── OCSP stapling + revocation check
├── ECH support detection (via HTTPS DNS record)
├── Session security (tickets, 0-RTT, renegotiation)
└── Certificate chain analysis (depth, cross-signing, intermediate issues)
```

**Total passive footprint per target:** 1 HTTP GET + 10-15 DoH queries + 1 TLS handshake + 10 JARM probes
**Equivalent to:** Visiting the site in a browser + running `dig` a few times + checking SSL Labs
**Legal status:** Completely passive observation of publicly-advertised configurations

---

## 10. API Discovery — Passive (Tier 1) vs Active (Tier 2)

### 10.1 Tier 1: Published API Surface (Passive)

These are paths the target explicitly makes available — fetching them is identical to what any API consumer does:

| Path / Method | What We Fetch | What It Reveals |
|---|---|---|
| `/swagger.json`, `/swagger/v1/swagger.json` | OpenAPI 2.0 spec | Full API schema — endpoints, methods, parameters, auth requirements, models |
| `/openapi.json`, `/openapi.yaml`, `/api-docs` | OpenAPI 3.0/3.1 spec | Same — newer spec format, richer type info |
| `/docs`, `/redoc`, `/api/docs` | API documentation pages | Human-readable endpoint listing, sometimes with try-it-out buttons |
| `/graphql` (POST introspection query) | GraphQL schema | Complete type system — queries, mutations, subscriptions, fields, arguments |
| `/robots.txt` | Disallow directives | Paths the site doesn't want crawled — often reveals admin panels, API routes, internal tools |
| `/sitemap.xml` | URL inventory | All pages/endpoints the site wants indexed |
| `/.well-known/openid-configuration` | OIDC discovery | Auth provider (Okta, Auth0, Keycloak, Azure AD), token endpoints, scopes, grant types |
| `/.well-known/security.txt` | Security contact | Responsible disclosure contact, PGP key, hiring link, acknowledgments |
| `/.well-known/change-password` | Password change URL | Reveals auth system endpoint |
| `/.well-known/assetlinks.json` | Android app links | Mobile app associations |
| `/.well-known/apple-app-site-association` | iOS app links | Apple universal links |
| `OPTIONS /api/*` (CORS preflight) | CORS policy | Allowed methods, headers, origins — reveals API capabilities |
| `?wsdl` on known paths | SOAP WSDL definition | Legacy SOAP API schema |
| Response headers on any endpoint | `Link:` header (HATEOAS) | Related API endpoints, pagination |
| Error format on `/api/` | Framework error page | Django REST ("detail": "Not found"), FastAPI ({"detail": ...}), Spring Boot (timestamp+status+error), Express (stack trace) |

**Total requests:** ~15-20 GETs to well-known paths. Same traffic as any developer reading the API docs.

### 10.2 What `ghost_api` Would Return

```python
@dataclass
class APIDiscoveryReport:
    url: str

    # Published specs
    openapi_spec: dict | None      # parsed swagger/openapi JSON if found
    openapi_url: str | None        # where we found it
    openapi_version: str | None    # "2.0", "3.0.3", "3.1.0"
    graphql_introspection: dict | None  # schema if introspection enabled
    graphql_url: str | None
    wsdl: str | None               # WSDL XML if found

    # Well-known paths
    robots_txt: dict | None        # {allowed: [...], disallowed: [...], sitemaps: [...]}
    sitemap_urls: list[str]
    security_txt: dict | None      # {contact, encryption, policy, hiring, acknowledgments}
    oidc_config: dict | None       # OpenID Connect discovery document
    oidc_provider: str | None      # "Auth0", "Okta", "Keycloak", "Azure AD", etc.

    # API surface
    endpoints_discovered: int
    methods_available: list[str]   # from CORS OPTIONS or spec
    api_versions: list[dict]       # [{version: "v1", status: "active"}, {version: "v2", status: "404"}]

    # Framework fingerprint
    framework: str | None          # "FastAPI", "Django REST", "Spring Boot", "Express", etc.
    framework_evidence: str        # how we determined it

    # CORS
    cors_policy: dict | None       # {origin, credentials, methods, headers}

    # Sensitive findings
    sensitive_paths: list[dict]    # [{path, reason}] — debug endpoints, admin panels from robots.txt
    warnings: list[str]

    search_urls: dict[str, str]
    error: str | None = None
```

### 10.3 Tier 2 Boundary (Out of Scope Without Authorization)

These cross the line from "reading published information" to "probing for undisclosed attack surface":

| Method | Why It's Tier 2 |
|---|---|
| Brute-forcing API paths (`/admin`, `/users`, `/internal`, `/debug`) | Guessing paths not published — active probing |
| Fuzzing parameters (send malformed input) | Attack payload territory |
| Trying default credentials (`admin/admin`, API keys) | Authentication bypass attempt |
| Forced browsing (IDOR testing on `/users/1`, `/users/2`) | Accessing unauthorized resources |
| Method tampering (PUT/DELETE on GET-only endpoints) | Unexpected mutation testing |
| GraphQL batching/depth attacks | DoS / abuse testing |
| Rate limit testing (intentional flooding) | Availability testing |

### 10.4 Implementation Notes

**Swagger/OpenAPI discovery paths to check (ordered by frequency):**
```python
OPENAPI_PATHS = [
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/swagger/v1/swagger.json",
    "/api/swagger.json",
    "/api/v1/swagger.json",
    "/api/v2/swagger.json",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi.yaml",
    "/swagger.yaml",
    "/docs",
    "/redoc",
    "/api/docs",
    "/api/openapi.json",
]
```

**GraphQL introspection query:**
```graphql
{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields { name type { name kind } }
    }
  }
}
```

**Framework fingerprinting from error responses:**
```python
FRAMEWORK_FINGERPRINTS = {
    "FastAPI":       {"pattern": '"detail":', "path": "/nonexistent", "status": 404},
    "Django REST":   {"pattern": '"detail":"Not found"', "path": "/api/", "status": 404},
    "Spring Boot":   {"pattern": '"timestamp"', "path": "/error", "status": 404},
    "Express":       {"pattern": "Cannot GET", "path": "/nonexistent", "status": 404},
    "Laravel":       {"pattern": "Symfony", "path": "/nonexistent", "status": 404},
    "ASP.NET":       {"pattern": "X-AspNet-Version", "path": "/", "status": 200},
    "Flask":         {"pattern": "Werkzeug", "path": "/nonexistent", "status": 404},
    "Rails":         {"pattern": "ActionController", "path": "/nonexistent", "status": 404},
}
```

**OIDC provider identification from discovery document:**
```python
OIDC_PROVIDERS = {
    "auth0.com": "Auth0",
    "okta.com": "Okta",
    "login.microsoftonline.com": "Azure AD",
    "accounts.google.com": "Google",
    "cognito-idp": "AWS Cognito",
    "keycloak": "Keycloak",
    "auth.pingone.com": "PingOne",
    "login.salesforce.com": "Salesforce",
}
```
