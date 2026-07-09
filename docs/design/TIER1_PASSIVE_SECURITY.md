# GhostMCP Tier 1: Passive Security Assessment — Design Document

**Date:** 2026-06-19
**Status:** PROPOSED
**Scope:** 3 tools, ~500 lines of code, 3-4 dev days

---

## Overview

Tier 1 adds passive security assessment capabilities to GhostMCP — checks that observe publicly-advertised security policies using standard HTTP requests and DNS queries. No attack payloads, no authorization needed, legal against any target.

### New Tools

| Tool | What It Does | Input | Data Source | Effort |
|---|---|---|---|---|
| `ghost_headers` | Grade a site's HTTP security headers (A+ through F) | URL | Single GET request | 1 day |
| `ghost_dns` | Check DNS security (SPF/DKIM/DMARC/DNSSEC, dangling CNAMEs) | Domain | DNS queries (UDP/TCP) | 2 days |
| `ghost_cert` upgrade | Add letter grading + protocol/cipher warnings to existing tool | Host | Existing TLS connection | 0.5 day |

### What It Enables

An agent doing recon on a domain can now answer:
- "Does this site have proper security headers?" → `ghost_headers`
- "Is their email spoofable?" → `ghost_dns` (SPF/DKIM/DMARC check)
- "How secure is their TLS?" → `ghost_cert` (with grading)
- "Are there subdomain takeover risks?" → `ghost_dns` (dangling CNAME detection)

Combined with existing tools (`ghost_subdomains`, `ghost_recon`, `ghost_cert`), this gives a complete passive security posture assessment.

---

## Data Flow

### ghost_headers

```
Agent Request                    GhostMCP                           Target
─────────────                    ────────                           ──────
                                      
ghost_headers(url)  ─────────►  [1] Validate URL
                                [2] Single GET request  ──────────► Target web server
                                [3] Read response headers ◄────────  HTTP headers returned
                                [4] Grade each header               
                                [5] Compute overall grade           
                                [6] Generate recommendations        
                   ◄─────────   [7] Return HeaderReport            
```

**Request count:** 1 HTTP GET (same as visiting the site in a browser)
**Latency:** < 3 seconds
**Rate limit concern:** None — single request per call

### ghost_dns

```
Agent Request                    GhostMCP                           DNS Infrastructure
─────────────                    ────────                           ──────────────────
                                      
ghost_dns(domain)  ──────────►  [1] Validate domain
                                [2] Parallel DNS queries  ─────────► Recursive resolver
                                    ├─ TXT (_spf.)       
                                    ├─ TXT (_dmarc.)     
                                    ├─ TXT (selector._domainkey.)   
                                    ├─ MX records        
                                    ├─ NS records        
                                    ├─ CAA records       
                                    ├─ DS/DNSKEY (DNSSEC)
                                    └─ AXFR attempt       ─────────► Authoritative NS
                                                          ◄─────────  (refused or zone data)
                                [3] Check subdomains for  ─────────► CNAME resolution
                                    dangling CNAMEs       ◄─────────  (NXDOMAIN = dangling)
                                [4] Analyze SPF syntax    
                                [5] Validate DMARC policy 
                                [6] Grade email security  
                   ◄──────────  [7] Return DNSReport     
```

**Request count:** 8-15 DNS queries (parallel) + 1 AXFR attempt + N CNAME checks
**Latency:** < 5 seconds (DNS queries are fast, run in parallel)
**Rate limit concern:** None — standard DNS queries, same as any email client or browser

### ghost_cert upgrade (grading)

```
Agent Request                    GhostMCP                           Target
─────────────                    ────────                           ──────
                                      
ghost_cert(host)   ──────────►  [1] Existing TLS connection logic
                                [2] Existing cert parsing
                                [3] NEW: Grade protocol version
                                [4] NEW: Grade cipher strength
                                [5] NEW: Check PFS support
                                [6] NEW: Compute letter grade
                                [7] NEW: Add warnings list
                   ◄──────────  [8] Return CertReport + grade
```

**Request count:** 0 additional (uses existing TLS handshake)
**Latency:** Same as current ghost_cert (< 2 seconds)

---

## Architecture

### Module Layout

```
ghostmcp/recon/
├── certs.py          ← MODIFY: add grading logic (~100 lines)
├── headers.py        ← NEW: security header analysis (~200 lines)
├── dns_intel.py      ← NEW: DNS security checks (~300 lines)
├── ...existing...
```

### Dependencies

| Tool | New Dependencies | Already Installed |
|---|---|---|
| `ghost_headers` | None | `httpx` (existing) |
| `ghost_dns` | `dnspython` (pip) | — |
| `ghost_cert` upgrade | None | `cryptography`, `ssl` (existing) |

### Dataclasses

```python
# headers.py
@dataclass
class HeaderCheck:
    name: str              # e.g., "Strict-Transport-Security"
    present: bool
    value: str | None      # actual header value if present
    rating: str            # "good", "warning", "bad", "missing"
    recommendation: str    # what to fix

@dataclass  
class HeaderReport:
    url: str
    grade: str             # "A+", "A", "B", "C", "D", "F"
    score: int             # 0-100 numeric
    headers: list[HeaderCheck]
    warnings: list[str]
    raw_headers: dict[str, str]
    search_urls: dict[str, str]  # SecurityHeaders.com, Mozilla Observatory
    error: str | None = None


# dns_intel.py
@dataclass
class DNSRecord:
    record_type: str       # SPF, DMARC, DKIM, MX, NS, CAA, DNSSEC
    value: str | None
    valid: bool
    issues: list[str]

@dataclass
class DanglingCNAME:
    subdomain: str
    cname_target: str
    status: str            # "dangling", "active", "unknown"
    takeover_risk: str     # "high", "medium", "low", "none"

@dataclass
class DNSReport:
    domain: str
    spf: DNSRecord
    dmarc: DNSRecord
    dkim: DNSRecord | None  # requires knowing the selector
    dnssec: DNSRecord
    zone_transfer: bool     # True if AXFR succeeded (vulnerable)
    mx_records: list[dict]
    nameservers: list[str]
    caa_records: list[str]
    dangling_cnames: list[DanglingCNAME]
    email_security_grade: str  # "A" through "F"
    search_urls: dict[str, str]
    error: str | None = None
```

---

## Header Grading Algorithm

### Scoring Model

Each header contributes points to a 100-point scale:

| Header | Max Points | Present | Good Config | Perfect Config |
|---|---|---|---|---|
| Strict-Transport-Security | 20 | +10 | +15 (max-age >= 31536000) | +20 (+ includeSubDomains + preload) |
| Content-Security-Policy | 25 | +10 | +18 (no unsafe-inline) | +25 (strict, nonce-based) |
| X-Content-Type-Options | 10 | +10 | +10 (nosniff) | +10 |
| X-Frame-Options | 10 | +7 | +10 (DENY or SAMEORIGIN) | +10 |
| Referrer-Policy | 10 | +5 | +8 (strict-origin-when-cross-origin) | +10 (no-referrer) |
| Permissions-Policy | 10 | +5 | +8 (restrictive) | +10 (fully locked down) |
| CORS headers | 15 | +5 (if appropriate) | +10 (restrictive) | +15 (no wildcard) |

### Grade Thresholds

| Score | Grade | Meaning |
|---|---|---|
| 90-100 | A+ | Exemplary — all headers present with strict values |
| 80-89 | A | Excellent — all critical headers, minor improvements possible |
| 65-79 | B | Good — most headers present, some gaps |
| 50-64 | C | Adequate — critical headers present but weak configuration |
| 30-49 | D | Poor — critical headers missing |
| 0-29 | F | Failing — minimal or no security headers |

---

## DNS Security Grading Algorithm

### Email Security Grade

| Check | Points | Criteria |
|---|---|---|
| SPF present | +20 | TXT record with `v=spf1` exists |
| SPF valid syntax | +5 | No errors in SPF record |
| SPF strict (`-all`) | +5 | Uses `-all` (hard fail) vs `~all` (soft fail) |
| DMARC present | +25 | `_dmarc.` TXT record exists |
| DMARC policy `reject` | +10 | `p=reject` (strongest) |
| DMARC policy `quarantine` | +5 | `p=quarantine` (moderate) |
| DMARC rua/ruf set | +5 | Reporting configured |
| DKIM present | +15 | At least one `_domainkey` TXT record found |
| DNSSEC enabled | +10 | DS records present in parent zone |
| No zone transfer | +5 | AXFR refused by all nameservers |

### Grade Thresholds

| Score | Grade |
|---|---|
| 90-100 | A |
| 75-89 | B |
| 50-74 | C |
| 25-49 | D |
| 0-24 | F |

---

## TLS Grading Algorithm (ghost_cert upgrade)

### Protocol Scoring

| Protocol | Score Impact |
|---|---|
| TLS 1.3 only | A (best) |
| TLS 1.2 + 1.3 | A |
| TLS 1.1 enabled | Cap at B |
| TLS 1.0 enabled | Cap at C |
| SSL 3.0 enabled | Cap at F |

### Cipher Scoring

| Cipher Category | Impact |
|---|---|
| AEAD ciphers (GCM, ChaCha20) | Good |
| CBC ciphers (with proper padding) | Acceptable |
| RC4, DES, 3DES, NULL | Cap at D |
| No PFS (non-ECDHE/DHE) | Cap at B |

### Certificate Issues

| Issue | Impact |
|---|---|
| Expired | F |
| Self-signed | Cap at C |
| Hostname mismatch | Cap at D |
| Key < 2048-bit RSA | Cap at C |
| SHA-1 signature | Cap at C |
| Missing SCT (CT) | Warning only |

---

## MCP Tool Registration

```python
# ghost_headers
@mcp.tool(
    name="ghost_headers",
    description="Analyze HTTP security headers of a URL and return a letter grade (A+ through F) with specific recommendations.",
    parameters={
        "url": {"type": "string", "description": "URL to check security headers for."},
    },
)

# ghost_dns  
@mcp.tool(
    name="ghost_dns",
    description="Check DNS security configuration: SPF, DKIM, DMARC, DNSSEC, zone transfer vulnerability, and dangling CNAME detection.",
    parameters={
        "domain": {"type": "string", "description": "Domain to check DNS security for."},
    },
)

# ghost_cert gets no new registration — existing tool, just enhanced output
```

---

## Integration with Existing Tools

### Recon Workflow (agent perspective)

```
1. ghost_subdomains(domain)     → discover infrastructure
2. ghost_cert(host)             → TLS grade for each host
3. ghost_headers(url)           → security header grade for each site  
4. ghost_dns(domain)            → email security + DNS config
5. ghost_recon(domain, ["tech"]) → technology stack
6. ghost_threat(domain)         → threat intel feeds

= Complete passive security posture assessment
```

### ghost_report Integration

The composite `ghost_report` tool should optionally accept a domain and include:
- Header grade
- TLS grade  
- DNS/email security grade
- Combined "security posture" section in the report

---

## Testing Strategy

| Tool | Unit Tests | Integration Tests |
|---|---|---|
| `ghost_headers` | Mock httpx response with various header combos, test grading logic | Hit real sites (google.com = A+, neverssl.com = F) |
| `ghost_dns` | Mock dnspython responses, test SPF/DMARC parsing | Hit real domains (google.com has SPF+DMARC, test domains without) |
| `ghost_cert` grading | Use existing test fixtures, test grade computation | Existing integration tests cover live TLS |

---

## Risks & Mitigations

| Risk | Mitigation |
|---|---|
| DNS queries flagged as suspicious | Standard recursive queries — identical to any browser/email client |
| Zone transfer attempt blocked | Expected — most servers refuse. We report "secure" when refused. |
| Target rate limits our header check | Single GET request — indistinguishable from a normal visit |
| DKIM selector unknown | Try common selectors: `default`, `google`, `selector1`, `selector2`, `s1`, `s2`, `k1`, `mail` |
| Results misinterpreted as "scan" | Clear documentation that these are passive observations, not active tests |
