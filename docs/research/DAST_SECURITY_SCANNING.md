# DAST & Security Scanning Landscape for GhostMCP

**Date:** 2026-06-19
**Purpose:** Map the DAST/security scanning landscape and identify what's in-scope for GhostMCP (passive) vs out-of-scope (active, requires ForensicsMCP).

---

## The Line: Passive vs Active

| Category | Passive (GhostMCP) | Active (ForensicsMCP) |
|---|---|---|
| **What it does** | Reads publicly-advertised security policies | Sends attack payloads to test for vulns |
| **Authorization needed** | No — observing public information | Yes — written permission required |
| **Legal risk** | None — equivalent to visiting the site | CFAA/CMA violations without authorization |
| **Request volume** | 1-5 requests per check | 1,000-50,000+ requests per scan |
| **Time** | < 5 seconds | 10-60+ minutes |
| **Fits GhostMCP model** | Yes | No |

---

## Tier 1: Passive Security Checks (GhostMCP Scope)

### Security Headers

What we check with a single GET request:

| Header | What It Does | Impact If Missing |
|---|---|---|
| `Strict-Transport-Security` (HSTS) | Forces HTTPS for future visits | MitM downgrade attacks |
| `Content-Security-Policy` (CSP) | Controls which scripts/styles can execute | XSS attacks succeed |
| `X-Frame-Options` | Prevents clickjacking via iframes | Clickjacking |
| `X-Content-Type-Options` | Prevents MIME-type sniffing | Drive-by downloads |
| `Referrer-Policy` | Controls referrer information leakage | Information disclosure |
| `Permissions-Policy` | Controls browser feature access (camera, mic, geolocation) | Feature abuse |
| `Cross-Origin-Resource-Policy` | Controls cross-origin resource loading | Data leakage |
| `Cross-Origin-Opener-Policy` | Isolates browsing context | Spectre-style attacks |

**Grading model (like SecurityHeaders.com):**
- A+: All headers present with strict values
- A: All critical headers present
- B: Most headers present, minor issues
- C: Some headers missing
- D: Critical headers missing
- F: No security headers at all

**Competitors:**
- SecurityHeaders.com (Scott Helme) — free, web-based
- Mozilla Observatory — free, open source, more comprehensive
- Hardenize — paid, more detailed

### DNS Security

What we check with standard DNS queries:

| Check | What It Tells Us | Query Type |
|---|---|---|
| SPF record | Who can send email for this domain | TXT lookup |
| DKIM | Email authentication | TXT lookup (selector._domainkey) |
| DMARC | Email policy (reject/quarantine/none) | TXT lookup (_dmarc.) |
| DNSSEC | DNS response integrity | DS/DNSKEY lookup |
| Zone transfer (AXFR) | If full DNS zone is exposed | AXFR attempt |
| CAA records | Which CAs can issue certs for this domain | CAA lookup |
| MX records | Mail server configuration | MX lookup |
| Dangling CNAMEs | Subdomain takeover risk | CNAME resolution check |

### TLS/SSL Grading

Enhance existing `ghost_cert` with:

| Check | Issue | Severity |
|---|---|---|
| TLS 1.0 enabled | Deprecated, known attacks (BEAST, POODLE) | HIGH |
| TLS 1.1 enabled | Deprecated since 2021 | MEDIUM |
| Weak ciphers (RC4, DES, 3DES) | Breakable encryption | HIGH |
| No PFS (Perfect Forward Secrecy) | Past traffic decryptable if key compromised | MEDIUM |
| Short RSA key (< 2048 bit) | Breakable with modern compute | HIGH |
| Self-signed cert | No trust chain validation | HIGH |
| Expired cert | Browser warnings, trust loss | CRITICAL |
| Cert hostname mismatch | Browser warnings | HIGH |
| Missing OCSP stapling | Slower revocation checking | LOW |
| No CT log entry | Cert not publicly logged | LOW |

---

## Tier 2: Active DAST Scanning (Out of Scope — ForensicsMCP)

### Tool Landscape

| Tool | License | API | Hosting | Best For |
|---|---|---|---|---|
| **OWASP ZAP** | Apache 2.0 (free) | REST API | Self-hosted (Docker) | Full DAST, CI/CD integration |
| **Nuclei** | MIT (free) | CLI/library | Self-hosted | Fast template-based scanning |
| **Nikto** | GPL (free) | CLI | Self-hosted | Quick web server checks |
| **Wapiti** | GPL (free) | CLI | Self-hosted | Python-based active scanner |
| **StackHawk** | Commercial | REST API | Cloud hosted | Developer-friendly, built on ZAP |
| **Invicti** | Commercial | REST API | Cloud/on-prem | Proof-based scanning |
| **Acunetix** | Commercial (~$4.5K/yr) | REST API | Cloud/on-prem | Fast, accurate |
| **Burp Suite Enterprise** | Commercial (~$8K+/yr) | REST API | Cloud/on-prem | Gold standard |
| **Qualys WAS** | Commercial | REST API | Cloud | Enterprise compliance |
| **Rapid7 InsightAppSec** | Commercial | REST API | Cloud | Remediation tracking |
| **AppCheck** | Commercial | REST API | Cloud | Built by pen testers |
| **Checkmarx DAST** | Commercial | REST API | Cloud | Part of ASPM platform |
| **Escape.tech** | Commercial | REST API | Cloud | API-first (GraphQL/REST) |

### What ZAP Can Do (if we went Tier 2)

ZAP REST API capabilities:
- `GET /JSON/core/view/alerts/` — list findings
- `POST /JSON/spider/action/scan/` — start crawling
- `POST /JSON/ascan/action/scan/` — start active scan
- `GET /JSON/ascan/view/status/` — poll scan progress
- `GET /JSON/core/other/htmlreport/` — generate report

ZAP Docker one-liner:
```bash
docker run -u zap -p 8080:8080 zaproxy/zap-stable zap.sh -daemon -port 8080
```

### What Nuclei Can Do

Nuclei template categories relevant to web apps:
- `http/cves/` — known CVE detection (thousands of templates)
- `http/misconfiguration/` — misconfigs (exposed .git, .env, debug panels)
- `http/vulnerabilities/` — generic vulns (SQLi, XSS, SSRF)
- `http/exposed-panels/` — admin panels, dashboards
- `http/technologies/` — tech fingerprinting

Nuclei CLI:
```bash
nuclei -u https://target.com -t http/cves/ -severity critical,high
```

---

## Implementation Priority for GhostMCP

| Tool | Effort | Priority | Dependencies |
|---|---|---|---|
| `ghost_headers` | 1 day (~150 lines) | **P1** | None — single HTTP request |
| `ghost_cert` grading upgrade | 1 day (~100 lines) | **P1** | Existing module |
| `ghost_dns` | 2 days (~250 lines) | **P2** | `dnspython` pip package |
| `ghost_scan` (Tier 2) | 5+ days | **P3 / Out of scope** | ZAP Docker or StackHawk API |

---

## Key Insight

GhostMCP's passive security tools would compete with:
- SecurityHeaders.com (headers only)
- Mozilla Observatory (headers + TLS + cookies)
- SSL Labs (TLS only)
- MXToolbox (DNS/email only)

But we'd combine all of them into a single toolset callable by an AI agent. That's the value — not replacing any one of these, but having *all* of them available in one place during an agent's workflow.
