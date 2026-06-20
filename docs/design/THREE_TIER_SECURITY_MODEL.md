# GhostMCP / ForensicsMCP: Three-Tier Security Assessment Model

**Date:** 2026-06-19
**Purpose:** Define the complete three-tier model from passive recon through active red team testing, with clear legal/authorization boundaries at each tier.

---

## Tier Architecture Overview

```
Tier 1 — PASSIVE RECON (GhostMCP)
  No authorization needed. Read publicly-advertised information.
  Legal against any target. Same traffic as visiting the site.
    │
    │ operator provides credentials + authorization acknowledgment
    ▼
Tier 2 — AUTHENTICATED DISCOVERY (GhostMCP + auth context)
  Authorized login. Walk the API as a legitimate user.
  Requires: credentials + scope document / ownership / bug bounty.
    │
    │ operator explicitly opts into active testing
    ▼
Tier 3 — ACTIVE RED TEAM (ForensicsMCP)
  Send attack payloads, fuzz, inject, escalate.
  Requires: explicit pen test authorization + scope document.
  Automated OWASP API Top 10 + cloud + identity + supply chain + AI.
```

---

## Tier 1 — Passive Recon (GhostMCP)

**Authorization:** None required
**Legal basis:** Public information observation
**Traffic profile:** 1 HTTP GET + DNS queries + 1 TLS handshake per target

| Tool | What It Does |
|---|---|
| `ghost_headers` | Security header grading, server fingerprinting, cookie analysis, CORS policy |
| `ghost_dns` | All DNS record types via DoH, email security (SPF/DKIM/DMARC), dangling CNAMEs, service discovery from TXT tokens |
| `ghost_cert` | TLS grading, JARM fingerprinting, mTLS detection, ALPN, OCSP, ECH |
| `ghost_api` | Fetch published API specs (Swagger, GraphQL introspection, robots.txt, well-known paths, OIDC discovery) |
| `ghost_subdomains` | Certificate Transparency + DNS brute force |
| `ghost_recon` | Dorking-based infrastructure discovery |

**The line:** We only read paths the target explicitly publishes. We never guess paths, send payloads, or attempt authentication.

---

## Tier 2 — Authenticated Discovery (Authorized)

**Authorization:** Valid credentials + one of: ownership / pen test scope / bug bounty program
**Legal basis:** Authorized use of the system
**Traffic profile:** Normal authenticated API usage (same as any legitimate user)

### What Unlocks With a Login

#### API Surface Expansion

| Capability | What You See | Value |
|---|---|---|
| **Authenticated OpenAPI/Swagger** | Admin endpoints, internal routes hidden from public docs | Often 2-3x more endpoints visible after auth |
| **Full GraphQL schema** | Mutations blocked for anonymous (user mgmt, data export, config) | Full attack surface for BOLA/BFLA testing |
| **Role-based endpoint mapping** | Compare admin vs user vs guest — what returns 200 vs 403 | Privilege escalation surface map |
| **Internal API documentation** | `/admin/api-docs`, `/internal/docs` | Developer-facing docs not meant for public |
| **WebSocket endpoints** | Often require auth to upgrade | Real-time API surface — chat, notifications, streaming |
| **Server-Sent Events** | Auth-gated streaming | Event schemas, internal event types |
| **API versioning** | Old/deprecated versions often still accessible to authed users | Legacy attack surface |

#### Infrastructure (with VPN/internal access)

| Capability | What You See | Value |
|---|---|---|
| **Internal DNS zones** | Internal hostnames, service discovery | Microservice topology, database servers, internal tools |
| **Service mesh catalog** | Consul/Envoy/Istio service listing | Complete service-to-service dependency map |
| **Cloud metadata** | IAM roles, instance profiles, security groups | Cloud posture from inside |
| **Kubernetes API** | Namespaces, services, ingress, RBAC | Container orchestration attack surface |
| **Container registry** | All deployed images, tags, layers | Full software inventory |

#### Proposed Tool: `ghost_auth_scan`

```
Input:
  target: URL
  auth_type: "bearer" | "basic" | "cookie" | "oauth2" | "api_key"
  credentials: token/user:pass/cookie value (per-scan, never stored)
  authorization: "i_own_this" | "authorized_pentest" | "bug_bounty"

Output:
  authenticated_endpoints: 87 (vs 34 unauthenticated)
  new_endpoints_found: 53
  role_analysis:
    your_role: "user" (from JWT claims or API response)
    endpoints_accessible: 64
    endpoints_forbidden: 23 (exist but return 403)
  schema_diff:
    public_spec: 34 endpoints
    authenticated_spec: 87 endpoints
    hidden_endpoints: 53
  sensitive_findings:
    - /api/v2/debug/config returns 200 (debug endpoint in production)
    - /api/v2/admin/users returns user list with emails (PII)
    - /api/v2/export/all-data (bulk data export endpoint)
```

**Safety controls:**
- Credentials accepted per-scan, NEVER persisted
- Authorization acknowledgment logged to audit trail
- Read-only — no mutations, no writes, no deletes at Tier 2
- Only enumerates — does not attempt to exploit what it finds

---

## Tier 3 — Active Red Team (ForensicsMCP)

**Authorization:** Explicit penetration test agreement + scope document
**Legal basis:** Written authorization from target owner
**Traffic profile:** Attack payloads, fuzzing, injection, credential testing

### 3.1 OWASP API Security Top 10 (2023) — Automated Testing

| # | Vulnerability | Automated Test Approach |
|---|---|---|
| **API1** | Broken Object Level Authorization (BOLA) | Multi-identity replay: request object A as user B. Detect 200 with data = BOLA confirmed. |
| **API2** | Broken Authentication | JWT manipulation (alg:none, key confusion, expired token replay), MFA bypass, session fixation |
| **API3** | Broken Object Property Level Authorization | Over-posting: add fields not in UI (role, is_admin, price). Detect if server accepts them. |
| **API4** | Unrestricted Resource Consumption | Controlled stress: large payloads, deep JSON nesting, missing pagination enforcement |
| **API5** | Broken Function Level Authorization (BFLA) | Access admin endpoints as regular user. Map role→function access matrix. |
| **API6** | Unrestricted Access to Sensitive Business Flows | Automate financial flows (transfer→approve→execute), bypass step ordering, remove CAPTCHA |
| **API7** | Server-Side Request Forgery (SSRF) | Inject internal URLs (127.0.0.1, cloud metadata endpoints) in URL/hostname parameters |
| **API8** | Security Misconfiguration | Stack traces, debug endpoints, verbose errors, default credentials, weak TLS |
| **API9** | Improper Inventory Management | Compare discovered endpoints vs documented. Flag shadow/deprecated APIs. |
| **API10** | Unsafe Consumption of APIs | Mock malicious upstream responses. Detect injection/crash from trusted third-party data. |

### 3.2 Cloud-Specific Attack Modules

| Module | What It Tests | Attack Technique |
|---|---|---|
| **AWS IAM Escalation** | IAM policy analysis → privilege escalation paths | Assume-role chains, STS token abuse, cross-account roles |
| **SSRF → Cloud Metadata** | Endpoints accepting URLs → internal metadata | IMDSv1 (169.254.169.254), IMDSv2 (token required), Azure IMDS, GCP metadata |
| **S3 Bucket Misconfiguration** | Public/authenticated bucket access | List, read, write, ACL manipulation on discovered buckets |
| **Azure Entra ID Enumeration** | Tenant + user enumeration | OAuth error-based enumeration, user existence via login.microsoftonline.com |
| **GCP Service Account Abuse** | Service account key exposure | Key file discovery, impersonation, cross-project access |
| **Kubernetes Attack Paths** | RBAC misconfiguration, pod escape | Service account token abuse, mount hostPath, privileged containers |
| **Lambda/Functions Abuse** | Serverless privilege escalation | Event injection, environment variable extraction, timeout-based data exfil |
| **Container Escape** | Container boundary testing | /proc/1/root access, cgroup escape, Docker socket exposure |

### 3.3 Identity & Authentication Attacks

| Module | What It Tests | Technique |
|---|---|---|
| **JWT Manipulation** | Token validation strength | Algorithm confusion (RS256→HS256), none attack, claim tampering, kid injection |
| **OAuth Flow Abuse** | OAuth implementation correctness | Authorization code interception, redirect_uri manipulation, scope escalation, PKCE bypass |
| **SAML Attacks** | SAML signature validation | XML signature wrapping, assertion replay, comment injection |
| **Session Management** | Session security | Fixation, prediction, concurrent sessions, post-logout token validity |
| **Credential Stuffing** | Login endpoint resilience | Cross-reference with breach databases (we already have ghost_breach) to test leaked creds |
| **Password Spraying** | Account lockout effectiveness | Controlled spray against discovered usernames (from Tier 2 enumeration) |
| **Kerberoasting** | AD service account security | Request service tickets, offline crack attempt |
| **AS-REP Roasting** | AD pre-authentication | Identify accounts without pre-auth, request AS-REP for offline cracking |
| **LDAP Enumeration** | Directory exposure | Anonymous bind, user/group enumeration, password policy extraction |
| **MFA Bypass** | MFA implementation robustness | Recovery code brute force, SMS intercept, push fatigue simulation |

### 3.4 Supply Chain Attack Simulation

| Module | What It Tests | Technique |
|---|---|---|
| **Dependency Confusion** | Package manager security | Publish higher-version package to public registry with same name as internal package |
| **Typosquatting Detection** | Package name vigilance | Generate typosquat names for target's dependencies, check if any are registered |
| **SBOM/Lockfile Analysis** | Known vulnerable components | Parse package-lock.json/requirements.txt/go.sum → CVE mapping |
| **CI/CD Pipeline Audit** | Pipeline security | Enumerate GitHub Actions/GitLab CI permissions, secret exposure, self-hosted runner risks |
| **Artifact Integrity** | Build provenance | Check for unsigned artifacts, missing SLSA provenance, reproducible build verification |
| **Malicious Dependency Injection** | Supply chain resilience | Simulate compromised dependency (in controlled lab) → trace blast radius |

### 3.5 AI/LLM Security Testing

| Module | What It Tests | Technique |
|---|---|---|
| **Prompt Injection** | Instruction override resistance | Direct injection (override system prompt), indirect (poisoned context/RAG sources) |
| **Jailbreaking** | Safety filter robustness | Role-play, encoding (base64, ROT13), multi-step reasoning, language switching |
| **Data Exfiltration** | Training data exposure | Memorization probing, divergence attacks, verbatim extraction attempts |
| **Context Leakage** | Multi-tenant isolation | Cross-conversation context bleeding, system prompt extraction |
| **Agent Permission Testing** | Tool-use safety boundaries | Instruct agent to escalate from read-only to write operations, chain tools unexpectedly |
| **Safety Bypass Measurement** | Quantified safety posture | Run N attack patterns, measure success rate, generate "safety score" |

### 3.6 Network & Protocol Attacks

| Module | What It Tests | Technique |
|---|---|---|
| **DNS Rebinding** | Same-origin policy bypass | Point DNS at internal IPs after initial resolution |
| **HTTP Request Smuggling** | Proxy/server desync | CL.TE, TE.CL, TE.TE payload variations |
| **WebSocket Hijacking** | WS auth/origin validation | Cross-site WebSocket hijacking, origin spoofing |
| **HTTP/2 Specific** | HTTP/2 implementation | CONTINUATION flood, HPACK bombing, stream multiplexing abuse |
| **Cache Poisoning** | CDN/proxy cache integrity | Host header injection, cache key manipulation, web cache deception |
| **Subdomain Takeover (active)** | Actually claim dangling subdomain | Register service at dangling CNAME target, serve content (with authorization) |

---

## Safety Architecture for Tier 3

### Mandatory Controls

| Control | Implementation |
|---|---|
| **Authorization gate** | Tool REFUSES to run without explicit authorization acknowledgment |
| **Scope enforcement** | Only test domains/IPs explicitly listed in scope |
| **Credential handling** | Accept per-scan, never persist, wipe from memory after scan completes |
| **Rate limiting** | Respect target's rate limits, configurable max RPS |
| **Kill switch** | Immediate scan termination capability |
| **Audit logging** | Every request logged with timestamp, target, technique, authorization |
| **Safe mode** | Default to detection-only (report what WOULD work without actually exploiting) |
| **Scope warning** | Alert if a discovered link/redirect would leave the authorized scope |
| **Data handling** | Any PII/credentials discovered during testing are encrypted in the report |
| **Cleanup** | Tool tracks all changes made (accounts created, data modified) for post-test cleanup |

### Authorization Model

```python
class Authorization:
    type: str       # "i_own_this", "authorized_pentest", "bug_bounty"
    scope: list     # domains/IPs authorized for testing
    rules_of_engagement: dict  # {max_rps, no_dos, no_data_destruction, testing_hours}
    scope_document: str | None  # path to signed scope doc
    acknowledged_at: str       # ISO timestamp of operator acknowledgment
    operator: str              # who initiated the test
```

---

## What Makes This Different From Existing Tools

| Gap in Current Tools | How We Fill It |
|---|---|
| **Burp/ZAP are HTTP-only** | Cloud IAM + identity + supply chain + AI modules |
| **Cobalt Strike is post-exploitation only** | Full kill chain: recon → discovery → exploitation |
| **Nuclei is stateless/template-driven** | Stateful multi-identity workflows, business logic testing |
| **No tool unifies cloud + API + identity** | Single attack-graph engine across all surfaces |
| **No tool tests AI/LLM systems** | Prompt injection, jailbreak, agent permission testing |
| **Most tools are one-shot** | Continuous validation (run regularly, track drift) |
| **Results lack context** | Attack-path-aware prioritization ("this matters because...") |

---

## Implementation Priority

| Phase | Scope | Effort | Dependencies |
|---|---|---|---|
| **Tier 1** (now) | ghost_headers, ghost_dns, ghost_cert upgrade, ghost_api | 7-10 days | None (httpx only) |
| **Tier 2** (next) | ghost_auth_scan — authenticated API walking | 5-7 days | Tier 1 complete |
| **Tier 3 Phase A** | OWASP API Top 10 automated testing | 15-20 days | Tier 2 complete |
| **Tier 3 Phase B** | Cloud attack modules (AWS/Azure/GCP) | 15-20 days | Cloud SDK access |
| **Tier 3 Phase C** | Identity attacks (JWT, OAuth, SAML, AD) | 10-15 days | Identity provider access |
| **Tier 3 Phase D** | Supply chain + AI/LLM testing | 10-15 days | CI/CD + LLM access |

**Total Tier 3:** ~50-70 days of development. This is ForensicsMCP, not GhostMCP.

---

## Key Principle

> **GhostMCP finds things. ForensicsMCP tests them. Unimind remembers everything.**
>
> The three systems are complementary:
> - GhostMCP (Tier 1): "Here's what's exposed"
> - ForensicsMCP (Tier 2-3): "Here's what's exploitable"
> - Unimind: "Here's what we learned, and here's what changed since last time"
