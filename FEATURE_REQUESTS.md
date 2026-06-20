
## Feature Request: `ghost_render` — Headless Browser Rendering + JS Console Capture

### Problem
When developing SPAs (Single Page Applications) with frameworks like Vue, React, or Angular, the raw HTML contains template directives (`v-if`, `v-for`, `{{}}`) that only resolve after JavaScript executes. Current `ghost_fetch` returns the raw HTML, which is useless for diagnosing:

- Whether the JS framework successfully mounted
- Runtime JavaScript errors (ReferenceError, TypeError, etc.)
- Which Vue/React components rendered vs failed
- Console errors/warnings from the application
- The actual DOM state after client-side rendering

This makes it impossible for an AI coding agent to debug frontend issues without the user manually opening browser DevTools and reporting back.

### Proposed Solution

#### `ghost_render` tool
```
Parameters:
  url: string          — URL to load
  wait: int            — milliseconds to wait for JS execution (default 5000)
  execute: string      — optional JS to run after page loads
  extract: string      — "dom" (rendered HTML), "console" (console output), "both"
  screenshot: bool     — return a screenshot of the rendered page

Returns:
  rendered_html: string  — the DOM after JS execution (what the user actually sees)
  console_log: string[]  — all console.log/warn/error output
  js_errors: string[]    — uncaught errors, unhandled promise rejections
  title: string          — document.title after render
  screenshot: bytes      — optional PNG screenshot
```

#### Implementation
Use Playwright or Puppeteer (headless Chromium) behind the paranoia proxy chain:
- `casual`: direct headless Chrome
- `cautious`: headless + random user-agent
- `ghost`/`midnight`: headless through proxy/Tor

#### Use Cases

1. **SPA Debugging**: Fetch a Vue/React page, get the rendered DOM instead of template syntax. Immediately see if the framework mounted successfully.

2. **JS Error Detection**: The #1 reason Vue/React fails silently is a JavaScript error during setup. `ghost_render` captures `console.error` and `window.onerror` — the AI agent can read the exact error message and stack trace without the user needing DevTools.

3. **Visual Regression**: Screenshots let the agent compare what the page looks like before/after a change.

4. **Form Interaction Testing**: `execute` parameter allows filling forms, clicking buttons, and checking the result — basic E2E testing without Selenium/Cypress setup.

5. **CSP/CORS Detection**: Some pages block JS execution via Content Security Policy. `ghost_render` would surface these as errors in `js_errors`.

### Real-World Example
We're building a ZCS-replacement webmail with Vue 3 (no build step, CDN). After 20+ agent edits, the 3800-line app.js has an invisible bug that prevents Vue from mounting. `ghost_fetch` returns raw `{{ }}` templates. With `ghost_render`, we'd get either:
- The rendered page (Vue mounted successfully), OR
- The exact console error: "Uncaught ReferenceError: xxx is not defined at app.js:1234"

That single piece of information would save hours of debugging.

### Priority: HIGH
This is the single biggest gap in the AI-assisted frontend development workflow. Every other tool works great for backend/API work. Frontend debugging is flying blind without it.

---
Filed by: OpenCode agent during NewHotness webmail development session
Date: 2026-06-17

---

## Feature Request: Passive Security Assessment Tools (Tier 1 DAST-Adjacent)

### Problem
GhostMCP currently identifies infrastructure (subdomains, certs, tech stack) but doesn't assess the *security posture* of what it finds. An agent doing recon can find a website but can't tell you "this site has no CSP, no HSTS, serves CORS headers to everyone, and has a misconfigured SPF record" without active exploitation.

These checks are **passive** — a single HTTP request or DNS lookup — and require NO authorization from the target. They observe publicly-advertised security policies, not vulnerabilities.

### Proposed Tools

#### `ghost_headers` — Security Header Analysis & Grading
```
Input: URL
Output: {
  grade: "A" | "B" | "C" | "D" | "F",
  headers_present: {
    strict_transport_security: {value, rating, recommendation},
    content_security_policy: {value, rating, recommendation},
    x_frame_options: {value, rating, recommendation},
    x_content_type_options: {value, rating, recommendation},
    referrer_policy: {value, rating, recommendation},
    permissions_policy: {value, rating, recommendation},
    cors: {value, rating, recommendation},
  },
  headers_missing: [list of recommended headers not set],
  warnings: [specific issues — "CSP uses unsafe-inline", "HSTS max-age too low"],
  raw_headers: {full response headers},
}
```
**Effort:** ~150 lines, 1 day
**Legal:** Fully passive — single GET request, reads publicly-served headers

#### `ghost_dns` — DNS Security & Misconfiguration Checks
```
Input: domain
Output: {
  spf: {record, valid, issues},
  dkim: {selector_found, valid},
  dmarc: {record, policy, issues},
  dnssec: {enabled, valid},
  zone_transfer: {vulnerable: bool},
  dangling_cnames: [{subdomain, cname_target, status}],
  mx_records: [{priority, host, supports_tls}],
  nameservers: [list],
  caa_records: [list],
}
```
**Effort:** ~250 lines, 2 days
**Legal:** All DNS lookups are passive public queries

#### `ghost_cert` upgrades — SSL/TLS Grading
Enhance existing `ghost_cert` with:
- Letter grade (A/B/C/D/F like SSL Labs)
- Protocol version warnings (TLS 1.0/1.1 deprecated)
- Weak cipher detection
- Certificate transparency log check
- HPKP/CAA policy validation

**Effort:** ~100 lines added to existing module, 1 day
**Legal:** Already implemented — just adding grading logic

### Priority: MEDIUM
These are natural extensions of existing recon tools. Low effort, high value for security assessments. All passive and legal against any target.

### Research References
- See `docs/research/DAST_SECURITY_SCANNING.md` for full landscape analysis
- SecurityHeaders.com (free online header checker — our competition)
- Mozilla Observatory (free, open source — grades headers)
- SSL Labs (Qualys — the gold standard for TLS grading)

---
Filed by: OpenCode agent during GhostMCP v0.4.0 session
Date: 2026-06-19

---

## Feature Request: `ghost_api` — Passive API Surface Discovery (Tier 1)

### Problem
During reconnaissance, knowing that a target runs an API is only half the picture. The full API schema — endpoints, methods, parameters, authentication requirements — is often publicly available via standard discovery paths (Swagger, OpenAPI, GraphQL introspection, OIDC discovery). Currently GhostMCP can find subdomains and tech stack but can't tell an agent "this site has 34 API endpoints, uses Auth0 for auth, runs FastAPI, and has GraphQL introspection wide open."

### Proposed Solution

#### `ghost_api` — Passive API Discovery
```
Input: URL (base URL of target)
Output: {
  openapi_spec: full parsed spec if found (endpoints, methods, params, models),
  graphql_schema: type system if introspection enabled,
  robots_txt: allowed/disallowed paths,
  security_txt: contact, policy, encryption,
  oidc_config: auth provider + token endpoints,
  framework: identified framework + evidence,
  cors_policy: origin/credentials/methods analysis,
  api_versions: active vs deprecated versions,
  sensitive_paths: debug endpoints, admin panels from robots.txt,
  endpoints_discovered: total count,
}
```

#### What It Checks (all Tier 1 — published paths only)
- ~16 common OpenAPI/Swagger paths
- GraphQL introspection query
- `/robots.txt` and `/sitemap.xml`
- `/.well-known/openid-configuration`, `/.well-known/security.txt`
- CORS preflight (OPTIONS request)
- WSDL endpoints
- Framework fingerprinting from error response format

#### What It Does NOT Do (Tier 2 — requires authorization)
- No path brute-forcing / forced browsing
- No parameter fuzzing
- No credential testing
- No method tampering
- No rate limit probing

#### Why This Is Passive
Every path we check is something the target explicitly publishes for API consumers. Fetching `/swagger.json` is identical to what any developer does when integrating with the API. GraphQL introspection is a built-in feature, not an exploit — if it's on, they chose to leave it on.

### Effort: ~2 days (~300 lines)
### Dependencies: None (httpx only)
### Priority: MEDIUM

### Research Reference
- See `docs/research/TIER1_EXPANDED_PASSIVE_INTELLIGENCE.md` Section 10

---
Filed by: OpenCode agent during GhostMCP v0.4.0 session
Date: 2026-06-19

---

## Feature Request: Active DAST Scanning (Tier 2 — Out of Scope Without Authorization)

### IMPORTANT: Legal & Ethical Constraints

**Active DAST scanning sends attack payloads (SQL injection, XSS, path traversal, etc.) to the target. This is ONLY legal when:**
1. You own the target, OR
2. You have explicit written authorization from the target owner (scope document, bug bounty program, pen test agreement)

**Unauthorized active scanning is illegal under CFAA (US), Computer Misuse Act (UK), and equivalent laws worldwide. GhostMCP MUST enforce authorization acknowledgment before executing any active scan.**

### Proposed Design (Future / ForensicsMCP Territory)

#### `ghost_scan` — Orchestrated DAST Scanning
```
Input: {
  target: URL,
  authorization: "i_own_this" | "authorized_pentest" | "bug_bounty",
  scan_type: "baseline" | "full" | "api",
  api_spec: (optional OpenAPI/Swagger URL),
}
Output: {
  job_id: string,
  status: "queued" | "running" | "complete",
  estimated_time: "15 min",
}

# Then poll for results:
Input: {job_id}
Output: {
  findings: [{severity, confidence, url, evidence, cwe_id, description, remediation}],
  scan_duration: "12 min",
  requests_sent: 4521,
  alerts_by_severity: {high: 2, medium: 5, low: 12, info: 34},
}
```

#### Implementation Options
| Option | Pros | Cons |
|---|---|---|
| **ZAP Docker sidecar** | Full DAST, free, we have Docker infra | Heavy (~1GB image), slow startup |
| **Nuclei in container** | Lightweight, fast, template-based | Less thorough than ZAP for logic bugs |
| **StackHawk API** | Hosted, no infra to manage, built on ZAP | Paid ($), another API key |
| **Burp Suite Enterprise API** | Gold standard accuracy | Expensive ($8K+/yr) |

#### Safety Controls Required
1. **Authorization prompt** — tool MUST require explicit acknowledgment before scanning
2. **Scope enforcement** — only scan the specified domain, no following external links
3. **Rate limiting** — respect robots.txt, limit concurrent requests
4. **Audit logging** — log every scan with target, time, authorization claim, who initiated
5. **Kill switch** — ability to stop a running scan immediately
6. **No credential storage** — if auth is needed, accept it per-scan, never persist

### Priority: LOW (future / out of scope for current GhostMCP)
This belongs in a separate project (ForensicsMCP) or behind a very explicit "I know what I'm doing" gate. GhostMCP's identity is passive OSINT, not active exploitation.

### Relationship to GhostMCP
```
GhostMCP (passive) ──finds──> targets, tech stacks, exposed surfaces
         │
         ▼
ForensicsMCP (active) ──tests──> specific vulns with authorization
         │
         ▼
Unimind (memory) ──remembers──> findings, remediations, patterns
```

---
Filed by: OpenCode agent during GhostMCP v0.4.0 session
Date: 2026-06-19

---

## Feature Request: `ghost_auth_session` — Ephemeral Session-Scoped Authentication

### Problem
GhostMCP's Tier 1 tools are passive — they read publicly-advertised information. But for web development workflows, developers need an agent that can **log into their own application** and test authenticated pages: check security headers behind login walls, validate API responses for authenticated users, capture console errors in protected SPAs, and verify that access controls work correctly.

Currently, Ghost has no concept of authentication. A developer can't say "log into my staging app at localhost:3000 and check all the pages."

### Proposed Design

Authentication is **session-scoped and ephemeral** — credentials exist only in memory for the duration of the MCP session, are never persisted to disk/database/logs, and are wiped on disconnect.

#### `ghost_auth_session` — Create Ephemeral Auth Session
```
Input: {
  url: string,                    # Login page or API endpoint
  method: "form" | "bearer" | "cookie" | "basic" | "oauth2",
  credentials: {                  # Method-specific
    # form: {username_field, password_field, username, password, submit_selector}
    # bearer: {token}
    # cookie: {name, value}
    # basic: {username, password}
    # oauth2: {client_id, client_secret, token_url, scopes}
  },
  scope: "read_only" | "interactive",  # What the session is allowed to do
  ttl_minutes: 30,                # Auto-wipe timer (default 30, max 120)
  origin_lock: "localhost:3000",  # Session ONLY works for this origin
}

Output: {
  session_id: string,           # Ephemeral in-memory reference
  auth_type: "cookie" | "bearer" | "basic",
  origin: "localhost:3000",
  expires_at: "2026-06-20T14:30:00Z",
  status: "authenticated",
  # NEVER echoes credentials back
}
```

#### Integration with Existing Tools
Once a session exists, existing Ghost tools accept an optional `session` parameter:

```python
ghost_render(url="/dashboard", session=session_id)
# → Renders authenticated page, returns DOM + console + network requests

ghost_headers(url="/api/users", session=session_id)
# → Checks security headers on authenticated endpoints

ghost_api(url="http://localhost:3000", session=session_id)
# → Discovers authenticated vs unauthenticated API surface diff
# → "53 endpoints visible after auth vs 34 without"

ghost_fetch(url="/api/me", session=session_id)
# → Fetches authenticated API response
```

### Safety Controls

| Control | Implementation |
|---|---|
| **Memory-only storage** | Python dict, never serialized, never written to disk/DB/log |
| **Auto-expiry TTL** | Session auto-wipes after TTL (default 30 min) even if client doesn't disconnect |
| **Origin lock** | Auth for `localhost:3000` cannot be used against `api.production.com` |
| **No credential echo** | `ghost_auth_session` returns session metadata but NEVER returns credentials |
| **No Unimind storage** | Auth sessions are explicitly excluded from knowledge assimilation |
| **Session listing** | `ghost_auth_sessions()` returns active session count/origins but no credentials |
| **Manual wipe** | `ghost_auth_destroy(session_id)` for immediate cleanup |
| **Disconnect cleanup** | All sessions destroyed when MCP client disconnects |

### Use Cases

1. **Web Development QA** — "Log into my staging app and check all pages for console errors, missing headers, and broken links"
2. **Authenticated API Testing** — "Log in as a regular user and tell me what API endpoints are visible vs what admin sees"
3. **SPA Debugging Behind Auth** — "My Vue app works on the login page but breaks after login — render the dashboard and show me the console errors"
4. **Access Control Validation** — "Log in as user A, check what /api/users returns, then log in as user B and compare"
5. **Visual Regression** — "Screenshot every authenticated page before and after this deploy"
6. **Security Header Audit** — "Check if authenticated pages have the same CSP/HSTS as public pages"

### Architecture Notes

- Sessions live in a `dict[str, AuthSession]` on the MCP server process
- `AuthSession` dataclass holds: auth_type, cookies/headers (encrypted in memory), origin_lock, created_at, expires_at
- When a tool receives `session=session_id`, it injects the stored auth headers/cookies into its httpx/Playwright request
- For `ghost_render`, the Chromium browser context gets the session cookies set via CDP
- **No changes to existing tool signatures** when used without auth — `session` parameter is always optional

### Effort: ~3 days (~400 lines)
- Session manager class (~100 lines)
- Auth method handlers (form login via Playwright, bearer/cookie/basic injection) (~150 lines)
- Integration hooks in ghost_render, ghost_headers, ghost_fetch, ghost_api (~100 lines)
- Tests (~50 lines)

### Priority: MEDIUM
Significant UX improvement for web developers. Keeps Ghost as one MCP with a clean internal boundary between authenticated and unauthenticated operation.

### Dependencies
- `ghost_render` (existing — Playwright/Chromium)
- No new pip dependencies

---
Filed by: OpenCode agent
Date: 2026-06-20

---

## Feature Request: `ghost_asn` — BGP / ASN / Network Infrastructure Reconnaissance

### Problem
During organizational reconnaissance, understanding a target's network infrastructure is critical: which Autonomous System Numbers (ASNs) they operate, what IP prefixes they announce via BGP, who their upstream peers are, what Internet Exchange Points (IXPs) they connect to, and what other organizations share their network infrastructure. This information reveals the full scope of an organization's internet presence — far beyond what DNS alone shows.

Currently `ghost_ip` provides geolocation and ISP/ASN info for a single IP, but can't answer "what is the full network footprint of this organization?"

### Proposed Solution

#### `ghost_asn` — ASN & BGP Infrastructure Lookup
```
Input: {
  query: string,        # ASN number (e.g., "AS15169"), org name ("Google"), or IP address
  query_type: "asn" | "org" | "ip",   # auto-detected if omitted
}

Output: {
  asn: {
    number: 15169,
    name: "GOOGLE",
    description: "Google LLC",
    country: "US",
    rir: "ARIN",                    # Regional Internet Registry
    allocation_date: "2000-03-30",
  },
  prefixes_v4: [
    {prefix: "8.8.8.0/24", name: "Google DNS", description: "..."},
    {prefix: "142.250.0.0/15", name: "Google services", ...},
    # ... all announced IPv4 prefixes
  ],
  prefixes_v6: [...],              # IPv6 prefixes
  prefix_count: {v4: 847, v6: 512},
  peers: {
    upstream: [{asn: 6939, name: "Hurricane Electric", ...}],
    downstream: [{asn: 36040, name: "YouTube", ...}],
    peer_count: {upstream: 12, downstream: 234},
  },
  ix_presence: [                   # Internet Exchange Points
    {ix: "AMS-IX", city: "Amsterdam", speed: "400G"},
    {ix: "DE-CIX", city: "Frankfurt", speed: "400G"},
  ],
  related_asns: [                  # Other ASNs by same org
    {asn: 36040, name: "YouTube"},
    {asn: 396982, name: "Google Cloud"},
  ],
  abuse_contact: "network-abuse@google.com",
  investigation_urls: {
    bgpview: "https://bgpview.io/asn/15169",
    ripestat: "https://stat.ripe.net/AS15169",
    he_bgp: "https://bgp.he.net/AS15169",
    peeringdb: "https://www.peeringdb.com/asn/15169",
  }
}
```

### What This Enables for Recon

| Use Case | How ghost_asn Helps |
|---|---|
| **Full org footprint** | "Show me every IP range Google operates" → reveals infrastructure beyond DNS |
| **Subsidiary discovery** | Related ASNs reveal acquisitions, subsidiaries, cloud tenants |
| **Hosting identification** | IP → ASN mapping reveals if target uses AWS, Azure, GCP, or self-hosts |
| **Peering analysis** | Upstream/downstream peers reveal network dependencies and transit paths |
| **IX presence** | Where they physically interconnect — geographic footprint of infrastructure |
| **IP attribution** | "Does this suspicious IP belong to the target org or a third party?" |
| **Scope validation** | During authorized testing, confirm which IP ranges belong to the target |

### Free APIs (No Authentication Required)

| API | Endpoints | Rate Limit | Data |
|---|---|---|---|
| **BGPView** | `/asn/{asn}`, `/asn/{asn}/prefixes`, `/asn/{asn}/peers`, `/asn/{asn}/ixs`, `/ip/{ip}`, `/search?query_term={org}` | ~100 req/min (undocumented) | ASN details, prefixes, peers, IXPs |
| **RIPEstat** | `/data/as-overview/data.json`, `/data/announced-prefixes/data.json`, `/data/asn-neighbours/data.json` | Fair use (no hard limit) | Comprehensive RIR data, historical |
| **PeeringDB** | `/api/net?asn={asn}` | Generous (API key optional) | IX presence, peering policies, facility info |
| **Team Cymru** | DNS-based: `dig +short AS15169.asn.cymru.com TXT` | Unlimited (DNS) | Lightweight ASN/prefix origin lookups |

**Recommended primary:** BGPView (richest free API, JSON, no auth)
**Recommended fallback:** RIPEstat (authoritative RIR data, more conservative)
**Recommended enrichment:** PeeringDB (IX/facility info BGPView doesn't have)

### Implementation

```python
# Primary: BGPView API (https://bgpview.docs.apiary.io/)
async def _bgpview_asn(asn: int) -> dict:
    r = await httpx_client.get(f"https://api.bgpview.io/asn/{asn}")
    prefixes = await httpx_client.get(f"https://api.bgpview.io/asn/{asn}/prefixes")
    peers = await httpx_client.get(f"https://api.bgpview.io/asn/{asn}/peers")
    ixs = await httpx_client.get(f"https://api.bgpview.io/asn/{asn}/ixs")
    # Merge and format

# IP → ASN lookup
async def _ip_to_asn(ip: str) -> dict:
    r = await httpx_client.get(f"https://api.bgpview.io/ip/{ip}")
    # Returns ASN + prefix for the IP

# Org name → ASN search
async def _search_org(name: str) -> list:
    r = await httpx_client.get(f"https://api.bgpview.io/search?query_term={name}")
    # Returns matching ASNs, IPs, prefixes
```

### Integration with Existing Tools

- `ghost_ip` → already returns ASN; `ghost_asn` expands on that with full prefix/peer/IX data
- `ghost_subdomains` → discovered subdomains can be mapped to ASNs to identify which are self-hosted vs cloud
- `ghost_cert` → certificate SANs can be cross-referenced with ASN prefix ranges
- `ghost_recon` → ASN data enriches the overall organizational recon picture

### Effort: ~2 days (~250 lines)
- BGPView API client (~100 lines)
- RIPEstat fallback (~50 lines)
- PeeringDB enrichment (~50 lines)
- Response formatting and investigation URLs (~50 lines)

### Priority: MEDIUM
High value for organizational recon. Zero cost (free APIs), zero new dependencies (httpx only), zero infrastructure.

### Dependencies: None (httpx only)

---
Filed by: OpenCode agent
Date: 2026-06-20
