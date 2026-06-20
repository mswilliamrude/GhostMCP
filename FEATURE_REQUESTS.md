
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
