# GhostMCP — API Keys & Service Providers Reference

This document catalogs all external services that GhostMCP can integrate with,
organized by category. All services are optional — core functionality works without
any API keys.

---

## Search Engines

| Provider | Env Variable | Free Tier | Sign Up | Used By |
|----------|-------------|-----------|---------|---------|
| **Serper.dev** | `SERPER_API_KEY` | 2,500 queries (one-time) | https://serper.dev | `ghost_search`, `ghost_dork` |
| **Brave Search** | `BRAVE_API_KEY` | 2,000 queries/month | https://brave.com/search/api/ | `ghost_search`, media search |
| **Bing** | `BING_API_KEY` | Limited | Azure portal | `ghost_search` |
| **SearXNG** | None (self-hosted) | Unlimited | Docker Compose | `ghost_searxng` |
| **DuckDuckGo** | None required | Unlimited (scraping) | N/A | `ghost_search`, `ghost_dork` |
| **Google** | None required | Unlimited (scraping, CAPTCHA risk) | N/A | `ghost_search`, `ghost_dork` |

**Auto-fallback chain (API engines first, scrapers last):**
Serper → Brave → Bing → SearXNG → Google → DDG Lite

---

## Threat Intelligence (All Free, No Keys Required)

| Provider | Env Variable | Free Tier | API Endpoint | Used By |
|----------|-------------|-----------|--------------|---------|
| **CIRCL NSRL** | None | Unlimited | `https://hashlookup.circl.lu/` | `ghost_hash` |
| **MalwareBazaar** | None | Unlimited | `https://mb-api.abuse.ch/api/v1/` | `ghost_hash`, `ghost_threat` |
| **ThreatFox** | None | Unlimited | `https://threatfox-api.abuse.ch/api/v1/` | `ghost_hash`, `ghost_threat` |
| **URLhaus** | None | Unlimited | `https://urlhaus-api.abuse.ch/v1/` | `ghost_threat` |
| **Feodo Tracker** | None | Unlimited | `https://feodotracker.abuse.ch/` | `ghost_threat` |
| **RansomWatch** | None | Unlimited | `https://raw.githubusercontent.com/joshhighet/ransomwatch/` | `ghost_threat` |

---

## Vulnerability Intelligence (All Free, No Keys Required)

| Provider | Env Variable | Free Tier | API Endpoint | Used By |
|----------|-------------|-----------|--------------|---------|
| **NVD (NIST)** | None | 5 req/30s (unauthed) | `https://services.nvd.nist.gov/rest/json/cves/2.0` | `ghost_cve` |
| **OSV.dev** | None | Unlimited | `https://api.osv.dev/v1/query` | `ghost_vuln` |
| **EPSS (FIRST)** | None | Unlimited | `https://api.first.org/data/v1/epss` | `ghost_cve` |
| **CISA KEV** | None | Unlimited | `https://www.cisa.gov/sites/.../known_exploited_vulnerabilities.json` | `ghost_cve` |

---

## Optional Paid Services

| Provider | Env Variable | Free Tier | Paid Tier | Used By |
|----------|-------------|-----------|-----------|---------|
| **VirusTotal** | `VT_API_KEY` | 4 req/min | $0+ (community) | `ghost_hash` |
| **Serper.dev** | `SERPER_API_KEY` | 2,500 one-time | $50/mo (10K) | `ghost_search` |
| **Brave Search** | `BRAVE_API_KEY` | 2,000/month | $5/mo (20K) | `ghost_search`, media search |

---

## Future Integrations (Backlog)

### Planned — High Priority

| Provider | Env Variable | Free Tier | Category | Status |
|----------|-------------|-----------|----------|--------|
| **HIBP** | `GHOST_HIBP_KEY` | Single lookups free | Breach monitoring | Backlog |
| **Dehashed** | `DEHASHED_API_KEY` | None ($5/week) | Credential search | Backlog |

### Planned — Medium Priority

| Provider | Env Variable | Free Tier | Category | Status |
|----------|-------------|-----------|----------|--------|
| **Shodan** | `SHODAN_API_KEY` | Limited | Infrastructure/IoT | Backlog |
| **AbuseIPDB** | `ABUSEIPDB_API_KEY` | 1,000/day | IP reputation | Backlog |
| **URLScan.io** | `URLSCAN_API_KEY` | 100/day | URL analysis | Backlog |
| **PhishTank** | `PHISHTANK_API_KEY` | Free (key required) | Phishing detection | Backlog |
| **AlienVault OTX** | `OTX_API_KEY` | Free (key required) | Threat intel feeds | Backlog |

### Planned — Low Priority

| Provider | Env Variable | Free Tier | Category | Status |
|----------|-------------|-----------|----------|--------|
| **LeakIX** | `LEAKIX_API_KEY` | Limited | Exposed services | Backlog |
| **WiGLE** | `WIGLE_API_KEY` | Free (key required) | Wireless OSINT | Backlog |
| **NumVerify** | `NUMVERIFY_API_KEY` | 100/month | Phone validation | Backlog |

### Evaluated — Not Planned

| Provider | Reason | Notes |
|----------|--------|-------|
| **Maltego** | Wrong fit — GUI tool, KG already covers transforms | Our tools ARE the transforms |
| **PimEyes** | Ethical/legal concerns | Face search — risky to include |
| **Epieos** | Fragile scraping, limited value vs HIBP | No public API |

---

## Configuration

> **Public repo — keep secrets out of git.** Store real key values in the
> out-of-tree protected file `~/.protected/ghostmcp.conf` (copied from
> `scripts/ghostmcp.conf.example`), not in tracked files. `build-ghostmcp.sh`
> auto-sources it; for other tooling, `set -a; . ~/.protected/ghostmcp.conf; set +a`.
> The examples below use placeholders — never commit real values.

### Environment Variables (opencode.json)

```json
{
  "mcp": {
    "ghostmcp": {
      "type": "local",
      "command": ["python3", "-m", "ghostmcp"],
      "enabled": true,
      "environment": {
        "PYTHONPATH": "/path/to/GhostMCP",
        "SERPER_API_KEY": "your-serper-key",
        "BRAVE_API_KEY": "your-brave-key",
        "VT_API_KEY": "your-virustotal-key"
      }
    }
  }
}
```

### ghost_client.yaml (Bridge Configuration)

```yaml
server: ws://10.0.10.7:8080/bridge
client_id: my-laptop
ports:
  - 8080
  - 3000
allow_web_access: true
web_access_mode: self_only
locality:
  region: US-TX
  timezone: US/Central
  label: "Austin office"
```

### Docker Container (Environment Variables)

```bash
docker run -d \
  -e GHOST_MODE=server \
  -e SERPER_API_KEY=your-key \
  -e BRAVE_API_KEY=your-key \
  -e VT_API_KEY=your-key \
  ghostmcp:latest
```

### ACI Deployment (build-ghostmcp.sh)

API keys are set in the ACI container group YAML via `environmentVariables`.
For sensitive keys, use `secureValue` instead of `value`:

```yaml
environmentVariables:
  - name: SERPER_API_KEY
    secureValue: "your-key"
  - name: BRAVE_API_KEY
    secureValue: "your-key"
```

---

*Last updated: 2026-06-18 (revised — Brave/Bing/SearXNG shipped, paths + HIBP env var corrected)*
