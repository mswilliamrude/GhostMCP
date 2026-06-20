# GhostMCP Research Documents

> Research papers, competitive analyses, and technical deep-dives supporting GhostMCP's development and feature roadmap.

---

## Table of Contents

| # | Document | Lines | Summary | Created | Modified |
|---|---|---|---|---|---|
| 1 | [TOP_SECURITY_FINDINGS_BY_TIER.md](TOP_SECURITY_FINDINGS_BY_TIER.md) | 1,101 | **Top 30 Security Findings by Assessment Tier** — 10 findings per tier (passive, authenticated, red team) with real-world incidents, MITRE ATT&CK/CWE/OWASP mappings, detailed TTPs, and GhostMCP detection coverage matrix. Validated against 18 Brave Search queries and 27 Perplexity citations. Covers British Airways Magecart, Equifax Struts, Capital One SSRF, xz Utils backdoor, Ivanti zero-days, and 24 more incidents (2017-2026). | 2026-06-20 | 2026-06-20 |
| 2 | [TIER1_EXPANDED_PASSIVE_INTELLIGENCE.md](TIER1_EXPANDED_PASSIVE_INTELLIGENCE.md) | 1,083 | **Expanded Tier 1 Passive Intelligence** — Full passive security assessment capabilities: JARM fingerprinting, mTLS detection, DNS-over-HTTPS implementation, subdomain takeover detection (14 platforms), header grading methodology, CT intelligence, and API discovery (Tier 1 vs Tier 2 boundary). Zero new pip dependencies — everything via httpx + stdlib. | 2026-06-20 | 2026-06-20 |
| 3 | [BEENVERIFIED_ALTERNATIVE.md](BEENVERIFIED_ALTERNATIVE.md) | 675 | **BeenVerified Alternative Analysis** — 8 data categories, 33 vendor comparison across people-search landscape. Breach data as accelerator ($31/mo HIBP + Snusbase closes half the gap to $5K/mo data broker licensing). Hunter.io as Pro tier bottleneck (500/mo cap). API pricing tiers and accuracy ratings. | 2026-06-18 | 2026-06-18 |
| 4 | [GHOSTMCP_PEOPLE_SEARCH_TIERS.md](GHOSTMCP_PEOPLE_SEARCH_TIERS.md) | 614 | **People Search Tiers** — 10 search types x 5 spending tiers matrix. Maps free → $5/mo → $31/mo → $100/mo → enterprise tiers against phone, email, username, people, VIN, court, breach, and report capabilities. API rate limits, accuracy ratings, and data freshness per tier. | 2026-06-18 | 2026-06-18 |
| 5 | [OSINT_APIS_AND_LIBRARIES.md](OSINT_APIS_AND_LIBRARIES.md) | 248 | **OSINT APIs and Libraries** — Catalog of free and paid OSINT data sources evaluated during GhostMCP development. Phone (phonenumbers, Veriphone, Twilio), email (EmailRep, Holehe, Hunter.io), vehicle (NHTSA), court (CourtListener), and breach (HIBP, Snusbase, DeHashed) APIs with pricing and capabilities. | 2026-06-17 | 2026-06-17 |
| 6 | [COMPETITIVE_LANDSCAPE.md](COMPETITIVE_LANDSCAPE.md) | 203 | **Three-Tier Competitive Landscape** — Shodan/Censys/Amass (Tier 1) vs Burp/ZAP/StackHawk (Tier 2) vs Cobalt Strike/Nuclei/Pentera (Tier 3). Feature comparison matrices, pricing models, API availability, AI/MCP integration status, and where GhostMCP fills gaps. Cloud tools (Pacu, ScoutSuite, Prowler) and AI red-team tools (Garak, Counterfit, ART). | 2026-06-20 | 2026-06-20 |
| 7 | [DAST_SECURITY_SCANNING.md](DAST_SECURITY_SCANNING.md) | 154 | **DAST Security Scanning Research** — Passive vs active distinction, tool landscape overview. Defines the boundary between GhostMCP (passive/authenticated) and ForensicsMCP (active DAST/red team). OWASP methodology alignment. | 2026-06-20 | 2026-06-20 |

---

## Document Statistics

- **Total documents:** 7
- **Total lines:** 4,078
- **Date range:** 2026-06-17 to 2026-06-20
- **Primary sources:** Perplexity sonar-pro (deep research), Brave Search (validation), OWASP, MITRE ATT&CK, 42Crunch, vendor documentation, HackerOne disclosures, CISA advisories

## Related Design Documents

Design documents are maintained in [`../design/`](../design/):

| Document | Description |
|---|---|
| [THREE_TIER_SECURITY_MODEL.md](../design/THREE_TIER_SECURITY_MODEL.md) | Architecture for Tier 1/2/3 security assessment with OWASP API Top 10 modules, cloud/identity/supply chain attack coverage, and safety controls |
| [TIER1_PASSIVE_SECURITY.md](../design/TIER1_PASSIVE_SECURITY.md) | Design specifications for ghost_headers, ghost_dns, and ghost_cert grading systems |

---

*Last updated: 2026-06-20*
