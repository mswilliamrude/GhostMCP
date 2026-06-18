# BeenVerified Alternative: People Search API Research for GhostMCP

**Date:** 2026-06-18
**Author:** OpenCode research session
**Purpose:** Evaluate free and paid APIs that could replicate BeenVerified's people search capabilities within GhostMCP's OSINT tool framework.

---

## 1. Executive Summary

BeenVerified aggregates data from 20+ public and proprietary sources into a single people search product. Replicating this is **partially achievable** using free/open APIs but has hard limits around three areas:

1. **Freely replicable (~60%):** Phone lookup, email intelligence, social media discovery, VIN decoding, federal court records, breach history, and username enumeration.
2. **Partially replicable with paid APIs (~25%):** Property records, company/person enrichment, phone carrier data, and email finding.
3. **Not replicable without licensing (~15%):** Consumer credit headers, DMV records, utility connection data, proprietary address history databases, and real-time skip-tracing data.

**Key finding:** The IntelTechniques "URL generator" approach — building search URLs for free public-facing sites rather than scraping them — is the most legally safe and sustainable model for GhostMCP. Combine this with actual API calls where free tiers exist.

### Cost Estimate for Full Coverage

| Tier | Monthly Cost | Coverage |
|------|-------------|----------|
| Free only | $0 | ~40% of BeenVerified data |
| Light paid | $50-150/mo | ~65% of BeenVerified data |
| Full paid | $500-2000/mo | ~80% of BeenVerified data |
| Licensed data broker | $5000+/mo | ~95% of BeenVerified data |

---

## 2. Data Source Matrix

### 2.1 Phone Lookup

| Source | Free Tier | Rate Limit | Data Returned | Python Library | Notes |
|--------|-----------|------------|---------------|----------------|-------|
| **libphonenumber** (Google) | Yes — fully free | N/A (local) | Validation, carrier type (mobile/landline/VOIP), country, region, formatting | `phonenumbers` (pip) | Offline library. No network calls. Identifies carrier type and region from number prefix. Does NOT do reverse lookup (number → name). |
| **NumVerify API** | 100 req/mo free | 100/mo free, paid from $15/mo | Carrier, line type, country, location, valid status | `requests` (direct REST) | Free tier is HTTP only (no HTTPS). Returns carrier name and line type. No name/owner data. |
| **Twilio Lookup** | No free tier | Pay-per-use: $0.005/lookup (basic), $0.035 (carrier), $0.06 (caller name) | Carrier, line type, caller name (CNAM), SIM swap detection | `twilio` (pip) | Best programmatic option for carrier + CNAM. Caller Name add-on returns actual subscriber name on ~60% of US landlines, ~30% of mobiles. Requires Twilio account. |
| **Truecaller** | No public API | N/A | Name, spam score, photo | None (unofficial scraping only) | No official API for developers. Some unofficial Python wrappers exist (`truecallerpy`) but violate ToS and break frequently. Not recommended. |
| **OpenCNAM** | 15 free lookups | 15/mo free, $0.004/lookup paid | Caller ID name (CNAM) | `requests` (direct REST) | Simple REST API. Returns the CNAM record for a US phone number. Limited to name only, not address. |
| **Veriphone** | 1000 req/mo free | 1000/mo | Validity, carrier, line type, country | `requests` | Good free tier. No caller name data. |

**GhostMCP recommendation:** Use `phonenumbers` (free, offline) for validation/formatting + NumVerify or Veriphone free tier for carrier lookup. Add Twilio Lookup as optional paid upgrade for CNAM (actual name resolution).

### 2.2 Email Intelligence

| Source | Free Tier | Rate Limit | Data Returned | Python Library | Notes |
|--------|-----------|------------|---------------|----------------|-------|
| **Hunter.io** | 25 searches/mo free | 25/mo free; plans from $49/mo (500 searches) | Domain search (all emails at domain), email finder (name+domain→email), email verifier, lead enrichment (100+ attributes), company enrichment | `pyhunter` (pip) or direct REST | Verified in research: Domain Search returns emails with confidence scores, names, positions, departments. Lead Enrichment returns full profile (location, social handles, employment). Clearbit replacement API available. Free tier is very limited. |
| **EmailRep.io** | Yes — free with API key | Free tier available (rate not published; ~50/day estimated) | Email reputation score, breach presence, social media presence, domain age, deliverability, dark web exposure, malicious activity, profile flags | `requests` (direct REST) | Verified in research: Simple `GET emailrep.io/{email}` returns JSON with reputation, suspicious flags, breach count, profiles found, domain info. Excellent for defensive OSINT. Run by Sublime Security. |
| **Have I Been Pwned** | Partial — Pwned Passwords is free; email search requires paid key ($3.50/mo+) | 10 req/min (free tier for passwords) | Breaches an email appears in, paste appearances, stealer log data, data classes exposed | `requests` (direct REST) | Verified in research: v3 API. Free: breach metadata, password checking via k-anonymity. Paid ($3.50/mo "Core"): email→breach lookup. "Pro" adds k-anonymity email search, domain search, stealer logs. Has MCP server. |
| **Clearbit** (now part of HubSpot) | Deprecated as standalone | N/A | Person enrichment, company enrichment | `clearbit` (pip) — deprecated | Was the gold standard for email→person enrichment. Now folded into HubSpot. Hunter.io offers a compatible replacement API. |
| **Holehe** | Yes — fully free | N/A (direct checks) | Which websites an email is registered on | `holehe` (pip) | Checks 120+ websites for email registration by attempting password reset flows. Ethical gray area but widely used in OSINT. Python CLI tool. |
| **Epieos** | Limited free | Rate limited | Social accounts, Google ID, profile photos linked to email | Web only, no official API | Useful for manual OSINT but not programmable. |

**GhostMCP recommendation:** EmailRep.io (free, instant) for reputation scoring + Holehe for account discovery + HIBP paid ($3.50/mo) for breach data. Hunter.io for professional email finding when budget allows.

### 2.3 Criminal / Court Records

| Source | Free Tier | Rate Limit | Data Returned | Python Library | Notes |
|--------|-----------|------------|---------------|----------------|-------|
| **CourtListener / RECAP** (Free Law Project) | Yes — free with auth token | 5 req/min, 50 req/hr, 125 req/day (free); more with membership/partnership | Case law (opinions), PACER dockets, party names, attorneys, judges, financial disclosures, oral arguments, citation graph | `requests` (direct REST) | Verified in research: REST API v4.4 with 3,358 jurisdictions. Also offers bulk data, database replication, webhooks, and an **MCP server** (directly usable by GhostMCP). Search by party name to find cases. Free Law Project non-profit — membership-based access. |
| **PACER** (Federal Courts) | $0.10/page, $3 cap per document | No API rate limit; cost-limited | Federal court filings, dockets, case details, parties, judgments | `juriscraper` (pip) | Official US federal court system. Not free — $0.10/page. RECAP (via CourtListener) mirrors much of this for free. No REST API — uses CM/ECF web interface. |
| **State Court Portals** | Varies by state | Varies | State criminal cases, civil cases, traffic | None (scraping required) | Highly fragmented. ~50 different systems. Some states (NY, CA, TX) have searchable online portals. Most require manual searches. No unified API exists. |
| **UNICOURT** | Paid only ($starting ~$500/mo) | Per-plan | Federal + state court records, normalized party data, case tracking | `requests` (REST API) | Commercial court data aggregator. Comprehensive but expensive. |
| **Judyrecords.com** | Free web search | N/A (web only) | Aggregated court record search across many states | None | Free web search across ~600M court cases. No API. Useful for URL-generator approach. |

**GhostMCP recommendation:** CourtListener is the clear winner — free, has a REST API AND an MCP server, covers federal courts plus some state courts. Use URL-generator approach for Judyrecords and state portals. PACER direct access via `juriscraper` for cases not in RECAP.

### 2.4 Property Records

| Source | Free Tier | Rate Limit | Data Returned | Python Library | Notes |
|--------|-----------|------------|---------------|----------------|-------|
| **County Assessor Websites** | Free (public records) | N/A (web scraping) | Owner name, assessed value, tax history, property details, parcel maps | None (per-county scraping) | Every US county has a public assessor website with owner/value data. No unified API — thousands of separate sites. IntelTechniques URL-generator approach works well here. |
| **Zillow API** | **Deprecated** (2021) | N/A | Was: Zestimate, property details | `pyzillow` (deprecated) | Zillow killed their free API in 2021. Bridge Interactive API exists but requires partnership. Zillow data is still scrapeable but violates ToS. |
| **ATTOM Data** | No free tier | Pay-per-use; starts ~$0.10/record | Property characteristics, owner info, AVM (automated valuation), deed history, foreclosure, tax, school data | `requests` (REST API) | Most comprehensive property API available. 155M+ US properties. Expensive for volume. Used by real estate companies and skip tracers. Plans start ~$250/mo for 2,500 records. |
| **Redfin** | No public API | N/A | Property listings, price history, estimates | None official | Redfin has no public API. Data available through their website. Some unofficial scraping libraries exist. |
| **Realtor.com API** (via RapidAPI) | Limited free tier | 500 req/mo free on RapidAPI | Listings, property details, price estimates | `requests` via RapidAPI | Available through RapidAPI marketplace. Free tier is very limited. |
| **OpenStreetMap / Overpass** | Free | Rate limited | Parcel boundaries, building footprints, addresses | `osmnx`, `overpy` (pip) | Free geographic data. No ownership or valuation data. Useful for address validation and mapping. |

**GhostMCP recommendation:** URL-generator approach for county assessor sites (free, legal). ATTOM Data as optional paid integration for comprehensive property records. OSM for address/geographic validation.

### 2.5 Vehicle Records

| Source | Free Tier | Rate Limit | Data Returned | Python Library | Notes |
|--------|-----------|------------|---------------|----------------|-------|
| **NHTSA vPIC API** | **Fully free** | Rate-controlled (automated traffic management, no published limit) | VIN decoding (make, model, year, body type, engine, fuel type, safety features), manufacturer details, WMI decoding, all makes/models, equipment plant codes, Canadian vehicle specs | `requests` (direct REST); `python-vin` for parsing | Verified in research: Comprehensive free API. Supports JSON/XML/CSV output. Batch decode up to 50 VINs. Decodes partial VINs. Covers all vehicles with 565 manufacturer submissions. Standalone databases available for download. |
| **NHTSA Recalls API** | **Fully free** | Reasonable use | Safety recalls by VIN, make/model/year, or campaign number | `requests` (direct REST) | Check if a vehicle has open recalls. Free government API. |
| **NHTSA Complaints API** | **Fully free** | Reasonable use | Consumer complaints about vehicles, crash data | `requests` (direct REST) | Safety complaint database searchable by vehicle. |
| **VINAudit** (RapidAPI) | Limited free | 100 req/mo free | VIN decode, market value, accident history | `requests` via RapidAPI | More detailed than NHTSA but limited free tier. |
| **NMVTIS** (National Motor Vehicle Title Information System) | **No public API** | N/A | Title history, odometer, total loss, salvage/junk status | None | Only accessible through approved providers (e.g., VINCheck, AutoCheck). Consumers get 1 free lookup via VINCheck.info but no API. |
| **DMV Records** | **Not accessible** | N/A | Registration, owner info, driving history | None | Protected by DPPA. Only available to authorized users (law enforcement, insurance, etc.). Cannot be accessed programmatically for people search. |

**GhostMCP recommendation:** NHTSA vPIC (free VIN decode) + NHTSA Recalls (free recall check) are easy wins. These are fully free government APIs with no auth required. Owner information from DMV records is NOT accessible — this is a hard legal barrier.

### 2.6 Social Media / Username Search

| Source | Free Tier | Rate Limit | Data Returned | Python Library | Notes |
|--------|-----------|------------|---------------|----------------|-------|
| **Sherlock** | **Fully free** (OSS) | N/A (direct HTTP checks) | Username existence across 400+ platforms | `sherlock-project` (pip), or clone from GitHub | Most popular OSINT username enumeration tool. Checks hundreds of sites for a given username. Python CLI. Can be imported as library. Active development on GitHub (sherlock-project/sherlock). |
| **WhatsMyName** | **Fully free** (OSS) | N/A (direct HTTP checks) | Username existence across 500+ sites with categorization | Clone from GitHub (`whatsmyname`) | Maintained by WebBreacher. JSON database of site check patterns. More sites than Sherlock, different detection methodology. Community-maintained. |
| **Maigret** | **Fully free** (OSS) | N/A | Username search across 2500+ sites, profile data extraction | `maigret` (pip) | Fork/evolution of Sherlock with broader coverage and profile parsing. Extracts profile data (bio, links, etc.) when available. |
| **Social-Searcher** | Limited free | 100 searches/day free | Social media posts by keyword/username across major platforms | Web + limited API | Searches public posts on Twitter, Facebook, Instagram, etc. API is limited on free tier. Mostly a monitoring tool. |
| **social-analyzer** | **Fully free** (OSS) | N/A | Profile analysis, profile picture matching | `social-analyzer` (pip) | Analyzes social media profiles for a target. Can do image matching. |
| **Twint** (Twitter) | **Deprecated** | N/A | Was: Twitter scraping without API | `twint` (broken) | Stopped working after Twitter API changes. Not recommended. |

**GhostMCP recommendation:** Sherlock (mainstream, well-maintained) + Maigret (broader coverage) as primary tools. WhatsMyName JSON database as supplementary data source. All are free and open source.

### 2.7 People Aggregators (Public Web Sources)

| Source | Free Access | API Available | Data Returned | Scraping Risk | Notes |
|--------|------------|---------------|---------------|---------------|-------|
| **ThatsThem** | Free web search | No API | Name, address, phone, email, age, relatives | Medium — rate limited, CAPTCHAs | One of the better free people search sites. No API available. URL-generator approach works. |
| **FastPeopleSearch** | Free web search | No API | Name, address, phone, email, age, relatives, neighbors | High — aggressive bot detection | Comprehensive free results but actively blocks automation. |
| **USPhonebook** | Free web search | No API | Reverse phone/address lookup, name search | Medium | Good for reverse phone lookups. No API. |
| **Whitepages** | Limited free | Premium API (Whitepages Pro/Ekata) — expensive | Name, address, phone, identity verification | High — heavy anti-bot | Free web searches very limited. API (Ekata, now part of Mastercard) starts at ~$500/mo for identity verification. |
| **Spokeo** | Limited free (partial results) | No public API | Name, address, phone, email, social media, photos | High | Teaser results for free, full results require subscription. |
| **PeopleFinder** | Limited free | No public API | Name, address, phone, age, relatives | Medium | Basic results free. Full reports paid. |
| **411.com** | Free web search | No API | White pages directory lookup | Low | Basic directory assistance. Limited data. |
| **Pipl** | Paid only (~$298/mo+) | Yes (REST API) | Comprehensive person profiles from deep web | N/A (API) | Was the gold standard for people search API. Very expensive. Recently pivoted to identity verification. |

**GhostMCP recommendation:** IntelTechniques-style URL generator for ThatsThem, FastPeopleSearch, USPhonebook, Whitepages, 411.com. Generate direct search URLs that the user can open in a browser. Do NOT scrape these sites — they actively detect and block bots, and scraping personal data carries legal risk.

### 2.8 General OSINT Frameworks

| Source | Free | Approach | Data Returned | Notes |
|--------|------|----------|---------------|-------|
| **IntelTechniques URL Generator** | Free (methodology) | Generates URLs to search 100+ public data sources | Search URLs for social media, people search, phone, email, username, image, domain, etc. | Michael Bazzell's approach: rather than scraping, generate the correct search URL and let the user interact with the site. Completely legal. GhostMCP should implement this pattern. |
| **OSINT Framework** (osintframework.com) | Free (directory) | Categorized directory of OSINT tools and sources | Links organized by category: username, email, domain, phone, social networks, public records, etc. | Not a tool itself — a directory. Useful for discovering new sources. |
| **SpiderFoot** | Free (OSS) + paid cloud | Automated OSINT collection across 200+ data sources | Everything: domains, IPs, emails, names, phones, social media, dark web, breaches | Python-based. Can run locally. Modular with 200+ modules. HX (cloud) version adds more features. |
| **Recon-ng** | Free (OSS) | Modular recon framework | Depends on loaded modules: DNS, contacts, social media, credentials | Python framework. Modules are like Metasploit for OSINT. Some modules need API keys. |
| **theHarvester** | Free (OSS) | Email/subdomain/name harvesting from public sources | Emails, names, subdomains, IPs, URLs from search engines | Python tool. Uses Google, Bing, LinkedIn, etc. as sources. |

**GhostMCP recommendation:** Implement the IntelTechniques URL generator pattern as `ghost_people` tool. For each data category (phone, email, name, address), generate 5-10 search URLs across the best free sources. This is legal, sustainable, and doesn't break when sites change their anti-bot measures.

---

## 3. Free vs. Paid Analysis

### What You Get for Free

| Category | Free Sources | Quality | Coverage |
|----------|-------------|---------|----------|
| Phone validation | libphonenumber, Veriphone | High | Validation/formatting excellent, no name resolution |
| Email reputation | EmailRep.io, Holehe | Good | Reputation + account discovery |
| Username search | Sherlock, Maigret | Excellent | 400-2500+ sites |
| VIN decoding | NHTSA vPIC | Excellent | All US vehicles, comprehensive |
| Vehicle recalls | NHTSA Recalls | Excellent | All US recalls |
| Court records | CourtListener | Good | Federal + some state |
| Breach history | HIBP (metadata only) | Good | 1000+ breaches (metadata free) |
| Social media discovery | Sherlock, WhatsMyName | Excellent | Broad coverage |

### What Requires Paid APIs

| Category | Best Paid Source | Monthly Cost | Worth It? |
|----------|-----------------|-------------|-----------|
| Email → breach lookup | HIBP ($3.50/mo) | $3.50 | **Yes** — cheap, essential |
| Email → person profile | Hunter.io ($49/mo) | $49 | Maybe — depends on use case |
| Phone → caller name | Twilio CNAM ($0.06/lookup) | Variable | Yes for specific lookups |
| Property records | ATTOM Data ($250+/mo) | $250+ | Only if property search is core |
| Comprehensive court data | UNICOURT ($500+/mo) | $500+ | No — CourtListener is sufficient |
| Identity verification | Ekata/Whitepages Pro | $500+/mo | No — too expensive for OSINT tool |

### The Unbridgeable Gap

These BeenVerified data sources **cannot** be replicated regardless of budget, because they require data broker licensing agreements:

1. **Consumer credit header data** — Requires CRA (Consumer Reporting Agency) status
2. **DMV records** — Protected by DPPA, requires permissible purpose
3. **Utility connection records** — Proprietary data from utility companies
4. **Real-time skip-tracing data** — LexisNexis, TLO, IRB proprietary databases
5. **Comprehensive address history** — USPS NCOALink requires licensing
6. **Voter registration files** — Available per-state but require bulk purchase ($50-$5000/state)

---

## 4. Legal Considerations

### 4.1 FCRA (Fair Credit Reporting Act)

**What it covers:** Any "consumer report" used for credit, employment, insurance, housing, or other FCRA-defined purposes.

**What requires FCRA compliance:**
- Using data to make decisions about a person's creditworthiness, employment eligibility, insurance eligibility, or housing
- Accessing credit header data, credit scores, or consumer credit information
- Any service marketed as a "background check" for employment or tenant screening

**What does NOT require FCRA compliance:**
- OSINT gathering from public sources for personal/investigative use
- Searching public court records, property records, or social media
- Using people search tools for reconnecting with people, self-research, or general curiosity
- Journalistic or research use

**GhostMCP impact:** GhostMCP is an OSINT tool, not a consumer reporting agency. As long as we:
- Do NOT market it for employment screening, tenant screening, or credit decisions
- Do NOT access FCRA-regulated databases (credit bureaus, etc.)
- Clearly state that results are not a "consumer report"
- Include appropriate disclaimers

We are **not subject to FCRA** for the data sources outlined in this document.

### 4.2 DPPA (Driver's Privacy Protection Act)

**What it covers:** Motor vehicle records held by state DMVs — registration data, driver's license info, photographs, SSN, address linked to vehicle registration.

**What it means for us:**
- DMV data is **completely off-limits** without a permissible purpose (law enforcement, insurance, legal proceedings, etc.)
- VIN decoding via NHTSA is fine — it reveals vehicle specs, not owner data
- License plate → owner lookups are NOT possible through any legal API
- Some states are stricter than the federal minimum (e.g., California, Arkansas)

**GhostMCP impact:** We can implement VIN decoding (NHTSA) but cannot offer license plate lookups or DMV record searches. This is a hard legal wall.

### 4.3 State Privacy Laws

**Key variations:**

| State/Law | Impact |
|-----------|--------|
| **California (CCPA/CPRA)** | Consumers can opt out of data sale/sharing. People search sites must honor opt-out requests. Doesn't affect our use of public records APIs. |
| **Illinois (BIPA)** | Biometric data (face recognition, fingerprints) requires consent. Affects any facial recognition tools. |
| **Vermont** | Data brokers must register with the state. Affects any business that sells personal data. |
| **Texas (TDPSA)** | Similar to CCPA. Opt-out rights for consumers. |
| **Virginia (VCDPA)** | Consumer data protection. Opt-out rights. |
| **Connecticut, Colorado, Utah** | Similar consumer privacy frameworks. |

**GhostMCP impact:** We are a tool, not a data broker. We don't store or sell personal data. We query public APIs and generate search URLs. State privacy laws primarily affect the data sources themselves, not tools that query them. However:
- We should NOT cache or store personal data retrieved from these sources
- We should include disclaimers about intended use
- We should not facilitate bulk data collection about individuals

### 4.4 Computer Fraud and Abuse Act (CFAA)

**Relevant concern:** Scraping websites that explicitly prohibit it in their ToS.

**GhostMCP approach:** The URL-generator pattern avoids this entirely. We generate URLs — the user decides whether to visit them. For actual API calls, we only use documented, authorized APIs with proper authentication.

---

## 5. Proposed GhostMCP Tools

### Phase 1: Free Tools (No API Keys Required)

#### `ghost_phone` — Phone Number Intelligence
```
Input: phone number (any format)
Output: {
  valid: bool,
  formatted: {e164, national, international},
  country: str,
  region: str,
  carrier_type: "mobile" | "landline" | "voip" | "unknown",
  carrier_name: str (if available via free API),
  timezone: str,
  search_urls: {
    truecaller: "https://...",
    whocallsme: "https://...",
    usphonebook: "https://..."
  }
}
```
**Libraries:** `phonenumbers` (offline) + Veriphone API (free tier, optional)

#### `ghost_email` — Email Intelligence
```
Input: email address
Output: {
  valid: bool,
  reputation: {score, suspicious, references, details},  # via EmailRep
  accounts_found: [list of sites],                        # via Holehe
  breaches: {count, names},                               # via HIBP (if key provided)
  search_urls: {
    hunter: "https://...",
    epieos: "https://...",
    haveibeenpwned: "https://..."
  }
}
```
**Libraries:** EmailRep.io (free API key) + `holehe` + HIBP

#### `ghost_username` — Username Enumeration
```
Input: username
Output: {
  found_on: [{site, url, category}],
  not_found: [sites checked],
  total_checked: int,
  search_urls: {
    namechk: "https://...",
    knowem: "https://..."
  }
}
```
**Libraries:** `sherlock-project` or `maigret`

#### `ghost_vin` — Vehicle Intelligence
```
Input: VIN (full or partial)
Output: {
  make, model, year, body_type, engine, fuel_type,
  manufacturer: {name, country},
  safety: {features, ratings},
  recalls: [{campaign, component, summary, remedy}],
  complaints: {count, summary},
  search_urls: {
    carfax: "https://...",
    autocheck: "https://..."
  }
}
```
**Libraries:** NHTSA vPIC API + NHTSA Recalls API (both free, no key)

#### `ghost_court` — Court Record Search
```
Input: person name, jurisdiction (optional)
Output: {
  federal_cases: [{case_name, docket, court, date, parties}],
  search_urls: {
    courtlistener: "https://...",
    judyrecords: "https://...",
    pacer: "https://...",
    state_courts: {state: "https://..."}
  }
}
```
**Libraries:** CourtListener REST API (free with token) or CourtListener MCP server

#### `ghost_people` — People Search URL Generator
```
Input: {name, city, state, phone, email, username} (any combination)
Output: {
  search_urls: {
    thatsthem: "https://...",
    fastpeoplesearch: "https://...",
    whitepages: "https://...",
    truepeoplesearch: "https://...",
    usphonebook: "https://...",
    411: "https://...",
    spokeo: "https://...",
    pipl: "https://...",
    social_media: {
      facebook: "https://...",
      linkedin: "https://...",
      twitter: "https://...",
      instagram: "https://..."
    },
    public_records: {
      voter_records: "https://...",
      property: "https://...",
      court: "https://..."
    }
  }
}
```
**Libraries:** None (URL construction only). IntelTechniques approach.

### Phase 2: Paid API Integrations (Optional, Key-Gated)

#### `ghost_phone` upgrades
- **Twilio CNAM:** Add caller name resolution ($0.06/lookup)
- **NumVerify Pro:** Enhanced carrier data

#### `ghost_email` upgrades
- **Hunter.io:** Email finding (name+domain→email), domain search
- **HIBP Pro:** Full breach details with k-anonymity

#### `ghost_property` — Property Records
```
Input: address or owner name
Output: {
  owner: {name, mailing_address},
  property: {type, beds, baths, sqft, lot_size, year_built},
  value: {assessed, market_estimate},
  tax: {annual_amount, year},
  deed: {sale_date, sale_price, seller},
  search_urls: {county_assessor: "https://..."}
}
```
**Libraries:** ATTOM Data API ($250+/mo)

---

## 6. Implementation Phases

### Phase 1: Core Free Tools (Week 1-2)

| Tool | Effort | Dependencies | Priority |
|------|--------|-------------|----------|
| `ghost_phone` | 2 days | `phonenumbers` pip install | P1 |
| `ghost_email` | 3 days | EmailRep.io free API key | P1 |
| `ghost_vin` | 2 days | None (NHTSA is key-free) | P1 |
| `ghost_username` | 2 days | `sherlock-project` or `maigret` pip | P1 |
| `ghost_people` (URL generator) | 1 day | None | P1 |
| `ghost_court` | 3 days | CourtListener API token (free) | P2 |

**Total Phase 1:** ~13 dev days, $0/mo running cost

### Phase 2: Paid API Integrations (Week 3-4)

| Enhancement | Effort | Monthly Cost | Priority |
|-------------|--------|-------------|----------|
| HIBP integration (breach details) | 1 day | $3.50/mo | P1 |
| Twilio CNAM (phone name lookup) | 1 day | Pay-per-use (~$6/100 lookups) | P2 |
| Hunter.io (email enrichment) | 2 days | $49/mo | P3 |
| CourtListener MCP integration | 1 day | Free (membership recommended) | P2 |

**Total Phase 2:** ~5 dev days, $52.50/mo minimum

### Phase 3: Advanced Features (Month 2+)

| Feature | Effort | Cost | Priority |
|---------|--------|------|----------|
| ATTOM property data | 3 days | $250+/mo | P3 |
| Batch phone/email processing | 2 days | Depends on APIs used | P3 |
| Report generation (PDF/HTML) | 3 days | $0 | P2 |
| Cross-referencing (link analysis) | 5 days | $0 | P2 |

---

## 7. Honest Limitations

### What BeenVerified Has That We Cannot Replicate

| BeenVerified Feature | Why We Can't Replicate | Alternative |
|---------------------|----------------------|-------------|
| **Comprehensive address history** | Requires USPS NCOALink license + proprietary databases (LexisNexis, TLO) | URL generator to people search sites that have this data |
| **Criminal records (all states)** | No unified database; each state has different systems, many not online | CourtListener (partial) + URL generator for state courts |
| **Sex offender registry** | Dru Sjodin NSOPW exists but no proper API; some states block scraping | URL generator to nsopw.gov and state registries |
| **DMV / vehicle ownership** | DPPA prohibits access without permissible purpose | VIN decode (specs only, no owner data) |
| **Phone owner name (reliable)** | CNAM only covers ~50% of numbers; full coverage requires data broker licensing | Twilio CNAM (partial) + URL generator |
| **Relatives / associates** | Proprietary social graph data from data brokers | URL generator to people search sites |
| **Email / phone → full profile** | Requires cross-referencing proprietary databases at scale | Partial via Hunter.io + EmailRep + HIBP + Sherlock |
| **Continuous monitoring** | Requires persistent infrastructure + data broker feeds | Not planned |
| **Background check reports** | FCRA compliance required; CRA certification needed | Explicitly NOT our use case — we are OSINT, not a CRA |

### Honest Assessment

BeenVerified charges ~$27/month because they've spent millions licensing data from:
- LexisNexis / Accurint
- TransUnion / Experian (non-credit header data)
- State DMVs (through permissible purpose agreements)
- USPS address change data
- Utility company records
- Proprietary social graph analysis

A free/open-source OSINT tool will **never** match this breadth of data. What we CAN do is:
1. Aggregate the best free APIs into a single interface
2. Provide the IntelTechniques URL-generator approach for sources without APIs
3. Add optional paid APIs for users who need more depth
4. Stay on the right side of the law by avoiding FCRA/DPPA-regulated data
5. Be transparent about what we can and cannot find

The value proposition of GhostMCP's people search is not "we replace BeenVerified" — it's "we give you 60% of the answer for free, instantly, from your terminal, with full transparency about sources, and generate URLs for you to check the rest manually."

---

## Appendix A: Python Package Summary

```
# Phase 1 — Free tools
pip install phonenumbers        # Phone validation (offline, Google libphonenumber)
pip install sherlock-project     # Username enumeration (or: pip install maigret)
pip install holehe               # Email account discovery

# Phase 2 — Paid integrations (optional)
pip install twilio               # Phone CNAM lookup
pip install pyhunter             # Hunter.io email finding

# Already in GhostMCP
# httpx                          # HTTP client for API calls
# (all existing ghost_* tools)
```

## Appendix B: Key API Endpoints Reference

```
# EmailRep (free, needs API key)
GET https://emailrep.io/{email}

# NHTSA VIN Decode (free, no key)
GET https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVin/{VIN}?format=json
GET https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValues/{VIN}?format=json

# NHTSA Recalls (free, no key)
GET https://api.nhtsa.gov/recalls/recallsByVehicle?make={make}&model={model}&modelYear={year}

# CourtListener (free, needs token)
GET https://www.courtlistener.com/api/rest/v4/search/?q={name}&type=r
Authorization: Token {your-token}

# HIBP (paid for email search, free for breach metadata)
GET https://haveibeenpwned.com/api/v3/breaches                    # Free
GET https://haveibeenpwned.com/api/v3/breachedAccount/{email}     # Paid
hibp-api-key: {your-key}

# Hunter.io (25 free searches/mo)
GET https://api.hunter.io/v2/domain-search?domain={domain}&api_key={key}
GET https://api.hunter.io/v2/email-finder?domain={domain}&first_name={first}&last_name={last}&api_key={key}
GET https://api.hunter.io/v2/email-verifier?email={email}&api_key={key}

# NumVerify (100 free req/mo)
GET http://apilayer.net/api/validate?access_key={key}&number={phone}

# Veriphone (1000 free req/mo)
GET https://api.veriphone.io/v2/verify?phone={phone}&key={key}
```

## 8. Breach Data as a People-Search Accelerator

### 8.1 The Insight

The ~15-20% of BeenVerified data that requires $5K+/mo data broker licensing (address history, employment, phone-to-name resolution, utility connections, social graphs) is substantially available through breach databases. Breach data from major incidents like Exactis (340M records), Apollo, PeopleDataLabs (1.2B), Facebook (533M), LinkedIn (700M), T-Mobile, AT&T, and Equifax collectively cover most of the PII that data brokers sell.

**Estimated coverage via breach data:**

| "Licensed" Data Type | Available in Breaches? | Key Breach Sources |
|---|---|---|
| **Address history** | Yes — extensively | Exactis (340M), Apollo, PeopleDataLabs (1.2B), loyalty programs, shipping DBs |
| **Phone + carrier** | Yes | T-Mobile, AT&T breaches, SIM swap DBs, marketing databases |
| **DMV / license data** | Partial — rare | State government breaches (sporadic, patchy coverage) |
| **Credit headers** | Partial — legally radioactive | Equifax 2017 (147M), Experian breaches — stale data |
| **Utility connections** | Yes | Billing system breaches, IoT vendor dumps |
| **Employment history** | Yes | LinkedIn (700M), Apollo, corporate HR system breaches |
| **Education** | Partial | University breaches, student loan servicer dumps |
| **Relatives / associates** | Yes | Facebook (533M), contact list harvesting, social graph dumps |

### 8.2 Breach Search API Landscape (2025-2026)

Services with REST APIs for programmatic breach data access:

| Service | Pricing | API | Search Fields | Notes |
|---|---|---|---|---|
| **DeHashed** | ~$0.02/query or subscription | REST API | Email, phone, username, IP, name, VIN, address, password hash | Most comprehensive field coverage. Industry standard. |
| **Snusbase** | ~$27/mo | REST API (2048 req/day included) | Email, phone, username, IP, name | Cheap, API included with any paid plan. Good for low-volume research. |
| **LeakCheck** | ~$10/mo | REST API | Email, phone, username | Budget-friendly. Smaller index than DeHashed. |
| **IntelligenceX** | Free tier + paid | REST API | Email, phone, username, IP, domain, URL, hash, BTC, CIDR, IPFS | Broadest search types. Also indexes pastes, darknet, Tor. Free tier is rate-limited. |
| **HIBP** | $3.50/mo (Core) | REST API | Email only (+ k-anonymity password check) | Metadata only — no raw PII returned. Legal gold standard. |
| **LeakRadar** | €29.99/mo (Starter) | REST API (30 req/sec, unlimited search) | Email, domain, stealer logs | No per-query charge. Flat monthly fee. Modern DeHashed alternative (2025). |
| **BreachSense** | Commercial (contact sales) | REST API | Email, domain, credentials, stealer logs, ransomware leaks | Continuous monitoring focus. Positioned as DeHashed replacement. |
| **Intelligence Security** | Commercial | REST API + Telegram bot | Email, credentials, domain recon | 2026-era Snusbase alternative. Free audit tools available. |
| **DataBreach.com** (Atlas Privacy) | Free search | No documented API | Email, name, address, phone, SSN, IP, username | Richest PII search but no programmatic access. Manual OSINT only. |

### 8.3 Open Source / Self-Hosted Options

No reputable project ships with pre-loaded breach data (legal reasons), but you can build your own:

| Tool | Type | Notes |
|---|---|---|
| **Elasticsearch + custom ingest** | Self-hosted index | Load breach data you legally possess into ES, build API on top |
| **Breach Checker (Passbae)** | Open source | Summarizes breached accounts by email, returns threat levels. Extensible. |
| **SpiderFoot** | OSINT framework (OSS) | 200+ modules, orchestrates calls to third-party APIs. Self-hostable. Not a breach DB itself. |
| **Recon-ng** | OSINT framework (OSS) | Module-based recon. Calls external APIs (you bring keys). Good for automation. |
| **Maltego CE** | Graph OSINT (free edition) | Visual link analysis. Breach data via transforms (bring your own API keys). |
| **Lampyre** | Desktop OSINT platform | Multiple data feeds, scripting support. No open breach API — uses integrations. |

**Key insight from Perplexity:** None of SpiderFoot/Maltego/Recon-ng/Lampyre provide breach data directly — they're *orchestrators* that call APIs you configure. The breach data must come from a dedicated provider (DeHashed, Snusbase, etc.) or your own legal index.

### 8.4 Additional Alternatives (Perplexity Findings, June 2026)

**Email finding (Hunter.io alternatives):**
- **Snov.io** — REST API, free tier, domain-to-email discovery
- **Apollo.io** — Prospecting API, large database, free tier available
- **RocketReach** — Email + phone finding, API access
- **VoilaNorbert** — Email verification + finding, small free tier

**Username enumeration (Sherlock alternatives):**
- **Maigret** — More sites than Sherlock, actively maintained, Python
- **WhatsMyName** — Community-maintained site list, can be used programmatically
- **Namechk** — Web-based, some have unofficial API access

**Court records (CourtListener alternatives):**
- **PACER + RECAP** — Official federal courts. RECAP (via CourtListener/Free Law Project) archives PACER docs for free access
- State-level court APIs vary wildly by jurisdiction
- Commercial (LexisNexis, Westlaw) — expensive, heavily licensed, not suitable for OSINT tooling

### 8.5 Two-Layer Legal Model for GhostMCP

The legally clean approach for breach integration:

**Layer 1 — Exposure Check (defensive, legal everywhere):**
```
"Has this identity been exposed in any breach?"
→ Returns: breach names, dates, data types exposed, severity score
→ Sources: HIBP, EmailRep.io, LeakCheck
→ Config: breach_enrichment: metadata_only (DEFAULT)
```

**Layer 2 — Breach Content (authorized research only):**
```
"What specific data was exposed?"
→ Returns: actual PII from breach records
→ Sources: DeHashed, Snusbase, IntelligenceX
→ Config: breach_enrichment: full
→ Requires: operator acknowledgment of legal responsibility
```

### 8.6 Cost-Benefit Analysis with Breach APIs

| Approach | Monthly Cost | Coverage vs BeenVerified |
|---|---|---|
| Free APIs only (HIBP free, EmailRep, NHTSA, phonenumbers) | $0 | ~40% |
| + HIBP paid + Snusbase | ~$31/mo | ~65% |
| + DeHashed or LeakRadar + Hunter.io | ~$80-130/mo | ~75% |
| + IntelligenceX + multiple providers | ~$200-500/mo | ~85% |
| Data broker licensing (Pipl, LexisNexis) | $5,000+/mo | ~95% |

**Bottom line:** With ~$30-50/mo in breach search APIs (Snusbase + HIBP), GhostMCP closes roughly half the gap between the free tier and the $5K/mo data broker tier. The remaining gap is freshness (breach data is point-in-time snapshots, not live feeds) and DMV/credit data (hard legal walls).

### 8.7 Three Real Problems with Breach-as-PeopleSearch

1. **Freshness** — Breach data is a snapshot from the dump date. BeenVerified gets live feeds. A 2022 breach won't show someone's 2026 address.

2. **Legal exposure** — Hard line between:
   - Checking if an email *appears* in a breach (defensive, HIBP-style) → **Legal**
   - *Using* breached PII for people-search enrichment → **Gray to illegal** depending on jurisdiction. CFAA, state privacy laws, GDPR all apply.

3. **Programmatic access** — The aggregated breach databases (Snusbase, DeHashed, IntelX, LeakRadar) are paid services. No truly free, stable, abuse-tolerant breach search API exists for good reason.

---

## Appendix C: IntelTechniques URL Templates

Example URL patterns for the `ghost_people` URL generator:

```python
PEOPLE_SEARCH_URLS = {
    "thatsthem_name": "https://thatsthem.com/name/{first}-{last}/{state}",
    "thatsthem_phone": "https://thatsthem.com/phone/{phone}",
    "thatsthem_email": "https://thatsthem.com/email/{email}",
    "fastpeoplesearch": "https://www.fastpeoplesearch.com/name/{first}-{last}_{city}-{state}",
    "whitepages": "https://www.whitepages.com/name/{first}-{last}/{city}-{state}",
    "truepeoplesearch": "https://www.truepeoplesearch.com/results?name={first}%20{last}&citystatezip={city}%20{state}",
    "usphonebook_phone": "https://www.usphonebook.com/{phone}",
    "usphonebook_name": "https://www.usphonebook.com/{first}-{last}/{state}",
    "411_name": "https://www.411.com/name/{first}-{last}/{city}-{state}",
    "spokeo_name": "https://www.spokeo.com/{first}-{last}",
    "spokeo_phone": "https://www.spokeo.com/phone/{phone}",
    "facebook": "https://www.facebook.com/search/people/?q={first}%20{last}",
    "linkedin": "https://www.linkedin.com/search/results/people/?keywords={first}%20{last}",
    "judyrecords": "https://www.judyrecords.com/record?q=%22{first}+{last}%22",
    "nsopw": "https://www.nsopw.gov/search-public?FirstName={first}&LastName={last}&State={state}",
}
```
