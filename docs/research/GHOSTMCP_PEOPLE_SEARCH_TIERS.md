# GhostMCP People Search: Tiered Capability Matrix vs BeenVerified

**Date:** 2026-06-18
**Purpose:** Map exactly what BeenVerified offers, then show what GhostMCP can deliver at each spending tier — which features light up, which vendors power them, and what stays dark.

---

## BeenVerified Feature Inventory

First, let's establish what BeenVerified actually sells (~$27/mo consumer plan):

| # | Feature | Data Points |
|---|---------|-------------|
| 1 | **Person Search** | Full name, aliases, age, DOB |
| 2 | **Address History** | Current + previous addresses, dates at each, mapped |
| 3 | **Phone Numbers** | Current + historical phone numbers, carrier, line type |
| 4 | **Email Addresses** | Known email addresses associated with the person |
| 5 | **Relatives & Associates** | Names of family members, roommates, associates |
| 6 | **Social Media Profiles** | Linked social accounts (Facebook, LinkedIn, Instagram, etc.) |
| 7 | **Criminal Records** | Arrests, charges, convictions, sex offender status |
| 8 | **Court Records** | Civil + criminal case history, federal + state |
| 9 | **Property Records** | Owned properties, assessed values, tax records |
| 10 | **Vehicle Records** | Vehicles owned, VIN, make/model/year |
| 11 | **Education** | Schools attended, degrees |
| 12 | **Employment** | Current/past employers, job titles |
| 13 | **Bankruptcy / Liens / Judgments** | Financial legal records |
| 14 | **Professional Licenses** | State-issued licenses (medical, legal, real estate, etc.) |
| 15 | **Reverse Phone Lookup** | Phone number → person identity |
| 16 | **Reverse Email Lookup** | Email → person identity |
| 17 | **Reverse Address Lookup** | Address → current/past residents |
| 18 | **Breach Monitoring** | Alert when your info appears in new breaches |
| 19 | **Dark Web Monitoring** | Scan dark web for PII exposure |
| 20 | **Background Check Report** | Consolidated PDF/web report |

---

## Tier 0: Free ($0/mo)

**Coverage: ~45% of BeenVerified features (9 of 20)**

At zero cost, GhostMCP delivers solid results in phone validation, username/social discovery, vehicle specs, federal court records, and breach metadata. The URL generator fills gaps by sending users directly to free people-search sites.

### Features Satisfied

| BV Feature | How GhostMCP Delivers It | Vendor / Tool | Accuracy |
|---|---|---|---|
| **Phone Numbers** (partial) | Validate, format, identify carrier type + carrier name, timezone | `phonenumbers` (Google, offline) + Veriphone (1000/mo free) | High for validation. No name resolution. |
| **Social Media Profiles** | Enumerate which platforms a username exists on (400-2500+ sites) | Sherlock (OSS) + Maigret (OSS) + WhatsMyName (OSS) | Excellent — better than BV for breadth |
| **Email Addresses** (partial) | Reputation score, breach count, account discovery (120+ sites), social profiles linked to email | EmailRep.io (free API) + Holehe (OSS) | Good — tells you which sites an email is registered on |
| **Vehicle Records** (specs only) | Full VIN decode: make, model, year, engine, body, safety features, manufacturer | NHTSA vPIC (free, no key) | Excellent — comprehensive, authoritative |
| **Vehicle Recalls** | Open recall campaigns for any vehicle | NHTSA Recalls API (free, no key) | Excellent — official government data |
| **Court Records** (federal) | Federal case search by party name, docket data, opinions | CourtListener / RECAP (free with token) | Good — strong on federal, partial on state |
| **Criminal Records** (partial) | Sex offender registry search | NSOPW URL generator (free) | Partial — covers sex offenders only |
| **Reverse Phone Lookup** (partial) | URL generator to free reverse-phone sites | USPhonebook, ThatsThem, Spokeo URLs | Indirect — sends user to site, doesn't return data |
| **Person Search** (indirect) | URL generator to 15+ free people-search sites | ThatsThem, FastPeopleSearch, Whitepages, TruePeopleSearch, 411, Spokeo, Facebook, LinkedIn | Indirect — generates links, user clicks through |

### Features NOT Satisfied

| BV Feature | Why Not | What You Get Instead |
|---|---|---|
| Address History | Requires data broker licensing (USPS NCOALink, LexisNexis) | URL generator to people-search sites that show this |
| Relatives & Associates | Requires proprietary social graph databases | URL generator to people-search sites |
| Property Records | County assessors have no unified API | URL generator to county assessor sites |
| Education | No free API exists for this | Nothing |
| Employment | No free API; LinkedIn scraping violates ToS | Nothing |
| Reverse Email → person | Requires cross-referencing proprietary DBs | EmailRep gives reputation, not identity |
| Reverse Address → residents | Requires data broker feeds | URL generator to people-search sites |
| Bankruptcy / Liens | PACER costs $0.10/page, no free alternative | CourtListener covers some |
| Professional Licenses | Per-state databases, no unified API | Nothing |
| Breach Monitoring | Requires persistent polling infrastructure | One-shot breach checks only |
| Dark Web Monitoring | Requires Tor infrastructure + persistent monitoring | Nothing at this tier |
| Background Check Report | Need data to compile a report from | Partial data, no consolidated report |

### Tier 0 Vendor Summary

| Vendor | Cost | What It Provides |
|---|---|---|
| `phonenumbers` (Google) | Free (pip, offline) | Phone validation, formatting, carrier type, region |
| Veriphone | Free (1000 req/mo) | Online carrier verification |
| EmailRep.io | Free (API key, ~50/day) | Email reputation, breach count, profiles |
| Holehe | Free (pip, OSS) | Email → 120+ site registration check |
| Sherlock | Free (pip, OSS) | Username → 400+ platform check |
| Maigret | Free (pip, OSS) | Username → 2500+ platform check with profile data |
| WhatsMyName | Free (OSS) | Username → 500+ site check, community-maintained lists |
| NHTSA vPIC | Free (no key) | VIN decode (comprehensive) |
| NHTSA Recalls | Free (no key) | Vehicle recall lookup |
| CourtListener | Free (API token) | Federal court records, opinions, dockets |
| URL Generator | Free (code only) | 15+ people-search site links for manual investigation |

**Total: $0/mo, 11 free tools/APIs**

---

## Tier 1: Budget ($30-50/mo)

**Coverage: ~65% of BeenVerified features (13 of 20)**

Adding HIBP and a breach search API (Snusbase or LeakCheck) is the single biggest bang-for-buck upgrade. Breach data fills in address history, phone-to-name, employment, and email associations that would otherwise require $5K/mo data broker licensing.

### New Features Unlocked (vs Tier 0)

| BV Feature | How GhostMCP Delivers It | Vendor | Accuracy |
|---|---|---|---|
| **Reverse Email Lookup** | Email → breach records revealing name, address, phone, password, employer | HIBP paid ($3.50/mo) + Snusbase ($27/mo) | Good — depends on which breaches contain the email |
| **Reverse Phone Lookup** | Phone → breach records revealing associated name/email/address | Snusbase (phone search included) | Moderate — coverage varies by phone number |
| **Address History** (partial) | Addresses from breached databases (Exactis, PeopleDataLabs, marketing DBs) | Snusbase / LeakCheck | Moderate — snapshot data, not live. Freshness degrades over time. |
| **Email Addresses** (full) | Full breach details: which breaches, what data exposed, credentials | HIBP Core ($3.50/mo) | Excellent — comprehensive breach metadata |
| **Employment** (partial) | Employer info from LinkedIn breach (700M), Apollo breach, HR system breaches | Snusbase (name/email search) | Low-Moderate — stale data, not current employer |
| **Dark Web Monitoring** (partial) | Stealer log data, ransomware leak exposure | HIBP Pro ($10/mo, optional) or Snusbase | Moderate — one-shot check, not continuous monitoring |

### Features Still NOT Satisfied

| BV Feature | Why Still Missing |
|---|---|
| Relatives & Associates | Breach data rarely contains relationship data |
| Property Records | Not in breach databases |
| Education | Rarely in breach data |
| Professional Licenses | Not in breach databases |
| Breach Monitoring (continuous) | Still one-shot, not polling |
| Criminal Records (comprehensive) | Breaches don't contain arrest records |
| Background Check Report | Partial data — not enough for a full report yet |

### Tier 1 Vendor Summary

| Vendor | Cost | What It Adds Over Tier 0 |
|---|---|---|
| **HIBP Core** | $3.50/mo | Email → breach lookup, breach details, data classes exposed |
| **Snusbase** | $27/mo | Multi-field breach search (email, phone, name, username, IP). 2048 req/day API. |
| *or* **LeakCheck** | $10/mo | Cheaper alternative. Email, phone, username search. Smaller index. |
| *or* **LeakRadar** | €29.99/mo | Flat fee, unlimited search, 30 req/sec. Stealer logs. Modern API. |

**Recommended combo: HIBP Core + Snusbase = $30.50/mo**
**Budget combo: HIBP Core + LeakCheck = $13.50/mo**

---

## Tier 2: Professional ($80-150/mo)

**Coverage: ~75% of BeenVerified features (15 of 20)**

Adding Hunter.io for email enrichment, Twilio for caller-name lookup, and DeHashed for deeper breach coverage fills most remaining gaps. This is where GhostMCP becomes a serious people-search tool.

### New Features Unlocked (vs Tier 1)

| BV Feature | How GhostMCP Delivers It | Vendor | Accuracy |
|---|---|---|---|
| **Reverse Phone → Name** | CNAM (Caller Name) lookup on US numbers | Twilio Lookup CNAM ($0.06/lookup) | Moderate — ~60% landline, ~30% mobile hit rate |
| **Email → Person Profile** | Name, position, company, social handles, location from email or domain | Hunter.io ($49/mo, 500 searches) | Good for professional/business emails. Weak for personal. |
| **Employment** (better) | Current employer + title via Hunter.io enrichment | Hunter.io Lead Enrichment | Good for professionals with business emails |
| **Bankruptcy / Liens** | Federal bankruptcy filings via CourtListener + PACER | PACER ($0.10/page, ~$10-20/mo typical) | Good — official federal records |
| **Person Search** (richer) | Cross-reference breach data + Hunter enrichment + CNAM for fuller profile | Multiple sources combined | Good — composite profile from 3-4 sources |

### Tier 2 Vendor Summary

| Vendor | Cost | What It Adds |
|---|---|---|
| Everything from Tier 1 | $30.50/mo | Base breach + email + phone + social |
| **Hunter.io Starter** | $49/mo | Email finding, lead enrichment, domain search (500 searches/mo) |
| **Twilio Lookup** | ~$6-12/mo (100-200 CNAM lookups) | Phone → caller name resolution |
| **PACER** | ~$10-20/mo (typical usage) | Federal bankruptcy, civil, criminal filings |
| *or* **Snov.io** | $39/mo | Hunter.io alternative — email finder + verifier + drip campaigns |
| *or* **Apollo.io** | Free tier (then $49/mo) | Large database, prospecting API, email + phone finding |
| *or* **RocketReach** | $53/mo | Email + phone finding, 170 searches/mo |

**Recommended combo: Tier 1 + Hunter.io + Twilio = ~$86-92/mo**

---

## Tier 3: Full OSINT ($200-500/mo)

**Coverage: ~85% of BeenVerified features (17 of 20)**

Adding IntelligenceX for deep/dark web search, a property data API, and multiple breach providers for maximum coverage. At this level, GhostMCP rivals BeenVerified on most axes except freshness and relationship mapping.

### New Features Unlocked (vs Tier 2)

| BV Feature | How GhostMCP Delivers It | Vendor | Accuracy |
|---|---|---|---|
| **Property Records** | Full property details: owner, value, tax, deed history, characteristics | ATTOM Data ($250+/mo, 2500 records) | Excellent — 155M US properties |
| **Dark Web Monitoring** (full) | Tor-indexed content, pastes, darknet markets, breach forums | IntelligenceX ($100-400/mo) | Good — broadest dark web coverage available via API |
| **Breach Monitoring** (near-continuous) | Multiple breach providers cross-checked, stealer log coverage | DeHashed + Snusbase + IntelligenceX + HIBP | Very Good — multiple vantage points |
| **Background Check Report** | Enough data sources to compile a meaningful composite report | All of the above, custom report generation | Good — not FCRA-compliant, but comprehensive for OSINT |
| **Address History** (better) | Property ownership via ATTOM + breach data + IntelX archives | ATTOM + Snusbase + IntelX | Good — combines deeds, breaches, and archived data |

### Features Still NOT Satisfied

| BV Feature | Why Still Missing | Could Be Solved By |
|---|---|---|
| **Relatives & Associates** | Requires proprietary social graph DB or Facebook API access (deprecated) | Data broker licensing ($5K+/mo) |
| **Education** | No unified API, per-school databases | Manual research or data broker |
| **Professional Licenses** | Per-state, 50+ separate systems | Custom scrapers per state (legal gray area) |

### Tier 3 Vendor Summary

| Vendor | Cost | What It Adds |
|---|---|---|
| Everything from Tier 2 | ~$90/mo | Full breach + email enrichment + phone CNAM |
| **IntelligenceX** | $100-400/mo | Tor/darknet/paste search, archived web content, broadest indicator types |
| **ATTOM Data** | $250+/mo (2500 records) | Property records: owner, value, tax, deed, characteristics |
| **DeHashed** | $15-30/mo (subscription) | Second breach source for cross-referencing, broader VIN/address search |
| *or* **BreachSense** | Contact sales | Continuous breach monitoring, stealer logs, ransomware leak data |
| *or* **Intelligence Security** | Contact sales | Snusbase alternative, Telegram bot, free audit tools |

**Recommended combo: Tier 2 + IntelligenceX + ATTOM = ~$440-740/mo**

---

## Tier 4: Data Broker ($5,000+/mo)

**Coverage: ~95% of BeenVerified features (19 of 20)**

At this level you're licensing the same data feeds BeenVerified uses. This requires business agreements, compliance programs, and often FCRA/DPPA certification.

### Final Features Unlocked

| BV Feature | Vendor | Cost | Requirements |
|---|---|---|---|
| **Relatives & Associates** | LexisNexis Accurint, TLO (TransUnion) | $2,000-5,000/mo | Business license, permissible purpose |
| **Education** | National Student Clearinghouse API | $500+/mo | Institutional membership |
| **Professional Licenses** | State licensing board feeds (aggregated by LexisNexis) | Included in LexisNexis | Business agreement |
| **Comprehensive Address History** | USPS NCOALink + LexisNexis | $1,000-3,000/mo | USPS license agreement |
| **DMV / Vehicle Ownership** | State DMV data via DPPA-authorized access | Varies by state | DPPA permissible purpose certification |

### What Still Can't Be Replicated (the last 5%)

| Feature | Why |
|---|---|
| Real-time skip tracing | Requires live data feeds from utilities, telecoms, financial institutions |
| Credit header data | CRA (Consumer Reporting Agency) certification required — federal regulatory process |

---

## Side-by-Side Summary

| Feature | Free ($0) | Budget ($31) | Pro ($90) | Full OSINT ($450) | Broker ($5K+) |
|---|---|---|---|---|---|
| Phone validation | Y | Y | Y | Y | Y |
| Phone → name | - | Partial (breach) | CNAM (60%) | CNAM + breach | Full |
| Email reputation | Y | Y | Y | Y | Y |
| Email → person | - | Partial (breach) | Hunter.io | Hunter + IntelX | Full |
| Email → breach data | Metadata | Full details | Full details | Multi-source | Full |
| Username → platforms | Y (2500+ sites) | Y | Y | Y | Y |
| Social media profiles | Y | Y | Y | Y | Y |
| VIN decode | Y | Y | Y | Y | Y |
| Vehicle recalls | Y | Y | Y | Y | Y |
| Vehicle ownership | - | - | - | - | DMV data |
| Court records (federal) | Y | Y | Y | Y | Y |
| Court records (state) | URL gen | URL gen | URL gen | URL gen | Aggregated |
| Criminal records | URL gen | URL gen + breach | URL gen + breach | URL gen + breach | Full |
| Sex offender | URL gen | URL gen | URL gen | URL gen | Full |
| Property records | URL gen | URL gen | URL gen | ATTOM (full) | Full |
| Address history | URL gen | Partial (breach) | Partial (breach) | Breach + ATTOM | Full |
| Relatives/associates | URL gen | URL gen | URL gen | URL gen | Full |
| Employment | - | Partial (breach) | Hunter.io | Hunter + breach | Full |
| Education | - | - | - | - | Full |
| Professional licenses | - | - | - | - | Full |
| Bankruptcy/liens | - | - | PACER | PACER | Full |
| Breach monitoring | - | One-shot | One-shot | Near-continuous | Continuous |
| Dark web monitoring | - | - | - | IntelX | Full |
| Background report | - | Partial | Good | Comprehensive | Full |
| **Features covered** | **9/20** | **13/20** | **15/20** | **17/20** | **19/20** |
| **% of BV** | **~45%** | **~65%** | **~75%** | **~85%** | **~95%** |

---

## Vendor Master List

Every vendor referenced across all tiers, with API details:

| Vendor | Category | Free Tier | Paid From | API Type | Search Fields | Python |
|---|---|---|---|---|---|---|
| `phonenumbers` | Phone | Fully free (offline) | - | Library | Phone → validation, carrier type, region | `phonenumbers` |
| Veriphone | Phone | 1000 req/mo | $15/mo | REST | Phone → validity, carrier, type | `requests` |
| NumVerify | Phone | 100 req/mo (HTTP only) | $15/mo | REST | Phone → carrier, type, location | `requests` |
| OpenCNAM | Phone | 15 lookups/mo | $0.004/lookup | REST | Phone → caller name (US only) | `requests` |
| Twilio Lookup | Phone | No | $0.005/basic, $0.06/CNAM | REST | Phone → carrier, CNAM, SIM swap | `twilio` |
| EmailRep.io | Email | Yes (~50/day) | Contact | REST | Email → reputation, breach count, profiles | `requests` |
| Holehe | Email | Fully free (OSS) | - | Library | Email → 120+ site registration | `holehe` |
| Hunter.io | Email | 25/mo | $49/mo | REST | Domain → emails, name → email, enrichment | `pyhunter` |
| Snov.io | Email | 50 credits/mo | $39/mo | REST | Domain → emails, email verification | `requests` |
| Apollo.io | Email | Free tier | $49/mo | REST | Email + phone finding, prospecting | `requests` |
| RocketReach | Email | Limited | $53/mo | REST | Email + phone finding, 170 searches/mo | `requests` |
| VoilaNorbert | Email | 50 leads | $49/mo | REST | Email finding + verification | `requests` |
| HIBP | Breach | Metadata free | $3.50/mo (Core) | REST | Email → breaches, password hashes | `requests` |
| Snusbase | Breach | No | $27/mo | REST (2048/day) | Email, phone, name, username, IP | `requests` |
| LeakCheck | Breach | No | $10/mo | REST | Email, phone, username | `requests` |
| DeHashed | Breach | Monitoring free | ~$15-30/mo | REST | Email, phone, username, IP, VIN, address, hash | `requests` |
| IntelligenceX | Breach/DarkWeb | Rate-limited free | $100-400/mo | REST | Email, phone, IP, domain, URL, hash, BTC, CIDR | `requests` |
| LeakRadar | Breach | No | €29.99/mo | REST (30/sec) | Email, domain, stealer logs | `requests` |
| BreachSense | Breach | No | Contact sales | REST | Email, domain, credentials, stealer logs | `requests` |
| Intelligence Security | Breach | Free audit tools | Contact sales | REST + Telegram | Email, credentials, domain recon | `requests` |
| DataBreach.com | Breach | Free search | - | None (web only) | Email, name, address, phone, SSN, IP, username | Manual |
| Sherlock | Username | Fully free (OSS) | - | Library/CLI | Username → 400+ platforms | `sherlock-project` |
| Maigret | Username | Fully free (OSS) | - | Library/CLI | Username → 2500+ platforms + profile data | `maigret` |
| WhatsMyName | Username | Fully free (OSS) | - | JSON data | Username → 500+ sites | `requests` |
| CourtListener | Court | Free (5/min, 125/day) | Membership | REST + MCP | Party name → federal cases, dockets, opinions | `requests` |
| PACER | Court | - | $0.10/page | Web/CMECF | Federal filings, dockets, bankruptcy | `juriscraper` |
| NHTSA vPIC | Vehicle | Fully free | - | REST | VIN → full vehicle specs | `requests` |
| NHTSA Recalls | Vehicle | Fully free | - | REST | Vehicle → open recalls | `requests` |
| ATTOM Data | Property | No | $250+/mo | REST | Address → owner, value, tax, deed, characteristics | `requests` |
| SpiderFoot | OSINT Framework | OSS | HX (hosted) | REST (self) | Orchestrator — calls other APIs | `spiderfoot` |
| Recon-ng | OSINT Framework | OSS | - | CLI | Orchestrator — modular recon | Python framework |
| Maltego CE | OSINT Framework | Free edition | $999/yr (Pro) | Transforms | Graph analysis — calls other APIs via transforms | Java + transforms |
| Lampyre | OSINT Platform | No | Contact | Desktop | Multiple data feeds, scripting | Desktop app |

**Total unique vendors/tools: 33**

---

## Recommended Build Path for GhostMCP

### Sprint 4-5: Free Tier (6 tools, $0/mo)
1. `ghost_phone` — phonenumbers + Veriphone
2. `ghost_email` — EmailRep.io + Holehe
3. `ghost_username` — Sherlock/Maigret
4. `ghost_vin` — NHTSA vPIC + Recalls
5. `ghost_court` — CourtListener API
6. `ghost_people` — URL generator (15+ sites)

### Sprint 6: Breach Tier ($31/mo)
7. `ghost_breach` — HIBP + Snusbase integration
   - Email, phone, name, username → breach records
   - Two-layer model: `metadata_only` (default) / `full` (operator opt-in)

### Sprint 7: Professional Tier ($90/mo, optional keys)
8. `ghost_phone` upgrade — Twilio CNAM
9. `ghost_email` upgrade — Hunter.io enrichment
10. `ghost_report` — Composite report generator (PDF/HTML)

### Future: Full OSINT ($450+/mo, optional keys)
11. `ghost_property` — ATTOM Data integration
12. `ghost_darkweb` — IntelligenceX integration
13. Cross-referencing / link analysis engine

---

## Key Takeaways

1. **The $0 → $31/mo jump is the biggest value inflection point.** Adding HIBP + Snusbase unlocks breach-sourced PII that would otherwise cost $5K+/mo through data brokers. This takes coverage from 45% to 65%.

2. **Breach data is the great equalizer.** Most of the "licensed" data that separates BeenVerified from free OSINT tools (address history, employment, phone associations) is available through breach databases for a fraction of the cost.

3. **The URL generator pattern is underrated.** Free people-search sites (ThatsThem, FastPeopleSearch, USPhonebook) contain excellent data. Rather than scraping them (illegal, fragile), generating links is legal, sustainable, and free.

4. **Three things are truly walled off:** DMV records (DPPA), credit data (FCRA/CRA), and real-time skip tracing. No amount of breach data or API spending replaces these. Only data broker licensing ($5K+/mo) opens these doors.

5. **33 vendors exist in this space.** GhostMCP should support all of them through a pluggable provider architecture. Users bring their own API keys; GhostMCP orchestrates the queries.
