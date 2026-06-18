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

## Search Types: What You Can Actually Do at Each Tier

This is the practical view — what searches can an operator run, what comes back, and how reliable is it.

### Search Type Index

| # | Search Type | Input | What You're Trying to Find |
|---|---|---|---|
| S1 | **Search by Name** | First + Last name (+ city/state optional) | Everything about this person |
| S2 | **Search by Email** | Email address | Who owns this email, what's exposed |
| S3 | **Search by Phone** | Phone number | Who owns this number, carrier, name |
| S4 | **Search by Username** | Social handle | Which platforms, real identity behind it |
| S5 | **Search by Address** | Street address | Who lives/lived there, property details |
| S6 | **Search by VIN** | Vehicle Identification Number | Vehicle specs, history, owner |
| S7 | **Search by Domain** | Company domain | Employees, emails, tech stack |
| S8 | **Search by IP** | IP address | Threat intel, geolocation, breach exposure |
| S9 | **Court Record Search** | Name or case number | Criminal/civil history, filings |
| S10 | **Background Check** | Name + DOB/location | Composite report across all sources |

---

### S1: Search by Name

*"Tell me everything about John Smith in Dallas, TX"*

| Tier | What Comes Back | Accuracy | Sources |
|---|---|---|---|
| **Free ($0)** | URL links to 15+ people-search sites where user clicks through manually. Federal court cases if any. Sex offender registry check link. | **Low-Indirect** — GhostMCP doesn't return PII directly, it generates links. The *sites* have good data, but you're doing manual work. | URL gen (ThatsThem, FastPeopleSearch, Whitepages, Spokeo, 411, LinkedIn, Facebook), CourtListener, NSOPW |
| **Budget ($31)** | Everything above + breach records tied to that name (emails, phones, passwords, addresses from breached databases). | **Moderate** — Breach data returns real PII but is name-collision-heavy. "John Smith" will return thousands of results. Need city/state/email to narrow. Freshness: data is from breach date, not current. | + Snusbase (name search), HIBP |
| **Pro ($90)** | Everything above + if you find their email from breach data, you can enrich it: employer, title, social handles, location via Hunter.io. CNAM on phone numbers found. Bankruptcy/lien records from PACER. | **Good** — The chain works: name → breach data → email → Hunter enrichment → employer/social profiles. CNAM resolves ~45% of phone numbers found. Composite profile is starting to look solid. | + Hunter.io, Twilio CNAM, PACER |
| **Full ($450)** | Everything above + property ownership records (current/past properties, values, tax history). Dark web exposure. Multiple breach sources cross-referenced. Enough for a composite background report. | **Very Good** — Multiple data sources corroborate each other. Property records confirm addresses. Breach cross-referencing reduces false positives. Dark web shows active threat exposure. | + ATTOM, IntelligenceX, DeHashed |
| **Broker ($5K+)** | Full BeenVerified-equivalent: verified current address, all historical addresses, relatives, associates, education, employment, licenses, DMV data, comprehensive criminal. | **Excellent** — Live data feeds, not snapshots. Verified, deduplicated, cross-referenced against authoritative sources. | LexisNexis, TLO, USPS NCOALink |

---

### S2: Search by Email

*"What can you tell me about user@example.com?"*

| Tier | What Comes Back | Accuracy | Sources |
|---|---|---|---|
| **Free ($0)** | Reputation score (suspicious? legit?), breach count (how many breaches), which 120+ websites this email is registered on, social profiles linked to it, domain age/registration. | **Good** — EmailRep gives a solid risk signal. Holehe confirms which platforms they use (Twitter, GitHub, Spotify, etc.). No name/address/phone returned. | EmailRep.io, Holehe |
| **Budget ($31)** | Everything above + full breach details: which specific breaches, what data classes leaked (passwords, addresses, phone numbers, DOBs), actual PII from breach records (name, address, phone if in breach data). | **Very Good** — If the email appears in Exactis, PeopleDataLabs, or Apollo breaches, you get name, address, phone, employer, and more. ~70% of active emails appear in at least one breach with PII. | + HIBP Core, Snusbase |
| **Pro ($90)** | Everything above + professional enrichment: full name, job title, company, LinkedIn URL, Twitter handle, location, other emails at the same domain. Email verification (deliverable? catch-all? disposable?). | **Very Good to Excellent** — Hunter.io enrichment is highly accurate for business emails (~85% match rate). Weaker for personal Gmail/Yahoo addresses (~30% match). Combined with breach data, you often get a complete profile. | + Hunter.io (or Snov.io/Apollo) |
| **Full ($450)** | Everything above + dark web exposure (is this email for sale on darknet markets?), archived web appearances, Tor-indexed content mentioning this email. Second breach source for cross-validation. | **Excellent** — Multiple vantage points dramatically reduce false negatives. IntelX catches things Snusbase misses and vice versa. | + IntelligenceX, DeHashed |
| **Broker ($5K+)** | Everything above + utility connections, verified current address, credit header data (name, address from credit file — not credit score). | **Excellent** — Authoritative, current data. | LexisNexis, Experian non-credit |

---

### S3: Search by Phone

*"Who owns 214-555-1234?"*

| Tier | What Comes Back | Accuracy | Sources |
|---|---|---|---|
| **Free ($0)** | Is it valid? Mobile/landline/VOIP? Which carrier (e.g., T-Mobile)? What region/timezone? Formatted in E.164/national/international. URL links to free reverse-phone sites. | **High for validation, zero for identity.** You know it's a valid T-Mobile cell in Dallas, TX — but not who owns it. URL links to USPhonebook/ThatsThem may show owner if user clicks through. | `phonenumbers`, Veriphone, URL gen |
| **Budget ($31)** | Everything above + breach records associated with this phone number: emails, names, passwords, addresses found in breaches where this phone was a data field. | **Moderate** — Phone numbers appear in fewer breaches than emails (~40% hit rate vs ~70% for email). When there's a hit, the data is usually accurate. Results may include old owners if number was recycled. | + Snusbase (phone search) |
| **Pro ($90)** | Everything above + **CNAM caller name**: the actual registered subscriber name from the carrier's CNAM database. Then chain: CNAM name → Hunter.io to find their email/employer. | **Moderate-Good** — CNAM works on ~60% of US landlines and ~30% of mobile numbers. When it works, the name is authoritative (it's from the carrier). Mobile CNAM often shows the carrier name instead of the person. VoIP numbers rarely have CNAM. | + Twilio CNAM, Hunter.io (chained) |
| **Full ($450)** | Everything above + IntelX/DeHashed cross-reference (more breach sources = higher hit rate on phone→identity). Property records can confirm address if name is resolved. | **Good** — Multiple breach sources + CNAM + property cross-reference builds a strong composite. Still ~20-30% of mobile numbers remain unresolvable. | + IntelligenceX, DeHashed, ATTOM |
| **Broker ($5K+)** | Carrier records, subscriber name, service address, account type, connected devices. Real-time. | **Excellent** — Direct carrier data. | Telecom data licensing |

---

### S4: Search by Username

*"Find everything about username 'darkphoenix42'"*

| Tier | What Comes Back | Accuracy | Sources |
|---|---|---|---|
| **Free ($0)** | Which platforms this username exists on (up to 2500+ sites checked). Profile URLs. Profile data extraction (bio, links, avatar) where available. Categorized by platform type (social, gaming, dev, forum, dating, etc.). | **Excellent** — This is where free OSINT shines. Maigret checks 2500+ sites, extracts profile data, and categorizes results. Better coverage than BeenVerified. False positives: ~5-10% (common usernames match unrelated accounts). | Sherlock, Maigret, WhatsMyName |
| **Budget ($31)** | Everything above + breach records where this username was a login credential. May reveal associated email, password, IP address, name from breached site databases. | **Very Good** — Username→breach search often reveals the email address behind the account, which then unlocks email-based searches. ~50% of unique usernames appear in at least one breach. | + Snusbase (username search) |
| **Pro ($90)** | Everything above + if breach data reveals an email, chain into Hunter.io enrichment for professional profile. | **Very Good** — The chain username→breach→email→Hunter gives you a path from anonymous handle to real identity in many cases. | + Hunter.io (chained via discovered email) |
| **Full ($450)** | Everything above + IntelX searches for this username across dark web forums, paste sites, Tor-indexed content, breach forum posts. | **Excellent** — IntelX catches dark web forum posts, paste dumps, and Tor content that Snusbase doesn't index. Valuable for threat actor attribution. | + IntelligenceX |
| **Broker ($5K+)** | Same — data brokers don't add much for username search. OSINT tools already dominate this category. | **No improvement** — free tools are already best-in-class here. | N/A |

---

### S5: Search by Address

*"Who lives at 1234 Main St, Dallas, TX 75201?"*

| Tier | What Comes Back | Accuracy | Sources |
|---|---|---|---|
| **Free ($0)** | URL links to people-search sites for reverse address lookup. Geographic data (parcel boundaries, building footprint) from OpenStreetMap. | **Low-Indirect** — You're generating links. The sites behind those links (Whitepages, ThatsThem) often show current residents, but GhostMCP doesn't extract the data — user clicks through. | URL gen, OpenStreetMap/Overpass |
| **Budget ($31)** | Everything above + breach records containing this address (from breaches that included address fields like Exactis, marketing databases). | **Low-Moderate** — Addresses are less commonly indexed in breach search APIs than email/phone. Snusbase doesn't support address search well. DeHashed does, but it's Tier 3. | + Snusbase (limited address search) |
| **Pro ($90)** | Same as Budget for address search — no new sources add address lookup capability at this tier. | **Low-Moderate** — Address search is a gap at this tier. The Pro tier additions (Hunter, Twilio, PACER) don't help with address→resident lookup. | Same as Budget |
| **Full ($450)** | **Major unlock:** ATTOM property records → current owner, purchase date, sale price, tax assessment, property details. DeHashed address field search for breach data. County assessor URL generator. | **Very Good** — ATTOM returns authoritative property ownership data (from county recorder deeds). You know who *owns* it. Doesn't tell you who *rents/lives* there if they're not the owner. | + ATTOM Data, DeHashed (address search) |
| **Broker ($5K+)** | Current + historical residents (including renters), utility connections, forwarding addresses. | **Excellent** — LexisNexis/TLO have utility connection data showing who has power/gas/internet at an address. | LexisNexis, utility data feeds |

---

### S6: Search by VIN

*"What can you tell me about VIN 1HGCM82633A004352?"*

| Tier | What Comes Back | Accuracy | Sources |
|---|---|---|---|
| **Free ($0)** | **Full vehicle specifications:** Make, model, year, trim, engine (displacement, cylinders, fuel type), body type, drive type, transmission, safety features (ABS, airbags, ESC), manufacturer name + country, plant city, GVWR. Open safety recalls with campaign details, component, remedy. Consumer complaints count/summary. | **Excellent** — NHTSA vPIC is the authoritative source. It's the same database used by DMVs, insurance companies, and law enforcement. 100% accuracy on specs. Recall data is definitive. | NHTSA vPIC, NHTSA Recalls, NHTSA Complaints |
| **Budget ($31)** | Everything above. Breach data doesn't add vehicle info. | **Same — Excellent** | Same |
| **Pro ($90)** | Everything above. No new VIN sources at this tier. | **Same — Excellent** | Same |
| **Full ($450)** | Everything above + DeHashed supports VIN as a search field — may return breach records where VIN was stored (insurance databases, dealer systems, telematics breaches). | **Excellent+** — Rare to find VIN in breach data, but when you do, it may link to owner name, address, email from the insurance/dealer breach. | + DeHashed (VIN search) |
| **Broker ($5K+)** | Everything above + vehicle ownership (registered owner name, address), title history, odometer readings, total loss/salvage status, lien information. | **Excellent** — DMV data via DPPA. NMVTIS for title history. | DMV data, NMVTIS, AutoCheck/Carfax |

---

### S7: Search by Domain

*"What can you find about employees at acmecorp.com?"*

| Tier | What Comes Back | Accuracy | Sources |
|---|---|---|---|
| **Free ($0)** | Email reputation for any known emails @domain. GhostMCP existing tools: subdomains (cert transparency), DNS records, tech stack fingerprinting, TLS certificate details. | **Good for infrastructure, zero for people.** You can map their tech stack and subdomains but can't enumerate employees without paid APIs. | GhostMCP ghost_subdomains, ghost_cert, ghost_recon, EmailRep.io |
| **Budget ($31)** | Everything above + breach records containing @domain emails — reveals employee names, personal emails, passwords, and which breaches exposed them. | **Good** — Breach data often reveals dozens of employee emails for medium-large companies. Shows who reused passwords, who's on dark web markets. Useful for social engineering assessment. | + Snusbase (domain search), HIBP (domain search at Pro tier) |
| **Pro ($90)** | **Major unlock:** Hunter.io Domain Search returns all known emails at a domain with: name, position, department, LinkedIn URL, confidence score. Email pattern detection (first.last@, f.last@, etc.). Up to 100 emails per domain on Starter plan. | **Very Good** — Hunter.io is the industry standard for domain→employee enumeration. ~85% accuracy on email patterns. Position/department data is ~60% accurate (scraped from LinkedIn, press releases, etc.). | + Hunter.io Domain Search, Snov.io, Apollo |
| **Full ($450)** | Everything above + IntelX searches for domain mentions across dark web, paste sites, Tor forums. Comprehensive breach cross-referencing across multiple providers. | **Excellent** — Full picture: every employee email found in breaches + Hunter enrichment + dark web exposure. Good enough for a professional security assessment of the organization's exposure. | + IntelligenceX, DeHashed |
| **Broker ($5K+)** | Same — corporate domain searches are well-served by Pro/Full tiers. | **Marginal improvement** — data brokers add little for domain OSINT. | N/A |

---

### S8: Search by IP Address

*"What's associated with IP 203.0.113.42?"*

| Tier | What Comes Back | Accuracy | Sources |
|---|---|---|---|
| **Free ($0)** | GhostMCP existing tools: threat intelligence feeds (URLhaus, ThreatFox, Feodo Tracker, RansomWatch). Is this IP associated with malware C2, botnets, or ransomware? | **Good for threat intel.** GhostMCP's `ghost_threat` tool already checks 4 threat feeds. No geolocation or ASN info at this tier (could add free MaxMind GeoLite2). | GhostMCP ghost_threat |
| **Budget ($31)** | Everything above + breach records associated with this IP (login IPs captured in breaches, VPN service breaches, webmail login logs). | **Moderate** — IP→breach search is niche. Some breaches captured login IPs (especially webmail and VPN services). When there's a hit, you get the user's email/username who logged in from that IP. | + Snusbase (IP search) |
| **Pro ($90)** | Same as Budget. Hunter/Twilio/PACER don't add IP search capability. | **Moderate** | Same as Budget |
| **Full ($450)** | Everything above + IntelX IP search across dark web, paste sites, Tor exit nodes. DeHashed IP field search for broader breach coverage. | **Good** — IntelX is the best API for IP→threat attribution. Catches things threat feeds miss: Tor exit node correlations, paste dumps with IP lists, dark web forum posts mentioning specific IPs. | + IntelligenceX, DeHashed |
| **Broker ($5K+)** | Same — IP search is an infosec domain, not a data broker domain. | **No improvement** — OSINT tools are already best-in-class. | N/A |

---

### S9: Court Record Search

*"Has Jane Doe been involved in any lawsuits?"*

| Tier | What Comes Back | Accuracy | Sources |
|---|---|---|---|
| **Free ($0)** | Federal court cases: case name, docket number, court, filing date, parties, attorneys, judges. Opinions/rulings text. RECAP archive of PACER filings. URL links to Judyrecords (600M state cases searchable) and state court portals. | **Good for federal, partial for state.** CourtListener covers all federal courts comprehensively. State coverage varies — some states are well-covered via RECAP, most are URL-gen only. | CourtListener/RECAP, Judyrecords URL, state court URLs |
| **Budget ($31)** | Same as Free. Breach data doesn't add court records. | **Same — Good** | Same |
| **Pro ($90)** | Everything above + PACER direct access for federal filings not yet in RECAP. Bankruptcy filings, liens, judgments from federal courts. ~$0.10/page, $3 cap per document. | **Very Good** — PACER fills gaps in RECAP. Bankruptcy/lien data is particularly valuable — this is financial history that BeenVerified charges for. Typical cost: $10-20/mo for moderate research. | + PACER ($0.10/page) |
| **Full ($450)** | Same as Pro. Property records from ATTOM may cross-reference with lien data. | **Very Good** | Same + ATTOM (lien cross-ref) |
| **Broker ($5K+)** | All federal + state court records aggregated, normalized, and searchable via single API. Continuous monitoring for new filings. | **Excellent** — UNICOURT ($500+/mo) or LexisNexis provides unified federal+state coverage. | UNICOURT, LexisNexis |

---

### S10: Background Check (Composite Report)

*"Run a full background on this person"*

| Tier | What Comes Back | Accuracy | Report Quality |
|---|---|---|---|
| **Free ($0)** | A collection of URL links to manually check + whatever CourtListener returns for court records + VIN specs if they have a vehicle + username platform hits. No unified report. | **Low** — Too fragmented. The user is doing most of the work clicking through URLs. Not enough data for a meaningful automated report. | No report — just links |
| **Budget ($31)** | Person profile reconstructed from breach data (name, emails, phones, addresses, passwords, employers from breaches) + all Free tier data. Can generate a partial structured report. | **Moderate** — Breach data is the backbone. Report has real PII but with caveats: data may be stale, multiple people may share a name, no verification against authoritative sources. Useful for preliminary research. | Partial report — breach-reconstructed profile + court records + social accounts |
| **Pro ($90)** | Breach profile + Hunter.io professional enrichment + CNAM phone resolution + bankruptcy/lien records from PACER + social media platforms. Cross-referenced across sources. Can generate a good structured report with confidence scores per data point. | **Good** — Multiple sources corroborate: if breach data says they work at AcmeCorp AND Hunter.io confirms an email at acmecorp.com AND LinkedIn profile matches, confidence is high. Report flags contradictions between sources. | Good report — multi-source composite with confidence ratings, source attribution |
| **Full ($450)** | Everything above + property records (homes owned, values, deed history) + dark web exposure scan + multiple breach provider cross-validation. Comprehensive structured report with every data point sourced and rated. | **Very Good** — This is a legitimate OSINT dossier. Property records add financial context. Dark web exposure adds threat assessment. Multiple breach sources reduce false negatives. Still lacks relatives/education/licenses. | Comprehensive report — property, financial, professional, criminal, breach exposure, dark web, social media |
| **Broker ($5K+)** | Full BeenVerified-equivalent report: verified identity, all addresses, relatives, education, employment, licenses, criminal (all states), vehicles owned, credit header. FCRA-compliant format if needed. | **Excellent** — Authoritative, current, verified against primary sources. | Full professional background report |

---

### Accuracy Rating Summary (All Search Types x All Tiers)

Scale: **-** = not available, **L** = Low, **M** = Moderate, **G** = Good, **VG** = Very Good, **E** = Excellent

| Search Type | Free ($0) | Budget ($31) | Pro ($90) | Full ($450) | Broker ($5K+) |
|---|---|---|---|---|---|
| **S1: By Name** | L (links only) | M (breach PII, name collisions) | G (breach + enrichment + CNAM chain) | VG (+ property, dark web, cross-ref) | E (live verified data) |
| **S2: By Email** | G (reputation + accounts) | VG (breach PII, ~70% hit rate) | VG-E (+ professional enrichment) | E (multi-source, dark web) | E (+ utility, credit header) |
| **S3: By Phone** | High validation, no identity | M (~40% breach hit rate) | M-G (CNAM 60% landline/30% mobile) | G (+ multi-breach cross-ref) | E (carrier subscriber data) |
| **S4: By Username** | E (2500+ sites, best-in-class) | VG (+ breach credentials, ~50% hit) | VG (+ email chain to Hunter) | E (+ dark web forums) | E (same — free is already best) |
| **S5: By Address** | L (links only) | L-M (limited breach address search) | L-M (no new address sources) | VG (ATTOM property ownership) | E (residents, utilities, forwarding) |
| **S6: By VIN** | E (NHTSA — authoritative) | E (same) | E (same) | E (+ breach VIN if available) | E (+ owner, title history, liens) |
| **S7: By Domain** | G (infrastructure only) | G (+ breach employee emails) | VG (Hunter.io employee enum, ~85%) | E (+ dark web, multi-breach) | E (marginal improvement) |
| **S8: By IP** | G (threat feeds) | M (limited breach IP data) | M (same) | G (IntelX dark web, Tor correlation) | G (same — OSINT is best here) |
| **S9: Court Records** | G (federal strong, state partial) | G (same) | VG (+ PACER bankruptcy/liens) | VG (+ property lien cross-ref) | E (unified federal + state) |
| **S10: Background** | L (fragmented links) | M (breach-reconstructed profile) | G (multi-source composite report) | VG (comprehensive OSINT dossier) | E (full professional report) |

### Where Each Tier Punches Above Its Weight

| Tier | Strongest Search Types | Why |
|---|---|---|
| **Free ($0)** | Username (E), VIN (E), Email reputation (G) | OSS tools (Maigret/Sherlock) and government APIs (NHTSA) are genuinely world-class at these specific tasks. |
| **Budget ($31)** | Email→identity (VG), Username→identity (VG) | Breach data is the great equalizer. $31/mo unlocks PII that data brokers charge $5K/mo for. |
| **Pro ($90)** | Domain→employees (VG), Background check (G), Court records (VG) | Hunter.io + PACER fill the professional/financial research gaps. The breach→email→Hunter chain creates a name→identity pipeline. |
| **Full ($450)** | Address→owner (VG), Background check (VG), Dark web (E) | ATTOM property data is the big unlock. IntelX provides visibility into dark web that no cheaper option matches. |
| **Broker ($5K+)** | Name→everything (E), Address→residents (E), Background (E) | Live, verified, comprehensive. But only 10-15% better than Full tier for 10x the cost. |

### The Diminishing Returns Curve

```
Coverage %
100 |                                                    _____ Broker ($5K+)
 95 |                                               ____/
 90 |                                          ____/
 85 |                                     ____/  Full ($450)
 80 |                                ____/
 75 |                           ____/  Pro ($90)
 70 |                      ____/
 65 |                 ____/  Budget ($31)
 60 |            ____/
 55 |       ____/
 50 |  ____/
 45 | /  Free ($0)
 40 |/
    +-----|---------|---------|---------|---------|-----> $/mo
    $0   $31       $90      $450    $5,000
```

**The steepest value curve is $0→$31.** After $450/mo, you're paying exponentially more for marginal gains. The $31→$90 jump is the second-best value, primarily because Hunter.io unlocks the email→professional-identity pipeline that makes name searches actually useful.

---

## API Rate Limits & Monthly Quotas by Provider

Reference table for capacity planning. How many searches can you run before hitting walls?

### Paid Providers

| Provider | Plan | Monthly Requests | Daily Cap | Per-Second | Cost/Query | Notes |
|---|---|---|---|---|---|---|
| **HIBP Core** | $3.50/mo | ~432,000/mo | ~14,400/day | 10/min (0.17/sec) | ~$0.000008 | Rate-limited, not volume-limited. Stay under 10/min and run all month. |
| **HIBP Pro** | $10/mo | ~432,000/mo | ~14,400/day | 10/min | ~$0.000023 | Same rate as Core. Adds k-anonymity email search, domain search, stealer logs. |
| **Snusbase** | $27/mo | ~61,440/mo | 2,048/day | ~1-2/sec (est.) | ~$0.0004 | Hard cap: 2,048 API req/day. Resets daily. API included with any paid plan. |
| **LeakCheck** | $10/mo | Varies | ~100-1000/day (est.) | Not published | ~$0.01-0.10 | Less transparent on limits. Smaller index than Snusbase. |
| **LeakRadar** | €29.99/mo | **Unlimited** searches | Unlimited | **30/sec** | €0 per search | Best rate limit of any breach provider. Quota on "cleartext unlocks" not searches. |
| **DeHashed** | $15-30/mo | Varies by plan | Varies | Not published | ~$0.02/query (est.) | Freemium monitoring; API on paid plans. Broadest field coverage (VIN, address, hash). |
| **IntelligenceX** | $100-400/mo | Varies by plan | Varies | Not published | Varies | Free tier is heavily rate-limited. Paid plans unlock Tor/darknet/paste indexing. |
| **Hunter.io Starter** | $49/mo | **500 searches**/mo | ~17/day | Not rate-limited | $0.098/search | Hard cap at 500. Each domain lookup, email finder, or verification = 1 search. 1,000 verifications included separately. **Bottleneck — be selective.** |
| **Snov.io Starter** | $39/mo | 1,000 credits/mo | ~33/day | Not published | $0.039/credit | 1 credit = 1 email found. More generous than Hunter for email finding. |
| **Apollo.io Free** | $0 | 300 emails/mo | ~10/day | Not published | $0 | Free: 300 email, 60 mobile credits. Paid ($49/mo): 2,400 email, 120 mobile. |
| **RocketReach** | $53/mo | 170 lookups/mo | ~6/day | Not published | $0.31/lookup | Smallest quota but highest data quality for professional emails. |
| **Twilio CNAM** | Pay-per-use | **Unlimited** | Unlimited | ~25/sec | **$0.06/lookup** | No monthly cap — pure pay-per-use. $50 budget = 833 lookups. $10 = 166. |
| **OpenCNAM** | Free (15) + pay | 15 free/mo, then unlimited | Unlimited | Not published | $0.004/lookup | 15x cheaper per-lookup than Twilio but less data returned. |
| **PACER** | Pay-per-page | **Unlimited** | Unlimited | N/A (web) | **$0.10/page** ($3 max/doc) | $20/mo budget = 200 pages or ~60-70 documents. |
| **BreachSense** | Contact sales | Unknown | Unknown | Unknown | Unknown | Enterprise/sales-driven pricing. Continuous monitoring focus. |
| **Intelligence Security** | Contact sales | Unknown | Unknown | Unknown | Unknown | Snusbase competitor. Has free audit tools but API pricing opaque. |

### Free Providers

| Provider | Monthly Requests | Daily Cap | Speed | Notes |
|---|---|---|---|---|
| `phonenumbers` | **Unlimited** (offline) | N/A | Instant | Local library — no network calls, no rate limits. |
| Veriphone | 1,000/mo | ~33/day | Fast | Resets monthly. Good free tier. |
| NumVerify | 100/mo (HTTP only) | ~3/day | Fast | Free tier is HTTP only (no HTTPS!). Very limited. |
| EmailRep.io | ~1,500/mo (est. 50/day) | ~50/day | Fast | Undocumented limit but stable. Free with API key registration. |
| Holehe | **Unlimited** (but slow) | N/A | **2-5 min/scan** | Checks 120+ sites per email. Each site = 1 HTTP request. Slow by nature. |
| Sherlock | **Unlimited** (but slow) | N/A | **2-5 min/scan** | Checks 400+ sites per username. Same slowness issue. |
| Maigret | **Unlimited** (but slow) | N/A | **3-8 min/scan** | Checks 2500+ sites. Slowest but most comprehensive. |
| WhatsMyName | **Unlimited** | N/A | ~1-2 min | ~500 sites. Faster than Maigret, fewer sites. |
| NHTSA vPIC | **Unlimited** (throttled) | N/A | Fast | Government API. No hard cap, automated traffic management. Batch: 50 VINs/req. |
| NHTSA Recalls | **Unlimited** (throttled) | N/A | Fast | Same as vPIC. |
| CourtListener | 3,750/mo | 125/day (50/hr, 5/min) | Fast | Free tier. Membership gets higher limits. |

### Practical Capacity at Each Tier

For a typical investigator running ~20-30 searches/day:

| Tier | Limiting Provider | 20 searches/day | Monthly Headroom | Bottleneck? |
|---|---|---|---|---|
| **Free ($0)** | CourtListener (125/day) | 20/day = 16% of cap | 84% headroom | No — all free providers can handle 20/day easily |
| **Budget ($31)** | Snusbase (2,048/day) | 20/day = 1% of cap | 99% headroom | No — Snusbase is generous |
| **Pro ($90)** | Hunter.io (500/mo total) | 20/day burns it in **25 days** | **Runs out day 25** | **YES — Hunter.io is the bottleneck.** Must be selective about which queries trigger enrichment. |
| **Full ($450)** | Same Hunter.io bottleneck | Same | Same | Smart routing needed: only call Hunter on high-confidence business emails |

**Mitigation for Hunter.io bottleneck:** The `ghost_email` tool should only trigger Hunter enrichment when (a) the email domain is a company domain (not gmail/yahoo/hotmail), and (b) no breach data already provides the person's identity. This conserves the 500/mo quota for cases where it adds value.

---

1. **The $0 → $31/mo jump is the biggest value inflection point.** Adding HIBP + Snusbase unlocks breach-sourced PII that would otherwise cost $5K+/mo through data brokers. This takes coverage from 45% to 65%.

2. **Breach data is the great equalizer.** Most of the "licensed" data that separates BeenVerified from free OSINT tools (address history, employment, phone associations) is available through breach databases for a fraction of the cost.

3. **The URL generator pattern is underrated.** Free people-search sites (ThatsThem, FastPeopleSearch, USPhonebook) contain excellent data. Rather than scraping them (illegal, fragile), generating links is legal, sustainable, and free.

4. **Three things are truly walled off:** DMV records (DPPA), credit data (FCRA/CRA), and real-time skip tracing. No amount of breach data or API spending replaces these. Only data broker licensing ($5K+/mo) opens these doors.

5. **33 vendors exist in this space.** GhostMCP should support all of them through a pluggable provider architecture. Users bring their own API keys; GhostMCP orchestrates the queries.
