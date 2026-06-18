# GhostMCP Issue: OSINT Search Anti-Greediness

## Title
OSINT search strategy: prevent greedy queries and distribute across engines

## Labels
enhancement, osint

## Body

### Problem

When performing OSINT background checks (e.g., company research, entity profiling), the `ghost_search` and `ghost_dork` tools allow the caller to stuff all desired facts into a single query string. This is bad tradecraft:

1. **Greedy queries fail** -- search engines return zero results when too many terms are combined (observed: 0/15 queries returned results during a Dashingsoft OSINT session)
2. **Reveals search heuristics** -- a single query containing `company name + registration number + government + governance + cybersecurity law` tips your intent to anyone monitoring search traffic
3. **Single engine dependency** -- all queries go to one engine (or auto-fallback), rather than spreading across engines to avoid rate limiting and detection

### Observed Behavior

During an OSINT research session on a Chinese software company:
- `ghost_search(query='Dashingsoft PyArmor company China Jondy Zhao corporate registration')` -> 0 results
- `ghost_search(query='大连鼎信软件 Dashingsoft Dalian China company registration government')` -> 0 results
- `ghost_search(query='Dashingsoft pyarmor China state cybersecurity law data compliance')` -> 0 results

All three queries were too greedy. Each should have been 5-10 separate focused queries distributed across different search engines.

### Expected Behavior

When GhostMCP detects an OSINT-pattern query (long query string, multiple proper nouns, entity research indicators), it should:

1. **Decompose the query** into atomic fact-seeking sub-queries (1-3 terms each)
2. **Distribute sub-queries across available engines** (serper, google, duckduckgo) rather than hammering one
3. **Stagger timing** between queries to avoid rate limiting
4. **Aggregate results** and deduplicate before returning

#### Example Decomposition

Input: `'Dashingsoft PyArmor company China Jondy Zhao corporate registration'`

Should become:
- Engine A: `'Dashingsoft company'`
- Engine B: `'Jondy Zhao PyArmor'`
- Engine C: `'Dashingsoft China registration'`
- Engine A: `'德新软件科技'` (if Chinese entity detected)
- Engine B: `'PyArmor dashingsoft.com'`

### Suggested Implementation

- Add an `osint_mode` or `spread` parameter to `ghost_search` that enables query decomposition
- Or: build a higher-level `ghost_osint_entity(name, type='company')` tool that handles the decomposition internally
- Respect the existing `paranoia` levels -- higher paranoia should spread more aggressively across engines and add delays
- Consider automatic language expansion for non-English entities (e.g., detect Chinese company name from ICP registration and search in both English and Chinese)

### Impact

Without this, OSINT research through GhostMCP requires the human operator to manually decompose queries and call ghost_search repeatedly with single terms -- defeating the purpose of having a search tool.
