# Feature: Brave Search API Integration

**Date:** 2026-06-18 (proposed) · **Implemented:** shipped to `main`
**Status:** IMPLEMENTED
**Priority:** Medium

> **This feature has shipped.** The design below is retained as a record.
> Live code: `ghostmcp/engines/brave.py` (`BraveEngine`) and
> `ghostmcp/engines/brave_media.py` (`BraveMediaEngine` — images/videos/news),
> registered in `ghostmcp/mcp.py`. Tests: `tests/test_brave.py` (22 tests).
> Exposed via `ghost_search(engine="brave")` and the media search tool.

---

## Summary

Add Brave Search API as a search engine option in GhostMCP. Brave provides a
privacy-focused, independent search index with structured JSON responses,
eliminating the HTML scraping fragility of DDG Lite and Google.

## Why Brave

| Advantage | Detail |
|-----------|--------|
| Independent index | Not a Google/Bing reskin — genuinely different results |
| Privacy-first | No user tracking, aligns with GhostMCP's ethos |
| Structured JSON | Proper API — no HTML parsing, no regex, no breakage |
| Free tier | 2,000 queries/month (sufficient for dev/personal use) |
| AI Summarizer | Optional AI-generated answer alongside web results |
| News search | Dedicated news endpoint for current events |
| Low rate limiting | Generous limits compared to DDG's aggressive throttling |

## API Details

**Base URL:** `https://api.search.brave.com/res/v1/web/search`

**Authentication:** API key via `X-Subscription-Token` header

**Free tier:** 2,000 queries/month (no credit card required)

**Sign up:** https://brave.com/search/api/

**Request:**
```bash
curl -s "https://api.search.brave.com/res/v1/web/search?q=Python+asyncio" \
  -H "X-Subscription-Token: YOUR_API_KEY" \
  -H "Accept: application/json"
```

**Response:**
```json
{
  "query": {"original": "Python asyncio"},
  "web": {
    "results": [
      {
        "title": "Async IO in Python: A Complete Walkthrough",
        "url": "https://realpython.com/async-io-python/",
        "description": "This tutorial will give you a firm grasp...",
        "age": "2 years ago",
        "language": "en"
      }
    ]
  }
}
```

**Parameters:**
| Param | Type | Description |
|-------|------|-------------|
| `q` | string | Search query (required) |
| `count` | int | Results per page (max 20, default 10) |
| `offset` | int | Pagination offset |
| `country` | string | Country code (e.g. `US`, `GB`, `DE`) |
| `search_lang` | string | Language code (e.g. `en`, `es`) |
| `safesearch` | string | `off`, `moderate`, `strict` |
| `freshness` | string | `pd` (past day), `pw` (past week), `pm` (past month) |

**Additional Endpoints:**
| Endpoint | URL | Description |
|----------|-----|-------------|
| Web Search | `/res/v1/web/search` | Standard web results |
| News Search | `/res/v1/news/search` | News articles |
| Summarizer | `/res/v1/summarizer/search` | AI-generated summary + sources |

## Implementation

### BraveEngine class (`ghostmcp/engines/brave.py`)

```python
class BraveEngine(SearchEngine):
    name = "brave"
    min_delay = 1.0  # Brave is generous with rate limits
    API_URL = "https://api.search.brave.com/res/v1/web/search"

    def __init__(self, proxy=None, api_key=None):
        super().__init__(proxy)
        self._api_key = api_key or os.environ.get("BRAVE_API_KEY", "")

    @property
    def available(self) -> bool:
        return bool(self._api_key)

    async def search(self, query, num_results=10):
        # GET request with X-Subscription-Token header
        # Parse structured JSON response
        # Return list[SearchResult]
```

### Auto-fallback chain (`ghostmcp/mcp.py`)

As shipped, API engines register ahead of scrapers, in this order:

**Serper → Brave → Bing → SearXNG → Google → DDG Lite**

Brave slots in after Serper (both API-based with structured JSON) and ahead of
the scrapers (Google/DDG), which are fragile and CAPTCHA-prone. Each engine only
registers if `available` (Brave requires `BRAVE_API_KEY`). Brave is rate-limited
conservatively (~30 per 10-min window, ≈67/day against the 2,000/month tier).

### Environment variable

```
BRAVE_API_KEY=your-brave-api-key-here
```

### Tests (`tests/test_brave.py`) — 22 tests

- Mock API response parsing
- Key detection (available/not available)
- Rate limit handling (429)
- Empty results
- Error responses

## Engine Comparison Matrix

| Engine | Type | API Key | Free Tier | Reliability | Result Quality |
|--------|------|---------|-----------|-------------|----------------|
| **Serper** | API | Required | 2,500 one-time | High | Best (Google index) |
| **Brave** | API | Required | 2,000/month | High | Good (independent) |
| **Google** | Scrape | None | Unlimited | Low (CAPTCHAs) | Best |
| **DDG Lite** | Scrape | None | Unlimited | Medium (throttling) | Good |

## Files (as shipped)

| File | Description |
|------|-------------|
| `ghostmcp/engines/brave.py` | `BraveEngine` class |
| `ghostmcp/engines/brave_media.py` | `BraveMediaEngine` (images/videos/news) |
| `tests/test_brave.py` | Unit tests (22) |
| `ghostmcp/mcp.py` | Registered in the auto-fallback chain + media tool |

---

*Proposed 2026-06-18 on `feature/brave-search`; implemented and merged to `main`.
Doc retained as a design record (branch since deleted).*
