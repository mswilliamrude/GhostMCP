"""Serper.dev API search engine — structured Google results via API."""

from __future__ import annotations

import os
from typing import Optional

import httpx

from .base import SearchEngine, SearchResult, SearchEngineError


class SerperEngine(SearchEngine):
    """Serper.dev API engine — structured Google results without scraping.

    Uses the Serper.dev API which provides 2,500 free searches per month.
    Much more reliable than HTML scraping as results come as structured JSON.

    Requires SERPER_API_KEY environment variable.
    """

    name = "serper"
    min_delay = 0.5  # API has generous rate limits

    API_URL = "https://google.serper.dev/search"

    def __init__(self, proxy: Optional[dict] = None, api_key: Optional[str] = None) -> None:
        """Initialize Serper engine.

        Args:
            proxy: Proxy config (rarely needed for API access).
            api_key: Serper API key. If None, reads from SERPER_API_KEY env var.
        """
        super().__init__(proxy=proxy)
        self.api_key = api_key or os.environ.get("SERPER_API_KEY", "")

    @property
    def available(self) -> bool:
        """Check if the engine is configured (has API key)."""
        return bool(self.api_key)

    async def search(self, query: str, num_results: int = 10) -> list[SearchResult]:
        """Search via Serper.dev API.

        Args:
            query: Search query string.
            num_results: Max results to return (API supports up to 100).

        Returns:
            List of parsed SearchResult objects.

        Raises:
            SearchEngineError: On API errors or missing key.
        """
        if not self.api_key:
            raise SearchEngineError(
                self.name,
                "SERPER_API_KEY not set. "
                "Get a free key (2,500 searches/month) at https://serper.dev\n"
                "  1. Sign up at https://serper.dev (Google account works)\n"
                "  2. Copy your API key from the dashboard\n"
                "  3. Export it: export SERPER_API_KEY='your-key-here'"
            )

        await self._rate_limit()

        payload = {
            "q": query,
            "num": min(num_results, 100),
        }
        headers = {
            "X-API-KEY": self.api_key,
            "Content-Type": "application/json",
        }

        transport = None
        if self.proxy:
            transport = httpx.AsyncHTTPTransport(proxy=self.proxy.get("all"))

        try:
            async with httpx.AsyncClient(
                transport=transport,
                timeout=30.0,
            ) as client:
                resp = await client.post(
                    self.API_URL,
                    json=payload,
                    headers=headers,
                )

                if resp.status_code == 401:
                    raise SearchEngineError(
                        self.name,
                        "Invalid SERPER_API_KEY. Check your key at https://serper.dev/dashboard"
                    )
                if resp.status_code == 429:
                    raise SearchEngineError(
                        self.name,
                        "Serper rate limit hit. Free tier: 2,500/month. "
                        "Check usage at https://serper.dev/dashboard"
                    )
                resp.raise_for_status()

                data = resp.json()
        except SearchEngineError:
            raise
        except httpx.HTTPStatusError as e:
            raise SearchEngineError(self.name, f"API HTTP {e.response.status_code}")
        except httpx.RequestError as e:
            raise SearchEngineError(self.name, f"Request failed: {e}")

        return self._parse_response(data, num_results)

    def _parse_response(self, data: dict, num_results: int) -> list[SearchResult]:
        """Parse Serper API JSON response into SearchResult objects.

        The API returns structured data with organic results,
        knowledge graph, people also ask, etc. We extract organic results.

        Args:
            data: Parsed JSON response from Serper API.
            num_results: Maximum results to return.

        Returns:
            List of SearchResult objects.
        """
        results: list[SearchResult] = []

        organic = data.get("organic", [])
        for item in organic[:num_results]:
            title = item.get("title", "")
            link = item.get("link", "")
            snippet = item.get("snippet", "")

            if not link:
                continue

            results.append(SearchResult(
                title=title or link,
                url=link,
                snippet=snippet,
                source_engine=self.name,
            ))

        return results
