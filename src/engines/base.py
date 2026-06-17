"""Abstract base class for search engines."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class SearchResult:
    """A single search result from any engine."""

    title: str
    url: str
    snippet: str
    source_engine: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __str__(self) -> str:
        return f"[{self.source_engine}] {self.title}\n  {self.url}\n  {self.snippet}"


class SearchEngineError(Exception):
    """Base exception for search engine failures."""

    def __init__(self, engine: str, message: str) -> None:
        self.engine = engine
        super().__init__(f"[{engine}] {message}")


class RateLimitError(SearchEngineError):
    """Raised when the engine rate-limits us."""

    pass


class SearchEngine(ABC):
    """Abstract base for all search engine implementations.

    Subclasses must implement `search()` which returns a list of SearchResult.
    Rate limiting and error handling are built into the base class.
    """

    name: str = "base"
    min_delay: float = 2.0  # seconds between requests

    def __init__(self, proxy: Optional[dict] = None) -> None:
        self.proxy = proxy
        self._last_request: float = 0.0
        self._lock = asyncio.Lock()

    async def _rate_limit(self) -> None:
        """Enforce minimum delay between requests."""
        async with self._lock:
            now = asyncio.get_event_loop().time()
            elapsed = now - self._last_request
            if elapsed < self.min_delay:
                await asyncio.sleep(self.min_delay - elapsed)
            self._last_request = asyncio.get_event_loop().time()

    @abstractmethod
    async def search(self, query: str, num_results: int = 10) -> list[SearchResult]:
        """Execute a search query and return results.

        Args:
            query: The search query string.
            num_results: Maximum number of results to return.

        Returns:
            List of SearchResult objects.

        Raises:
            SearchEngineError: On engine-specific failures.
            RateLimitError: When rate-limited by the engine.
        """
        ...
