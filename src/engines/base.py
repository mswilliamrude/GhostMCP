"""Abstract base class for search engines."""

from __future__ import annotations

import asyncio
import fcntl
import os
import tempfile
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
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


# Cross-process rate limit directory — shared between all GhostMCP instances
_RATE_LIMIT_DIR = Path(tempfile.gettempdir()) / "ghostmcp_ratelimit"
_RATE_LIMIT_DIR.mkdir(exist_ok=True)


class SearchEngine(ABC):
    """Abstract base for all search engine implementations.

    Subclasses must implement `search()` which returns a list of SearchResult.
    Rate limiting uses a cross-process file lock so multiple GhostMCP instances
    (e.g. multiple opencode sessions) don't clobber each other on the same engine.
    """

    name: str = "base"
    min_delay: float = 2.0  # seconds between requests

    def __init__(self, proxy: Optional[dict] = None) -> None:
        self.proxy = proxy
        self._last_request: float = 0.0
        self._lock = asyncio.Lock()
        # Cross-process lockfile per engine name
        self._lockfile = _RATE_LIMIT_DIR / f"{self.name}.lock"
        self._stampfile = _RATE_LIMIT_DIR / f"{self.name}.stamp"

    async def _rate_limit(self) -> None:
        """Enforce minimum delay between requests, across all processes.

        Uses a file lock (fcntl.flock) so multiple GhostMCP instances
        coordinate their request timing on the same engine.
        """
        async with self._lock:
            # Run the file-lock operation in a thread to avoid blocking the event loop
            await asyncio.get_event_loop().run_in_executor(None, self._rate_limit_sync)

    def _rate_limit_sync(self) -> None:
        """Synchronous cross-process rate limiting via file lock + timestamp file."""
        # Acquire exclusive lock — blocks until other processes release
        fd = os.open(str(self._lockfile), os.O_CREAT | os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)

            # Read last request timestamp from shared stamp file
            last_request = 0.0
            try:
                if self._stampfile.exists():
                    last_request = float(self._stampfile.read_text().strip())
            except (ValueError, OSError):
                pass

            now = time.monotonic()
            # On first run or if stamp is from a previous boot, use wall clock
            # for the delay but always write monotonic for in-session consistency
            elapsed = now - last_request if last_request > 0 else self.min_delay
            if elapsed < self.min_delay:
                time.sleep(self.min_delay - elapsed)

            # Write new timestamp
            self._stampfile.write_text(str(time.monotonic()))
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

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
