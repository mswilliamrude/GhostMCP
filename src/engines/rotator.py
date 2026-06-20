"""Engine rotation and rate management for search queries."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional

from .base import SearchEngine, SearchResult, SearchEngineError, RateLimitError


@dataclass
class EngineState:
    """Track per-engine health and rate state."""
    name: str
    engine: SearchEngine
    is_api: bool = False  # API-based engines (Brave, Serper) vs scrapers (Google, DDG)

    # Rate tracking
    requests_in_window: int = 0
    window_start: float = 0.0
    window_duration: float = 600.0  # 10-minute window

    # Limits (per 10-minute window)
    max_requests_per_window: int = 50

    # Cooldown state
    cooldown_until: float = 0.0  # timestamp when cooldown expires
    base_cooldown: float = 60.0  # base cooldown on failure (seconds)
    consecutive_failures: int = 0
    max_consecutive_failures: int = 3  # disable engine after this many failures in a row

    # Stats
    total_requests: int = 0
    total_successes: int = 0
    total_failures: int = 0
    last_captcha_time: float = 0.0


class EngineRotator:
    """Intelligent engine rotation with per-engine health tracking.

    Strategies:
    - Round-robin across available engines (not sequential fallback)
    - API engines preferred over scrapers (no CAPTCHA risk)
    - Per-engine window-based rate limiting
    - Adaptive cooldown on failure (doubles each consecutive failure)
    - Engine disabled after max_consecutive_failures (re-enabled after long cooldown)
    """

    def __init__(self):
        self._engines: list[EngineState] = []
        self._rotation_index: int = 0
        self._lock = asyncio.Lock()

    def register(self, engine: SearchEngine, is_api: bool = False,
                 max_per_window: int = 50, base_cooldown: float = 60.0) -> None:
        """Register an engine with its rate parameters."""
        state = EngineState(
            name=engine.name,
            engine=engine,
            is_api=is_api,
            max_requests_per_window=max_per_window,
            base_cooldown=base_cooldown,
            window_start=time.monotonic(),
        )
        self._engines.append(state)

    def _is_available(self, state: EngineState) -> bool:
        """Check if an engine is currently available for use."""
        now = time.monotonic()

        # Disabled due to too many consecutive failures?
        if state.consecutive_failures >= state.max_consecutive_failures:
            # Re-enable after extended cooldown (base * failures * 5)
            extended_cooldown = state.base_cooldown * state.consecutive_failures * 5
            if now < state.cooldown_until + extended_cooldown:
                return False
            # Extended cooldown expired — reset and try again
            state.consecutive_failures = 0

        # In cooldown?
        if now < state.cooldown_until:
            return False

        # Window expired? Reset counter
        if now - state.window_start > state.window_duration:
            state.requests_in_window = 0
            state.window_start = now

        # Over window limit?
        if state.requests_in_window >= state.max_requests_per_window:
            return False

        return True

    async def select_engine(self) -> Optional[EngineState]:
        """Select the next available engine using weighted round-robin.

        Priority: API engines first (no CAPTCHA risk), then scrapers.
        Within each tier, rotate in order.
        """
        async with self._lock:
            # First pass: try API engines
            api_engines = [s for s in self._engines if s.is_api and self._is_available(s)]
            if api_engines:
                # Round-robin among available API engines
                idx = self._rotation_index % len(api_engines)
                self._rotation_index += 1
                return api_engines[idx]

            # Second pass: try scrapers
            scraper_engines = [s for s in self._engines if not s.is_api and self._is_available(s)]
            if scraper_engines:
                idx = self._rotation_index % len(scraper_engines)
                self._rotation_index += 1
                return scraper_engines[idx]

            return None

    def record_success(self, state: EngineState) -> None:
        """Record a successful search."""
        state.requests_in_window += 1
        state.total_requests += 1
        state.total_successes += 1
        state.consecutive_failures = 0  # Reset failure counter

    def record_failure(self, state: EngineState, is_captcha: bool = False,
                       is_rate_limit: bool = False) -> None:
        """Record a failed search and apply cooldown."""
        state.requests_in_window += 1
        state.total_requests += 1
        state.total_failures += 1
        state.consecutive_failures += 1

        # Calculate cooldown: base * 2^(consecutive_failures - 1)
        cooldown = state.base_cooldown * (2 ** (state.consecutive_failures - 1))

        # Cap at 10 minutes
        cooldown = min(cooldown, 600.0)

        state.cooldown_until = time.monotonic() + cooldown

        if is_captcha:
            state.last_captcha_time = time.monotonic()
            # Extra penalty for CAPTCHA — double the cooldown
            state.cooldown_until = time.monotonic() + cooldown * 2

    async def search(self, query: str, num_results: int = 10,
                     max_attempts: int = 4) -> tuple[list[SearchResult], str]:
        """Execute a search with intelligent engine rotation.

        Returns:
            Tuple of (results, engine_name_used).
            Empty results list if all engines fail.
        """
        last_error: Optional[str] = None
        engines_tried: list[str] = []

        for attempt in range(max_attempts):
            state = await self.select_engine()
            if state is None:
                break  # No engines available

            if state.name in engines_tried:
                # Already tried this engine — skip to avoid loops
                # But only if we have other options
                other = [s for s in self._engines
                         if s.name not in engines_tried and self._is_available(s)]
                if other:
                    state = other[0]
                else:
                    break

            engines_tried.append(state.name)

            try:
                results = await state.engine.search(query, num_results=num_results)
                if results:
                    self.record_success(state)
                    return results, state.name
                else:
                    # Empty results — not a hard failure but try next engine
                    self.record_success(state)  # It worked, just no results
                    continue
            except RateLimitError:
                self.record_failure(state, is_rate_limit=True)
                last_error = f"[{state.name}] Rate limited"
                continue
            except SearchEngineError as e:
                is_captcha = "captcha" in str(e).lower()
                self.record_failure(state, is_captcha=is_captcha)
                last_error = str(e)
                continue

        return [], last_error or "No engines available"

    def get_status(self) -> dict:
        """Get current status of all engines for debugging."""
        now = time.monotonic()
        status = {}
        for s in self._engines:
            status[s.name] = {
                "available": self._is_available(s),
                "is_api": s.is_api,
                "requests_in_window": s.requests_in_window,
                "max_per_window": s.max_requests_per_window,
                "consecutive_failures": s.consecutive_failures,
                "cooldown_remaining": round(max(0, s.cooldown_until - now), 1),
                "total": s.total_requests,
                "successes": s.total_successes,
                "failures": s.total_failures,
            }
        return status
