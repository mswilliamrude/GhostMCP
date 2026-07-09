"""Brave Search API media engines — image, video, and news search."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import httpx

from .base import SearchEngine, SearchEngineError


# ---------------------------------------------------------------------------
# Data classes for media results
# ---------------------------------------------------------------------------


@dataclass
class ImageResult:
    """A single image search result from Brave."""

    title: str
    url: str  # page URL where image is embedded
    image_url: str  # direct image URL
    thumbnail_url: str
    source: str  # domain
    width: int = 0
    height: int = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __str__(self) -> str:
        return f"[image] {self.title}\n  Page: {self.url}\n  Image: {self.image_url} ({self.width}x{self.height})"


@dataclass
class VideoResult:
    """A single video search result from Brave."""

    title: str
    url: str  # page URL (youtube.com/watch?v=...)
    thumbnail_url: str
    source: str  # "YouTube", "Vimeo", etc.
    duration: str = ""  # "5:32"
    published: str = ""
    description: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __str__(self) -> str:
        dur = f" [{self.duration}]" if self.duration else ""
        return f"[video] {self.title}{dur}\n  {self.url}\n  Source: {self.source}"


@dataclass
class NewsResult:
    """A single news search result from Brave."""

    title: str
    url: str
    source: str  # publisher name
    published: str  # date
    description: str = ""
    thumbnail_url: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __str__(self) -> str:
        return f"[news] {self.title}\n  {self.url}\n  {self.source} — {self.published}"


# ---------------------------------------------------------------------------
# Brave Media Engine (extends BraveEngine with media search capabilities)
# ---------------------------------------------------------------------------


class BraveMediaEngine:
    """Brave Search API media engine — image, video, and news search.

    Uses the same auth as BraveEngine (GHOST_BRAVE_KEY) but hits different
    API endpoints for media content.

    Endpoints:
    - Images: https://api.search.brave.com/res/v1/images/search
    - Videos: https://api.search.brave.com/res/v1/videos/search
    - News:   https://api.search.brave.com/res/v1/news/search
    """

    IMAGES_URL = "https://api.search.brave.com/res/v1/images/search"
    VIDEOS_URL = "https://api.search.brave.com/res/v1/videos/search"
    NEWS_URL = "https://api.search.brave.com/res/v1/news/search"

    def __init__(self, proxy: Optional[dict] = None, api_key: Optional[str] = None) -> None:
        """Initialize Brave Media engine.

        Args:
            proxy: Proxy config (optional).
            api_key: Brave API key. If None, reads from GHOST_BRAVE_KEY env var.
        """
        self.proxy = proxy
        self.api_key = api_key or os.environ.get("GHOST_BRAVE_KEY", "")

    @property
    def available(self) -> bool:
        """Check if the engine is configured (has API key)."""
        return bool(self.api_key)

    def _get_headers(self) -> dict:
        """Get auth headers for Brave API requests."""
        return {
            "X-Subscription-Token": self.api_key,
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
        }

    def _check_key(self) -> None:
        """Raise if no API key is configured."""
        if not self.api_key:
            raise SearchEngineError(
                "brave",
                "GHOST_BRAVE_KEY not set. "
                "Get a free key (2,000 searches/month) at https://brave.com/search/api/\n"
                "  1. Sign up at https://brave.com/search/api/\n"
                "  2. Create an app and get your API key\n"
                "  3. Export it: export GHOST_BRAVE_KEY='your-key-here'"
            )

    def _handle_error_status(self, status_code: int) -> None:
        """Handle HTTP error status codes from Brave API."""
        if status_code == 401:
            raise SearchEngineError(
                "brave",
                "Invalid GHOST_BRAVE_KEY. Check your key at "
                "https://brave.com/search/api/"
            )
        if status_code == 403:
            raise SearchEngineError(
                "brave",
                "Brave API access denied. Your plan may not include "
                "this search type, or your key is inactive."
            )
        if status_code == 429:
            raise SearchEngineError(
                "brave",
                "Brave rate limit hit. Free tier: 2,000/month. "
                "Check usage at https://brave.com/search/api/"
            )

    async def _request(self, url: str, params: dict) -> dict:
        """Make an authenticated request to a Brave API endpoint.

        Args:
            url: The API endpoint URL.
            params: Query parameters.

        Returns:
            Parsed JSON response.

        Raises:
            SearchEngineError: On API errors.
        """
        self._check_key()

        transport = None
        if self.proxy:
            transport = httpx.AsyncHTTPTransport(proxy=self.proxy.get("all"))

        try:
            async with httpx.AsyncClient(
                transport=transport,
                timeout=30.0,
            ) as client:
                resp = await client.get(
                    url,
                    params=params,
                    headers=self._get_headers(),
                )

                self._handle_error_status(resp.status_code)
                resp.raise_for_status()
                return resp.json()

        except SearchEngineError:
            raise
        except httpx.HTTPStatusError as e:
            raise SearchEngineError("brave", f"API HTTP {e.response.status_code}")
        except httpx.TimeoutException:
            raise SearchEngineError("brave", "Request timed out (30s)")
        except httpx.ConnectError:
            raise SearchEngineError("brave", "Connection failed to api.search.brave.com")
        except httpx.RequestError as e:
            raise SearchEngineError("brave", f"Request failed: {e}")

    # ---------------------------------------------------------------------------
    # Image search
    # ---------------------------------------------------------------------------

    async def search_images(self, query: str, num_results: int = 10) -> list[ImageResult]:
        """Search for images via Brave Image Search API.

        Args:
            query: Search query string.
            num_results: Max results to return (API max 20 per request).

        Returns:
            List of ImageResult objects.

        Raises:
            SearchEngineError: On API errors or missing key.
        """
        count = min(max(1, num_results), 20)
        params = {
            "q": query,
            "count": count,
            "safesearch": "off",
        }

        data = await self._request(self.IMAGES_URL, params)
        return self._parse_image_response(data, num_results)

    def _parse_image_response(self, data: dict, num_results: int) -> list[ImageResult]:
        """Parse Brave Image Search API response.

        Brave image results structure:
        data["results"] → each has:
          - title: str
          - url: page URL where image appears
          - properties.url: direct image URL
          - thumbnail.src: thumbnail URL
          - source: domain string
          - properties.width/height: image dimensions
        """
        results: list[ImageResult] = []
        raw_results = data.get("results", [])

        for item in raw_results[:num_results]:
            title = item.get("title", "")
            page_url = item.get("url", "")

            if not page_url:
                continue

            # Image URL from properties
            properties = item.get("properties", {})
            image_url = properties.get("url", "")

            # Thumbnail
            thumbnail = item.get("thumbnail", {})
            thumbnail_url = thumbnail.get("src", "")

            # Source domain
            source = item.get("source", "")

            # Dimensions
            width = properties.get("width", 0)
            height = properties.get("height", 0)

            results.append(ImageResult(
                title=title or page_url,
                url=page_url,
                image_url=image_url,
                thumbnail_url=thumbnail_url,
                source=source,
                width=int(width) if width else 0,
                height=int(height) if height else 0,
            ))

        return results

    # ---------------------------------------------------------------------------
    # Video search
    # ---------------------------------------------------------------------------

    async def search_videos(self, query: str, num_results: int = 10) -> list[VideoResult]:
        """Search for videos via Brave Video Search API.

        Args:
            query: Search query string.
            num_results: Max results to return (API max 20 per request).

        Returns:
            List of VideoResult objects.

        Raises:
            SearchEngineError: On API errors or missing key.
        """
        count = min(max(1, num_results), 20)
        params = {
            "q": query,
            "count": count,
            "safesearch": "off",
        }

        data = await self._request(self.VIDEOS_URL, params)
        return self._parse_video_response(data, num_results)

    def _parse_video_response(self, data: dict, num_results: int) -> list[VideoResult]:
        """Parse Brave Video Search API response.

        Brave video results structure:
        data["results"] → each has:
          - title: str
          - url: video page URL
          - thumbnail.src: thumbnail URL
          - video.duration: duration string (e.g. "5:32")
          - age: publication age string (e.g. "2 days ago")
          - meta_url.hostname: source platform
          - description: video description
        """
        results: list[VideoResult] = []
        raw_results = data.get("results", [])

        for item in raw_results[:num_results]:
            title = item.get("title", "")
            url = item.get("url", "")

            if not url:
                continue

            # Thumbnail
            thumbnail = item.get("thumbnail", {})
            thumbnail_url = thumbnail.get("src", "")

            # Video metadata
            video = item.get("video", {})
            duration = video.get("duration", "")

            # Source/platform from meta_url
            meta_url = item.get("meta_url", {})
            source = meta_url.get("hostname", "")

            # Publication time
            published = item.get("age", "")

            # Description
            description = item.get("description", "")

            results.append(VideoResult(
                title=title or url,
                url=url,
                thumbnail_url=thumbnail_url,
                source=source,
                duration=duration,
                published=published,
                description=description,
            ))

        return results

    # ---------------------------------------------------------------------------
    # News search
    # ---------------------------------------------------------------------------

    async def search_news(self, query: str, num_results: int = 10) -> list[NewsResult]:
        """Search for news via Brave News Search API.

        Args:
            query: Search query string.
            num_results: Max results to return (API max 20 per request).

        Returns:
            List of NewsResult objects.

        Raises:
            SearchEngineError: On API errors or missing key.
        """
        count = min(max(1, num_results), 20)
        params = {
            "q": query,
            "count": count,
            "safesearch": "off",
        }

        data = await self._request(self.NEWS_URL, params)
        return self._parse_news_response(data, num_results)

    def _parse_news_response(self, data: dict, num_results: int) -> list[NewsResult]:
        """Parse Brave News Search API response.

        Brave news results structure:
        data["results"] → each has:
          - title: str
          - url: article URL
          - description: article description/snippet
          - age: publication time (e.g. "3 hours ago")
          - meta_url.hostname: publisher domain
          - thumbnail.src: article thumbnail
        """
        results: list[NewsResult] = []
        raw_results = data.get("results", [])

        for item in raw_results[:num_results]:
            title = item.get("title", "")
            url = item.get("url", "")

            if not url:
                continue

            # Publisher from meta_url
            meta_url = item.get("meta_url", {})
            source = meta_url.get("hostname", "")

            # Publication time
            published = item.get("age", "")

            # Description
            description = item.get("description", "")

            # Thumbnail
            thumbnail = item.get("thumbnail", {})
            thumbnail_url = thumbnail.get("src", "")

            results.append(NewsResult(
                title=title or url,
                url=url,
                source=source,
                published=published,
                description=description,
                thumbnail_url=thumbnail_url,
            ))

        return results
