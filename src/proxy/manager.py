"""Proxy manager for different paranoia levels."""

from __future__ import annotations

from typing import Optional

import httpx

from ..utils.config import ParanoiaLevel


class ProxyManager:
    """Manages proxy selection based on paranoia level.

    Paranoia levels:
        casual   — direct connection, no proxy
        cautious — rotating proxy (if available, else direct)
        ghost    — route through Tor (socks5://127.0.0.1:9050)
        midnight — Tor + identity rotation between requests
    """

    TOR_PROXY = "socks5://127.0.0.1:9050"
    TOR_CONTROL_PORT = 9051

    def __init__(self) -> None:
        self._tor_available: Optional[bool] = None

    def get_proxy(self, paranoia_level: str | ParanoiaLevel) -> Optional[dict]:
        """Get proxy configuration for the given paranoia level.

        Args:
            paranoia_level: One of casual, cautious, ghost, midnight.

        Returns:
            Proxy dict for httpx (e.g. {"all": "socks5://..."}) or None.
        """
        if isinstance(paranoia_level, str):
            paranoia_level = ParanoiaLevel(paranoia_level)

        if paranoia_level == ParanoiaLevel.CASUAL:
            return None

        if paranoia_level == ParanoiaLevel.CAUTIOUS:
            # Future: rotating proxy pool. For now, direct.
            return None

        if paranoia_level in (ParanoiaLevel.GHOST, ParanoiaLevel.MIDNIGHT):
            return {"all": self.TOR_PROXY}

        return None

    async def check_tor_health(self) -> bool:
        """Test if Tor SOCKS proxy is reachable.

        Returns:
            True if Tor proxy responds, False otherwise.
        """
        try:
            transport = httpx.AsyncHTTPTransport(proxy=self.TOR_PROXY)
            async with httpx.AsyncClient(
                transport=transport,
                timeout=10.0,
            ) as client:
                resp = await client.get("https://check.torproject.org/api/ip")
                data = resp.json()
                self._tor_available = data.get("IsTor", False)
                return self._tor_available
        except (httpx.RequestError, Exception):
            self._tor_available = False
            return False

    async def check_health(self, paranoia_level: str | ParanoiaLevel) -> bool:
        """Check if the proxy for a given level is healthy.

        Args:
            paranoia_level: The level to check connectivity for.

        Returns:
            True if connectivity is confirmed.
        """
        if isinstance(paranoia_level, str):
            paranoia_level = ParanoiaLevel(paranoia_level)

        if paranoia_level in (ParanoiaLevel.CASUAL, ParanoiaLevel.CAUTIOUS):
            # Direct connections are assumed healthy
            return True

        return await self.check_tor_health()

    @property
    def tor_available(self) -> Optional[bool]:
        """Last known Tor availability. None if never checked."""
        return self._tor_available
