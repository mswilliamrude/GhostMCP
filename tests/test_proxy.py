"""Tests for ProxyManager."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from src.proxy.manager import ProxyManager
from src.utils.config import ParanoiaLevel


class TestGetProxy:
    """Tests for ProxyManager.get_proxy()."""

    def setup_method(self):
        self.mgr = ProxyManager()

    def test_casual_returns_none(self):
        assert self.mgr.get_proxy(ParanoiaLevel.CASUAL) is None

    def test_cautious_returns_none(self):
        # Cautious is direct for now (future: rotating proxy)
        assert self.mgr.get_proxy(ParanoiaLevel.CAUTIOUS) is None

    def test_ghost_returns_tor_proxy(self):
        result = self.mgr.get_proxy(ParanoiaLevel.GHOST)
        assert result == {"all": "socks5://127.0.0.1:9050"}

    def test_midnight_returns_tor_proxy(self):
        result = self.mgr.get_proxy(ParanoiaLevel.MIDNIGHT)
        assert result == {"all": "socks5://127.0.0.1:9050"}

    @pytest.mark.parametrize("level_str,expected_none", [
        ("casual", True),
        ("cautious", True),
        ("ghost", False),
        ("midnight", False),
    ])
    def test_accepts_string_levels(self, level_str, expected_none):
        result = self.mgr.get_proxy(level_str)
        if expected_none:
            assert result is None
        else:
            assert result is not None
            assert "socks5://" in result["all"]

    def test_tor_proxy_constant(self):
        assert ProxyManager.TOR_PROXY == "socks5://127.0.0.1:9050"

    def test_tor_control_port_constant(self):
        assert ProxyManager.TOR_CONTROL_PORT == 9051


class TestCheckTorHealth:
    """Tests for check_tor_health() with mocked HTTP."""

    @pytest.mark.asyncio
    async def test_tor_healthy(self):
        """Successful Tor check returns True."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"IsTor": True, "IP": "198.51.100.1"}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncHTTPTransport", return_value=MagicMock()):
            with patch("httpx.AsyncClient", return_value=mock_client):
                mgr = ProxyManager()
                result = await mgr.check_tor_health()

        assert result is True
        assert mgr.tor_available is True

    @pytest.mark.asyncio
    async def test_tor_not_tor(self):
        """When IsTor is False, returns False."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"IsTor": False, "IP": "192.0.2.1"}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncHTTPTransport", return_value=MagicMock()):
            with patch("httpx.AsyncClient", return_value=mock_client):
                mgr = ProxyManager()
                result = await mgr.check_tor_health()

        assert result is False
        assert mgr.tor_available is False

    @pytest.mark.asyncio
    async def test_tor_connection_error(self):
        """Connection failure returns False."""
        import httpx

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncHTTPTransport", return_value=MagicMock()):
            with patch("httpx.AsyncClient", return_value=mock_client):
                mgr = ProxyManager()
                result = await mgr.check_tor_health()

        assert result is False
        assert mgr.tor_available is False

    @pytest.mark.asyncio
    async def test_tor_timeout(self):
        """Timeout returns False."""
        import httpx

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncHTTPTransport", return_value=MagicMock()):
            with patch("httpx.AsyncClient", return_value=mock_client):
                mgr = ProxyManager()
                result = await mgr.check_tor_health()

        assert result is False

    @pytest.mark.asyncio
    async def test_tor_available_initially_none(self):
        mgr = ProxyManager()
        assert mgr.tor_available is None


class TestCheckHealth:
    """Tests for check_health() method."""

    @pytest.mark.asyncio
    async def test_casual_always_healthy(self):
        mgr = ProxyManager()
        result = await mgr.check_health("casual")
        assert result is True

    @pytest.mark.asyncio
    async def test_cautious_always_healthy(self):
        mgr = ProxyManager()
        result = await mgr.check_health("cautious")
        assert result is True

    @pytest.mark.asyncio
    async def test_ghost_delegates_to_tor_check(self):
        mgr = ProxyManager()
        with patch.object(mgr, "check_tor_health", new_callable=AsyncMock, return_value=True):
            result = await mgr.check_health("ghost")
        assert result is True

    @pytest.mark.asyncio
    async def test_midnight_delegates_to_tor_check(self):
        mgr = ProxyManager()
        with patch.object(mgr, "check_tor_health", new_callable=AsyncMock, return_value=False):
            result = await mgr.check_health("midnight")
        assert result is False
