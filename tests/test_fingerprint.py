"""Tests for fingerprint header generation."""

from __future__ import annotations

import pytest

from src.proxy.fingerprint import get_headers, _ALL_UAS, _ACCEPT_LANGUAGES
from src.utils.config import ParanoiaLevel


class TestGetHeaders:
    """Tests for get_headers() function."""

    def test_returns_dict(self):
        h = get_headers()
        assert isinstance(h, dict)

    def test_default_is_casual(self):
        """No argument should behave like casual level."""
        h = get_headers()
        assert "User-Agent" in h
        assert "Accept" in h

    def test_has_required_keys(self):
        h = get_headers(ParanoiaLevel.CASUAL)
        required = ["User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Connection", "Upgrade-Insecure-Requests"]
        for key in required:
            assert key in h, f"Missing header: {key}"

    def test_casual_has_dnt(self):
        h = get_headers(ParanoiaLevel.CASUAL)
        assert "DNT" in h
        assert h["DNT"] == "1"

    def test_cautious_has_dnt(self):
        h = get_headers(ParanoiaLevel.CAUTIOUS)
        assert "DNT" in h

    def test_ghost_removes_dnt(self):
        h = get_headers(ParanoiaLevel.GHOST)
        assert "DNT" not in h

    def test_midnight_removes_dnt(self):
        h = get_headers(ParanoiaLevel.MIDNIGHT)
        assert "DNT" not in h

    def test_ghost_uses_tor_browser_ua(self):
        h = get_headers(ParanoiaLevel.GHOST)
        assert "Firefox/128.0" in h["User-Agent"]
        assert "Windows NT 10.0" in h["User-Agent"]

    def test_midnight_uses_tor_browser_ua(self):
        h = get_headers(ParanoiaLevel.MIDNIGHT)
        assert "Firefox/128.0" in h["User-Agent"]

    def test_ghost_standard_language(self):
        h = get_headers(ParanoiaLevel.GHOST)
        assert h["Accept-Language"] == "en-US,en;q=0.5"

    def test_midnight_standard_language(self):
        h = get_headers(ParanoiaLevel.MIDNIGHT)
        assert h["Accept-Language"] == "en-US,en;q=0.5"

    @pytest.mark.parametrize("level", [
        ParanoiaLevel.CASUAL, ParanoiaLevel.CAUTIOUS,
        ParanoiaLevel.GHOST, ParanoiaLevel.MIDNIGHT,
    ])
    def test_all_levels_produce_valid_headers(self, level):
        h = get_headers(level)
        assert "User-Agent" in h
        assert "Accept" in h
        assert len(h["User-Agent"]) > 10

    def test_accepts_string_casual(self):
        h = get_headers("casual")
        assert "User-Agent" in h

    def test_accepts_string_ghost(self):
        h = get_headers("ghost")
        assert "DNT" not in h

    def test_accepts_none(self):
        h = get_headers(None)
        assert "User-Agent" in h

    def test_casual_ua_from_pool(self):
        """Casual/cautious should use a UA from the defined pool."""
        h = get_headers(ParanoiaLevel.CASUAL)
        ua = h["User-Agent"]
        assert ua in _ALL_UAS

    def test_casual_lang_from_pool(self):
        h = get_headers(ParanoiaLevel.CASUAL)
        lang = h["Accept-Language"]
        assert lang in _ACCEPT_LANGUAGES

    def test_accept_header_value(self):
        h = get_headers()
        assert "text/html" in h["Accept"]
        assert "application/xhtml+xml" in h["Accept"]

    def test_accept_encoding_value(self):
        h = get_headers()
        assert "gzip" in h["Accept-Encoding"]
        assert "deflate" in h["Accept-Encoding"]
        # 'br' (brotli) is only advertised if the brotli package is installed
        try:
            import brotli  # noqa: F401
            assert "br" in h["Accept-Encoding"]
        except ImportError:
            assert "br" not in h["Accept-Encoding"]

    def test_connection_keep_alive(self):
        h = get_headers()
        assert h["Connection"] == "keep-alive"

    def test_upgrade_insecure(self):
        h = get_headers()
        assert h["Upgrade-Insecure-Requests"] == "1"

    def test_no_python_httpx_ua(self):
        """No level should expose python-httpx as User-Agent."""
        for level in ParanoiaLevel:
            h = get_headers(level)
            assert "python" not in h["User-Agent"].lower()
            assert "httpx" not in h["User-Agent"].lower()
