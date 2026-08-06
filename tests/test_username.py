"""Tests for username enumeration — builtin checker, external tools, search URLs."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ghostmcp.recon.username import (
    UsernameReport,
    _BUILTIN_SITES,
    _URL_ONLY_SITES,
    _build_search_urls,
    _check_site,
    _builtin_check,
    _run_external_tool,
    username_lookup,
)


# ---------------------------------------------------------------------------
# Search URL generation
# ---------------------------------------------------------------------------


class TestBuildSearchUrls:
    """Tests for _build_search_urls()."""

    def test_returns_expected_keys(self):
        urls = _build_search_urls("johndoe")
        assert "namechk" in urls
        assert "knowem" in urls
        assert "whatsmyname" in urls

    def test_urls_contain_username(self):
        urls = _build_search_urls("johndoe")
        for key, url in urls.items():
            assert "johndoe" in url

    def test_empty_username(self):
        urls = _build_search_urls("")
        assert isinstance(urls, dict)


# ---------------------------------------------------------------------------
# UsernameReport dataclass
# ---------------------------------------------------------------------------


class TestUsernameReport:
    """Tests for UsernameReport dataclass."""

    def test_defaults(self):
        report = UsernameReport(username="test")
        assert report.username == "test"
        assert report.sites_checked == 0
        assert report.accounts_found == []
        assert report.accounts_not_found_count == 0
        assert report.tool_used == "builtin"
        assert report.timed_out is False
        assert report.error is None

    def test_accounts_found_structure(self):
        report = UsernameReport(
            username="test",
            accounts_found=[
                {"site_name": "GitHub", "url": "https://github.com/test", "category": "development"},
                {"site_name": "Twitter/X", "url": "https://x.com/test", "category": "social"},
            ],
        )
        assert len(report.accounts_found) == 2
        assert report.accounts_found[0]["site_name"] == "GitHub"
        assert report.accounts_found[0]["category"] == "development"


# ---------------------------------------------------------------------------
# Builtin site checker (_check_site)
# ---------------------------------------------------------------------------


class TestCheckSite:
    """Tests for _check_site() — single site checking."""

    @pytest.mark.asyncio
    async def test_found_via_status_200(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                result = await _check_site(
                    client, "johndoe", "GitHub",
                    "https://github.com/{}", "development", "status",
                )

        assert result is not None
        assert result["site_name"] == "GitHub"
        assert result["url"] == "https://github.com/johndoe"
        assert result["category"] == "development"

    @pytest.mark.asyncio
    async def test_not_found_via_status_404(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                result = await _check_site(
                    client, "nonexistent_user_xyz123", "Instagram",
                    "https://instagram.com/{}/", "social", "status",
                )

        assert result is None

    @pytest.mark.asyncio
    async def test_json_check_found(self):
        """Reddit-style JSON check: 200 with valid data = found."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"kind": "t2", "data": {"name": "johndoe"}}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                result = await _check_site(
                    client, "johndoe", "Reddit",
                    "https://reddit.com/user/{}/about.json", "social", "json",
                )

        assert result is not None
        assert result["site_name"] == "Reddit"

    @pytest.mark.asyncio
    async def test_json_check_error_field(self):
        """Reddit returns {"error": 404} for missing users."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"error": 404}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                result = await _check_site(
                    client, "nonexistent123", "Reddit",
                    "https://reddit.com/user/{}/about.json", "social", "json",
                )

        assert result is None

    @pytest.mark.asyncio
    async def test_timeout_graceful(self):
        import httpx

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.TimeoutException("timed out")
            async with httpx.AsyncClient() as client:
                result = await _check_site(
                    client, "test", "GitHub",
                    "https://github.com/{}", "development", "status",
                )

        assert result is None

    @pytest.mark.asyncio
    async def test_connection_error_graceful(self):
        import httpx

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.ConnectError("connection refused")
            async with httpx.AsyncClient() as client:
                result = await _check_site(
                    client, "test", "Twitch",
                    "https://twitch.tv/{}", "social", "status",
                )

        assert result is None

    @pytest.mark.asyncio
    async def test_too_many_redirects_graceful(self):
        import httpx

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.TooManyRedirects("too many redirects")
            async with httpx.AsyncClient() as client:
                result = await _check_site(
                    client, "test", "Pinterest",
                    "https://pinterest.com/{}/", "social", "status",
                )

        assert result is None


# ---------------------------------------------------------------------------
# Builtin checker (_builtin_check)
# ---------------------------------------------------------------------------


class TestBuiltinCheck:
    """Tests for _builtin_check() — multi-site scanning."""

    @pytest.mark.asyncio
    async def test_returns_found_accounts(self):
        """Mock httpx to return 200 for GitHub, 404 for others."""
        async def mock_get(url, **kwargs):
            resp = MagicMock()
            if "github.com" in url:
                resp.status_code = 200
            else:
                resp.status_code = 404
            return resp

        with patch("httpx.AsyncClient.get", side_effect=mock_get):
            report = await _builtin_check("johndoe")

        # Should find GitHub + URL-only sites
        github_entries = [a for a in report.accounts_found if a["site_name"] == "GitHub"]
        assert len(github_entries) == 1
        assert github_entries[0]["url"] == "https://github.com/johndoe"

    @pytest.mark.asyncio
    async def test_sites_checked_count(self):
        async def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 404
            return resp

        with patch("httpx.AsyncClient.get", side_effect=mock_get):
            report = await _builtin_check("nonexistent_user_xyz")

        assert report.sites_checked == len(_BUILTIN_SITES)

    @pytest.mark.asyncio
    async def test_includes_url_only_sites(self):
        async def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 404
            return resp

        with patch("httpx.AsyncClient.get", side_effect=mock_get):
            report = await _builtin_check("johndoe")

        url_only_names = {f"{name} (url only)" for name, _, _ in _URL_ONLY_SITES}
        found_names = {a["site_name"] for a in report.accounts_found}
        assert url_only_names.issubset(found_names)

    @pytest.mark.asyncio
    async def test_tool_used_is_builtin(self):
        async def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 404
            return resp

        with patch("httpx.AsyncClient.get", side_effect=mock_get):
            report = await _builtin_check("test")

        assert report.tool_used == "builtin"

    @pytest.mark.asyncio
    async def test_search_urls_populated(self):
        async def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 404
            return resp

        with patch("httpx.AsyncClient.get", side_effect=mock_get):
            report = await _builtin_check("johndoe")

        assert "namechk" in report.search_urls
        assert "johndoe" in report.search_urls["namechk"]

    @pytest.mark.asyncio
    async def test_scan_time_recorded(self):
        async def mock_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 404
            return resp

        with patch("httpx.AsyncClient.get", side_effect=mock_get):
            report = await _builtin_check("test")

        assert report.scan_time_seconds >= 0


# ---------------------------------------------------------------------------
# External tool detection (_run_external_tool)
# ---------------------------------------------------------------------------


class TestRunExternalTool:
    """Tests for _run_external_tool() — maigret / sherlock subprocess."""

    @pytest.mark.asyncio
    async def test_no_tools_installed_returns_none(self):
        """Neither maigret nor sherlock on PATH → returns None."""
        mock_which = AsyncMock()
        mock_which.returncode = 1
        mock_which.communicate = AsyncMock(return_value=(b"", b""))

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = mock_which
            result = await _run_external_tool("johndoe", max_sites=100, timeout=120)

        assert result is None

    @pytest.mark.asyncio
    async def test_maigret_detected_and_run(self):
        """Maigret found on PATH → runs it and parses output."""
        call_count = 0

        async def mock_exec(*cmd, stdout=None, stderr=None):
            nonlocal call_count
            call_count += 1
            mock_proc = AsyncMock()

            if cmd[0] == "which" and cmd[1] == "maigret":
                # maigret is installed
                mock_proc.returncode = 0
                mock_proc.communicate = AsyncMock(return_value=(b"/usr/bin/maigret", b""))
            elif cmd[0] == "maigret":
                # actual maigret run
                mock_proc.returncode = 0
                mock_proc.communicate = AsyncMock(return_value=(
                    b"[+] GitHub: https://github.com/johndoe\n"
                    b"[+] Twitter: https://twitter.com/johndoe\n"
                    b"[-] Instagram: Not Found\n",
                    b"",
                ))
            else:
                mock_proc.returncode = 1
                mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            return mock_proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            result = await _run_external_tool("johndoe", max_sites=100, timeout=120)

        assert result is not None
        assert result.tool_used == "maigret"
        assert len(result.accounts_found) == 2
        assert result.accounts_found[0]["site_name"] == "GitHub"
        assert result.accounts_found[1]["site_name"] == "Twitter"

    @pytest.mark.asyncio
    async def test_timeout_sets_timed_out_flag(self):
        """When subprocess exceeds timeout, timed_out=True."""
        async def mock_exec(*cmd, stdout=None, stderr=None):
            mock_proc = AsyncMock()
            if cmd[0] == "which" and cmd[1] == "maigret":
                mock_proc.returncode = 0
                mock_proc.communicate = AsyncMock(return_value=(b"/usr/bin/maigret", b""))
            elif cmd[0] == "maigret":
                mock_proc.returncode = 0
                # First communicate() raises TimeoutError, second returns partial
                mock_proc.communicate = AsyncMock(
                    side_effect=[
                        asyncio.TimeoutError(),
                        (b"[+] GitHub: https://github.com/johndoe\n", b""),
                    ]
                )
                mock_proc.kill = AsyncMock()
                mock_proc.wait = AsyncMock()
            else:
                mock_proc.returncode = 1
                mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            return mock_proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec), \
             patch("asyncio.wait_for", side_effect=[
                 asyncio.TimeoutError(),
                 (b"[+] GitHub: https://github.com/johndoe\n", b""),
             ]):
            result = await _run_external_tool("johndoe", max_sites=50, timeout=5)

        assert result is not None
        assert result.timed_out is True

    @pytest.mark.asyncio
    async def test_sherlock_fallback(self):
        """When maigret not found but sherlock is, use sherlock."""
        async def mock_exec(*cmd, stdout=None, stderr=None):
            mock_proc = AsyncMock()
            if cmd[0] == "which" and cmd[1] == "maigret":
                mock_proc.returncode = 1  # not found
                mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            elif cmd[0] == "which" and cmd[1] == "sherlock":
                mock_proc.returncode = 0  # found
                mock_proc.communicate = AsyncMock(return_value=(b"/usr/bin/sherlock", b""))
            elif cmd[0] == "sherlock":
                mock_proc.returncode = 0
                mock_proc.communicate = AsyncMock(return_value=(
                    b"[+] GitHub: https://github.com/johndoe\n",
                    b"",
                ))
            else:
                mock_proc.returncode = 1
                mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            return mock_proc

        with patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
            result = await _run_external_tool("johndoe", max_sites=100, timeout=120)

        assert result is not None
        assert result.tool_used == "sherlock"


# ---------------------------------------------------------------------------
# username_lookup integration
# ---------------------------------------------------------------------------


class TestUsernameLookup:
    """Tests for username_lookup() public API."""

    @pytest.mark.asyncio
    async def test_empty_username(self):
        report = await username_lookup("")
        assert report.error == "Empty username"

    @pytest.mark.asyncio
    async def test_whitespace_only_username(self):
        report = await username_lookup("   ")
        assert report.error == "Empty username"

    @pytest.mark.asyncio
    async def test_falls_back_to_builtin(self):
        """When no external tool is found, uses builtin checker."""
        with patch("ghostmcp.recon.username._run_external_tool", new_callable=AsyncMock) as mock_ext, \
             patch("ghostmcp.recon.username._builtin_check", new_callable=AsyncMock) as mock_builtin:
            mock_ext.return_value = None  # no tools installed
            mock_builtin.return_value = UsernameReport(
                username="johndoe",
                tool_used="builtin",
                sites_checked=17,
                accounts_found=[{"site_name": "GitHub", "url": "https://github.com/johndoe", "category": "development"}],
            )
            report = await username_lookup("johndoe")

        mock_builtin.assert_called_once()
        assert report.tool_used == "builtin"

    @pytest.mark.asyncio
    async def test_uses_external_when_available(self):
        """When maigret/sherlock found, skips builtin."""
        with patch("ghostmcp.recon.username._run_external_tool", new_callable=AsyncMock) as mock_ext, \
             patch("ghostmcp.recon.username._builtin_check", new_callable=AsyncMock) as mock_builtin:
            mock_ext.return_value = UsernameReport(
                username="johndoe",
                tool_used="maigret",
                sites_checked=100,
                accounts_found=[],
            )
            report = await username_lookup("johndoe")

        mock_builtin.assert_not_called()
        assert report.tool_used == "maigret"

    @pytest.mark.asyncio
    async def test_username_stripped(self):
        with patch("ghostmcp.recon.username._run_external_tool", new_callable=AsyncMock) as mock_ext, \
             patch("ghostmcp.recon.username._builtin_check", new_callable=AsyncMock) as mock_builtin:
            mock_ext.return_value = None
            mock_builtin.return_value = UsernameReport(username="johndoe")
            report = await username_lookup("  johndoe  ")

        # The function strips whitespace before passing to tools
        mock_ext.assert_called_once()
        assert mock_ext.call_args[0][0] == "johndoe"
