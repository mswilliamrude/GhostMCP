"""Tests for subdomain enumeration via crt.sh and DNS brute force."""

from __future__ import annotations

import asyncio
import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.recon.subdomains import (
    CertEntry,
    SubdomainReport,
    _clean_subdomain,
    _parse_crtsh_response,
    enumerate_subdomains,
    dns_brute_force,
    DEFAULT_WORDLIST,
    _resolve_host,
)


# Sample crt.sh JSON response
SAMPLE_CRTSH_RESPONSE = [
    {
        "name_value": "www.example.com",
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "not_before": "2026-01-15T00:00:00",
        "not_after": "2027-04-15T23:59:59",
    },
    {
        "name_value": "api.example.com\nmail.example.com",
        "issuer_name": "C=US, O=DigiCert, CN=DigiCert SHA2",
        "not_before": "2026-03-01T00:00:00",
        "not_after": "2027-03-01T23:59:59",
    },
    {
        "name_value": "*.dev.example.com",
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "not_before": "2026-06-01T00:00:00",
        "not_after": "2027-09-01T23:59:59",
    },
    {
        "name_value": "staging.example.com",
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "not_before": "2020-01-01T00:00:00",
        "not_after": "2021-01-01T23:59:59",  # Expired
    },
    {
        "name_value": "other.notexample.com",
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "not_before": "2026-01-01T00:00:00",
        "not_after": "2027-01-01T23:59:59",
    },
]


class TestCleanSubdomain:
    """Tests for subdomain name cleaning."""

    def test_simple_name(self):
        assert _clean_subdomain("www.example.com") == "www.example.com"

    def test_strips_wildcard(self):
        assert _clean_subdomain("*.example.com") == "example.com"

    def test_strips_wildcard_deep(self):
        assert _clean_subdomain("*.dev.example.com") == "dev.example.com"

    def test_lowercase(self):
        assert _clean_subdomain("WWW.EXAMPLE.COM") == "www.example.com"

    def test_strips_whitespace(self):
        assert _clean_subdomain("  www.example.com  ") == "www.example.com"

    def test_rejects_no_dot(self):
        assert _clean_subdomain("localhost") is None

    def test_rejects_empty(self):
        assert _clean_subdomain("") is None

    def test_rejects_invalid_chars(self):
        assert _clean_subdomain("www.exam ple.com") is None

    def test_rejects_underscore(self):
        # Underscores are not valid in hostnames (though some exist in practice)
        assert _clean_subdomain("_dmarc.example.com") is None


class TestCertEntry:
    """Tests for CertEntry dataclass."""

    def test_not_expired(self):
        entry = CertEntry(
            subdomain="www.example.com",
            issuer="Let's Encrypt",
            not_before="2026-01-01T00:00:00",
            not_after="2099-12-31T23:59:59",
        )
        assert entry.is_expired is False

    def test_expired(self):
        entry = CertEntry(
            subdomain="old.example.com",
            issuer="Let's Encrypt",
            not_before="2020-01-01T00:00:00",
            not_after="2021-01-01T23:59:59",
        )
        assert entry.is_expired is True

    def test_invalid_date_not_expired(self):
        entry = CertEntry(
            subdomain="x.example.com",
            issuer="test",
            not_before="",
            not_after="not-a-date",
        )
        # Invalid dates default to not expired
        assert entry.is_expired is False


class TestParseResponse:
    """Tests for crt.sh response parsing."""

    def test_extracts_subdomains(self):
        report = _parse_crtsh_response(SAMPLE_CRTSH_RESPONSE, "example.com")
        assert "www.example.com" in report.subdomains
        assert "api.example.com" in report.subdomains
        assert "mail.example.com" in report.subdomains

    def test_strips_wildcards(self):
        report = _parse_crtsh_response(SAMPLE_CRTSH_RESPONSE, "example.com")
        # *.dev.example.com → dev.example.com
        assert "dev.example.com" in report.subdomains
        assert "*.dev.example.com" not in report.subdomains

    def test_deduplicates(self):
        duped = SAMPLE_CRTSH_RESPONSE + [SAMPLE_CRTSH_RESPONSE[0]]
        report = _parse_crtsh_response(duped, "example.com")
        # www.example.com appears twice but should be deduplicated
        assert report.subdomains.count("www.example.com") == 1

    def test_sorted(self):
        report = _parse_crtsh_response(SAMPLE_CRTSH_RESPONSE, "example.com")
        assert report.subdomains == sorted(report.subdomains)

    def test_filters_other_domains(self):
        report = _parse_crtsh_response(SAMPLE_CRTSH_RESPONSE, "example.com")
        assert "other.notexample.com" not in report.subdomains

    def test_excludes_expired_by_default(self):
        report = _parse_crtsh_response(SAMPLE_CRTSH_RESPONSE, "example.com", include_expired=False)
        assert "staging.example.com" not in report.subdomains

    def test_includes_expired_when_asked(self):
        report = _parse_crtsh_response(SAMPLE_CRTSH_RESPONSE, "example.com", include_expired=True)
        assert "staging.example.com" in report.subdomains

    def test_total_certs_count(self):
        report = _parse_crtsh_response(SAMPLE_CRTSH_RESPONSE, "example.com")
        assert report.total_certs == len(SAMPLE_CRTSH_RESPONSE)

    def test_handles_multiline_names(self):
        # api.example.com and mail.example.com were in one name_value
        report = _parse_crtsh_response(SAMPLE_CRTSH_RESPONSE, "example.com")
        assert "api.example.com" in report.subdomains
        assert "mail.example.com" in report.subdomains

    def test_empty_response(self):
        report = _parse_crtsh_response([], "example.com")
        assert report.subdomains == []
        assert report.total_certs == 0

    def test_domain_itself_included(self):
        data = [{"name_value": "example.com", "issuer_name": "R3", "not_before": "2026-01-01", "not_after": "2027-01-01"}]
        report = _parse_crtsh_response(data, "example.com")
        assert "example.com" in report.subdomains


class TestEnumerateSubdomains:
    """Tests for the async enumerate function — mocked HTTP."""

    @pytest.mark.asyncio
    async def test_successful_lookup(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = SAMPLE_CRTSH_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            report = await enumerate_subdomains("example.com")

        assert len(report.subdomains) > 0
        assert report.error is None

    @pytest.mark.asyncio
    async def test_timeout_returns_error(self):
        import httpx

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.TimeoutException("timed out")
            report = await enumerate_subdomains("example.com")

        assert report.error is not None
        assert "Timeout" in report.error

    @pytest.mark.asyncio
    async def test_http_error_returns_error(self):
        import httpx

        mock_resp = MagicMock()
        mock_resp.status_code = 503

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.HTTPStatusError(
                "Service Unavailable",
                request=MagicMock(),
                response=mock_resp,
            )
            report = await enumerate_subdomains("example.com")

        assert report.error is not None
        assert "503" in report.error

    @pytest.mark.asyncio
    async def test_domain_lowercased(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = []
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            report = await enumerate_subdomains("EXAMPLE.COM")

        assert report.domain == "example.com"


class TestSubdomainReport:
    """Tests for SubdomainReport dataclass."""

    def test_defaults(self):
        report = SubdomainReport(domain="example.com")
        assert report.subdomains == []
        assert report.cert_entries == []
        assert report.total_certs == 0
        assert report.error is None

    def test_with_error(self):
        report = SubdomainReport(domain="example.com", error="something broke")
        assert report.error == "something broke"


# ---------------------------------------------------------------------------
# DNS brute force tests
# ---------------------------------------------------------------------------

class TestDefaultWordlist:
    """Tests for the default subdomain wordlist."""

    def test_wordlist_has_common_entries(self):
        assert "www" in DEFAULT_WORDLIST
        assert "mail" in DEFAULT_WORDLIST
        assert "api" in DEFAULT_WORDLIST
        assert "admin" in DEFAULT_WORDLIST
        assert "staging" in DEFAULT_WORDLIST

    def test_wordlist_size(self):
        """Wordlist should have roughly 50 entries."""
        assert len(DEFAULT_WORDLIST) >= 45
        assert len(DEFAULT_WORDLIST) <= 55

    def test_wordlist_no_duplicates(self):
        assert len(DEFAULT_WORDLIST) == len(set(DEFAULT_WORDLIST))


class TestResolveHost:
    """Tests for _resolve_host() helper."""

    def test_successful_resolution(self):
        with patch("src.recon.subdomains.socket.getaddrinfo", return_value=[("AF_INET",)]):
            assert _resolve_host("www.example.com", 2.0) is True

    def test_failed_resolution(self):
        with patch("src.recon.subdomains.socket.getaddrinfo",
                   side_effect=socket.gaierror("Name or service not known")):
            assert _resolve_host("nonexistent.example.com", 2.0) is False

    def test_timeout_resolution(self):
        with patch("src.recon.subdomains.socket.getaddrinfo",
                   side_effect=socket.timeout("timed out")):
            assert _resolve_host("slow.example.com", 0.1) is False

    def test_os_error_resolution(self):
        with patch("src.recon.subdomains.socket.getaddrinfo",
                   side_effect=OSError("Network error")):
            assert _resolve_host("bad.example.com", 2.0) is False


class TestDnsBruteForce:
    """Tests for dns_brute_force() — mocked DNS."""

    @pytest.mark.asyncio
    async def test_finds_resolving_subdomains(self):
        """Should return subdomains that resolve successfully."""
        resolving = {"www.example.com", "api.example.com"}

        def mock_resolve(fqdn, timeout):
            return fqdn in resolving

        with patch("src.recon.subdomains._resolve_host", side_effect=mock_resolve):
            result = await dns_brute_force("example.com", wordlist=["www", "api", "nope"])

        assert "www.example.com" in result
        assert "api.example.com" in result
        assert "nope.example.com" not in result

    @pytest.mark.asyncio
    async def test_returns_sorted(self):
        """Results should be sorted alphabetically."""
        def mock_resolve(fqdn, timeout):
            return True

        with patch("src.recon.subdomains._resolve_host", side_effect=mock_resolve):
            result = await dns_brute_force("example.com", wordlist=["zzz", "aaa", "mmm"])

        assert result == sorted(result)

    @pytest.mark.asyncio
    async def test_uses_default_wordlist(self):
        """When no wordlist provided, uses DEFAULT_WORDLIST."""
        called_fqdns: list[str] = []

        def mock_resolve(fqdn, timeout):
            called_fqdns.append(fqdn)
            return False

        with patch("src.recon.subdomains._resolve_host", side_effect=mock_resolve):
            result = await dns_brute_force("example.com")

        assert len(called_fqdns) == len(DEFAULT_WORDLIST)
        assert result == []

    @pytest.mark.asyncio
    async def test_custom_wordlist(self):
        """Custom wordlist should override the default."""
        def mock_resolve(fqdn, timeout):
            return fqdn == "custom.example.com"

        with patch("src.recon.subdomains._resolve_host", side_effect=mock_resolve):
            result = await dns_brute_force("example.com", wordlist=["custom", "other"])

        assert result == ["custom.example.com"]

    @pytest.mark.asyncio
    async def test_empty_wordlist(self):
        """Empty wordlist should return no results."""
        with patch("src.recon.subdomains._resolve_host") as mock:
            result = await dns_brute_force("example.com", wordlist=[])

        assert result == []
        mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_none_resolve(self):
        """When nothing resolves, return empty list."""
        def mock_resolve(fqdn, timeout):
            return False

        with patch("src.recon.subdomains._resolve_host", side_effect=mock_resolve):
            result = await dns_brute_force("example.com", wordlist=["www", "mail", "ftp"])

        assert result == []

    @pytest.mark.asyncio
    async def test_domain_lowercased(self):
        """Domain should be lowercased before use."""
        called_fqdns: list[str] = []

        def mock_resolve(fqdn, timeout):
            called_fqdns.append(fqdn)
            return False

        with patch("src.recon.subdomains._resolve_host", side_effect=mock_resolve):
            await dns_brute_force("EXAMPLE.COM", wordlist=["www"])

        assert called_fqdns == ["www.example.com"]

    @pytest.mark.asyncio
    async def test_timeout_passed_to_resolver(self):
        """Custom timeout should be passed through to _resolve_host."""
        timeouts_seen: list[float] = []

        def mock_resolve(fqdn, timeout):
            timeouts_seen.append(timeout)
            return False

        with patch("src.recon.subdomains._resolve_host", side_effect=mock_resolve):
            await dns_brute_force("example.com", wordlist=["www"], timeout=5.0)

        assert timeouts_seen == [5.0]


class TestGhostSubdomainsMethodAll:
    """Tests for method='all' deduplication via the MCP tool."""

    @pytest.mark.asyncio
    async def test_deduplication_across_methods(self):
        """When both crt.sh and DNS find the same subdomain, it should appear once."""
        # Mock crt.sh to return www + api
        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {
                "name_value": "www.example.com",
                "issuer_name": "R3",
                "not_before": "2026-01-01T00:00:00",
                "not_after": "2027-01-01T23:59:59",
            },
            {
                "name_value": "api.example.com",
                "issuer_name": "R3",
                "not_before": "2026-01-01T00:00:00",
                "not_after": "2027-01-01T23:59:59",
            },
        ]
        mock_resp.raise_for_status = MagicMock()

        # Mock DNS to find www + mail (www overlaps with crt.sh)
        def mock_resolve(fqdn, timeout):
            return fqdn in ("www.example.com", "mail.example.com")

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            with patch("src.recon.subdomains._resolve_host", side_effect=mock_resolve):
                from src.mcp import ghost_subdomains
                result = await ghost_subdomains("example.com", method="all")

        # All three should appear, www only once
        assert "www.example.com" in result
        assert "api.example.com" in result
        assert "mail.example.com" in result
        # Count occurrences of www — should appear exactly once (deduplicated)
        www_lines = [line for line in result.split("\n") if "www.example.com" in line and line.strip().startswith("www")]
        assert len(www_lines) == 1
