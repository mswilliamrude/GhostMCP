"""Tests for subdomain enumeration via crt.sh."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.recon.subdomains import (
    CertEntry,
    SubdomainReport,
    _clean_subdomain,
    _parse_crtsh_response,
    enumerate_subdomains,
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
