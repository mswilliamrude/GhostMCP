"""Tests for IP intelligence module."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ghostmcp.recon.ip_intel import (
    IPReport,
    ip_lookup,
    _is_valid_ipv4,
    _is_valid_ipv6,
    _is_valid_ip,
    _generate_search_urls,
)


# ---------------------------------------------------------------------------
# IP validation tests
# ---------------------------------------------------------------------------

class TestIPValidation:

    def test_valid_ipv4(self):
        assert _is_valid_ipv4("8.8.8.8")
        assert _is_valid_ipv4("192.168.1.1")
        assert _is_valid_ipv4("0.0.0.0")
        assert _is_valid_ipv4("255.255.255.255")

    def test_invalid_ipv4(self):
        assert not _is_valid_ipv4("")
        assert not _is_valid_ipv4("256.1.1.1")
        assert not _is_valid_ipv4("1.2.3")
        assert not _is_valid_ipv4("1.2.3.4.5")
        assert not _is_valid_ipv4("abc.def.ghi.jkl")
        assert not _is_valid_ipv4("1.2.3.-1")

    def test_valid_ipv6(self):
        assert _is_valid_ipv6("::1")
        assert _is_valid_ipv6("2001:db8::1")
        assert _is_valid_ipv6("fe80::1%eth0") is False  # zone ID not supported by inet_pton on all platforms

    def test_invalid_ipv6(self):
        assert not _is_valid_ipv6("")
        assert not _is_valid_ipv6("not-an-ip")
        assert not _is_valid_ipv6("8.8.8.8")  # IPv4 is not valid IPv6

    def test_is_valid_ip_combined(self):
        assert _is_valid_ip("8.8.8.8")
        assert _is_valid_ip("2001:db8::1")
        assert not _is_valid_ip("not-an-ip")
        assert not _is_valid_ip("")


# ---------------------------------------------------------------------------
# Search URL generation
# ---------------------------------------------------------------------------

class TestSearchUrls:

    def test_generates_expected_sites(self):
        urls = _generate_search_urls("8.8.8.8")
        assert "shodan" in urls
        assert "abuseipdb" in urls
        assert "censys" in urls
        assert "greynoise" in urls
        assert "virustotal" in urls
        assert "ipinfo" in urls
        assert "whois" in urls
        assert "bgpview" in urls
        assert "urlhaus" in urls

    def test_ip_in_urls(self):
        urls = _generate_search_urls("1.2.3.4")
        for name, url in urls.items():
            assert "1.2.3.4" in url, f"{name} URL doesn't contain IP"

    def test_url_count(self):
        urls = _generate_search_urls("8.8.8.8")
        assert len(urls) >= 9


# ---------------------------------------------------------------------------
# IP lookup with mocked API
# ---------------------------------------------------------------------------

SAMPLE_IP_API_RESPONSE = {
    "status": "success",
    "country": "United States",
    "countryCode": "US",
    "region": "VA",
    "regionName": "Virginia",
    "city": "Ashburn",
    "zip": "20149",
    "lat": 39.03,
    "lon": -77.5,
    "timezone": "America/New_York",
    "isp": "Google LLC",
    "org": "Google Public DNS",
    "as": "AS15169 Google LLC",
    "asname": "GOOGLE",
    "reverse": "dns.google",
    "mobile": False,
    "proxy": False,
    "hosting": True,
    "query": "8.8.8.8",
}


class TestIPLookup:

    @pytest.mark.asyncio
    async def test_invalid_ip_returns_error(self):
        report = await ip_lookup("not-an-ip")
        assert report.error is not None
        assert "Invalid" in report.error
        assert not report.valid

    @pytest.mark.asyncio
    async def test_empty_ip_returns_error(self):
        report = await ip_lookup("")
        assert report.error is not None
        assert not report.valid

    @pytest.mark.asyncio
    async def test_successful_lookup(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_IP_API_RESPONSE

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            with patch("socket.gethostbyaddr", return_value=("dns.google", [], ["8.8.8.8"])):
                report = await ip_lookup("8.8.8.8")

        assert report.valid
        assert report.error is None
        assert report.country == "United States"
        assert report.city == "Ashburn"
        assert report.isp == "Google LLC"
        assert report.asn == "AS15169 Google LLC"
        assert report.is_hosting is True
        assert report.is_proxy is False
        assert report.reverse_dns == "dns.google"
        assert report.timezone == "America/New_York"
        assert report.latitude == 39.03

    @pytest.mark.asyncio
    async def test_proxy_detection(self):
        data = SAMPLE_IP_API_RESPONSE.copy()
        data["proxy"] = True
        data["hosting"] = False
        data["mobile"] = False

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = data

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            with patch("socket.gethostbyaddr", side_effect=OSError):
                report = await ip_lookup("1.2.3.4")

        assert report.is_proxy is True
        assert report.is_hosting is False

    @pytest.mark.asyncio
    async def test_rate_limited(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 429

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            with patch("socket.gethostbyaddr", side_effect=OSError):
                report = await ip_lookup("8.8.8.8")

        assert report.error is not None
        assert "Rate limited" in report.error

    @pytest.mark.asyncio
    async def test_timeout_handling(self):
        import httpx as _httpx

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=_httpx.TimeoutException("")):
            with patch("socket.gethostbyaddr", side_effect=OSError):
                report = await ip_lookup("8.8.8.8")

        assert report.error is not None
        assert "Timeout" in report.error

    @pytest.mark.asyncio
    async def test_search_urls_populated(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_IP_API_RESPONSE

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            with patch("socket.gethostbyaddr", side_effect=OSError):
                report = await ip_lookup("8.8.8.8")

        assert len(report.search_urls) >= 9
        assert "shodan" in report.search_urls
        assert "8.8.8.8" in report.search_urls["shodan"]

    @pytest.mark.asyncio
    async def test_api_failure_status(self):
        data = {"status": "fail", "message": "private range"}
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = data

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            with patch("socket.gethostbyaddr", side_effect=OSError):
                report = await ip_lookup("192.168.1.1")

        assert report.error is not None
        assert "private range" in report.error

    @pytest.mark.asyncio
    async def test_ipv6_lookup(self):
        data = SAMPLE_IP_API_RESPONSE.copy()
        data["query"] = "2001:4860:4860::8888"

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = data

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            with patch("socket.gethostbyaddr", side_effect=OSError):
                report = await ip_lookup("2001:4860:4860::8888")

        assert report.valid
        assert report.country == "United States"
