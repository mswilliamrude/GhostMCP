"""Tests for BGP/ASN network infrastructure reconnaissance module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ghostmcp.recon.asn import (
    ASNReport,
    asn_lookup,
    detect_query_type,
    _parse_asn_number,
    _generate_investigation_urls,
    _parse_details,
    _parse_prefixes,
    _parse_peers,
    _parse_ixs,
)


# ---------------------------------------------------------------------------
# Sample API responses
# ---------------------------------------------------------------------------

SAMPLE_ASN_DETAILS = {
    "status": "ok",
    "data": {
        "asn": 15169,
        "name": "GOOGLE",
        "description_short": "Google LLC",
        "country_code": "US",
        "rir_allocation": {
            "rir_name": "ARIN",
            "date_allocated": "2000-03-30",
        },
        "email_contacts": ["network-abuse@google.com"],
    },
}

SAMPLE_ASN_PREFIXES = {
    "status": "ok",
    "data": {
        "ipv4_prefixes": [
            {
                "prefix": "8.8.8.0/24",
                "name": "LVLT-GOGL-8-8-8",
                "description": "Google LLC",
                "country_code": "US",
            },
            {
                "prefix": "8.8.4.0/24",
                "name": "LVLT-GOGL-8-8-4",
                "description": "Google LLC",
                "country_code": "US",
            },
        ],
        "ipv6_prefixes": [
            {
                "prefix": "2001:4860::/32",
                "name": "GOOGLE",
                "description": "Google LLC",
                "country_code": "US",
            },
        ],
    },
}

SAMPLE_ASN_PEERS = {
    "status": "ok",
    "data": {
        "ipv4_peers": [
            {
                "asn": 13335,
                "name": "CLOUDFLARENET",
                "description": "Cloudflare Inc",
                "country_code": "US",
                "is_upstream": True,
            },
            {
                "asn": 32934,
                "name": "FACEBOOK",
                "description": "Facebook Inc",
                "country_code": "US",
                "is_upstream": False,
            },
        ],
        "ipv6_peers": [
            {
                "asn": 2906,
                "name": "NETFLIX",
                "description": "Netflix Inc",
                "country_code": "US",
                "is_upstream": False,
            },
        ],
    },
}

SAMPLE_ASN_IXS = {
    "status": "ok",
    "data": [
        {
            "name": "DE-CIX Frankfurt",
            "name_full": "Deutscher Commercial Internet Exchange",
            "city": "Frankfurt",
            "country_code": "DE",
            "speed": 100000,
        },
        {
            "name": "AMS-IX",
            "name_full": "Amsterdam Internet Exchange",
            "city": "Amsterdam",
            "country_code": "NL",
            "speed": 400000,
        },
    ],
}

SAMPLE_IP_RESPONSE = {
    "status": "ok",
    "data": {
        "prefixes": [
            {
                "prefix": "8.8.8.0/24",
                "asn": {"asn": 15169, "name": "GOOGLE", "description": "Google LLC"},
            }
        ]
    },
}

SAMPLE_SEARCH_RESPONSE = {
    "status": "ok",
    "data": {
        "asns": [
            {"asn": 15169, "name": "GOOGLE", "description": "Google LLC", "country_code": "US"},
        ],
        "ipv4_prefixes": [],
        "ipv6_prefixes": [],
    },
}


# ---------------------------------------------------------------------------
# Query type detection
# ---------------------------------------------------------------------------

class TestQueryTypeDetection:

    def test_pure_digits(self):
        assert detect_query_type("15169") == "asn"

    def test_as_prefix_uppercase(self):
        assert detect_query_type("AS15169") == "asn"

    def test_as_prefix_lowercase(self):
        assert detect_query_type("as15169") == "asn"

    def test_ipv4_address(self):
        assert detect_query_type("8.8.8.8") == "ip"

    def test_ipv6_address(self):
        assert detect_query_type("2001:4860:4860::8888") == "ip"

    def test_org_name(self):
        assert detect_query_type("Google LLC") == "org"

    def test_single_word_org(self):
        assert detect_query_type("Cloudflare") == "org"

    def test_empty_string(self):
        assert detect_query_type("") == ""

    def test_whitespace(self):
        assert detect_query_type("   ") == ""

    def test_ipv4_with_whitespace(self):
        assert detect_query_type("  8.8.8.8  ") == "ip"


# ---------------------------------------------------------------------------
# ASN parsing
# ---------------------------------------------------------------------------

class TestASNParsing:

    def test_plain_number(self):
        assert _parse_asn_number("15169") == 15169

    def test_as_prefix(self):
        assert _parse_asn_number("AS15169") == 15169

    def test_lowercase_as_prefix(self):
        assert _parse_asn_number("as15169") == 15169

    def test_whitespace(self):
        assert _parse_asn_number("  AS15169  ") == 15169

    def test_invalid_string(self):
        with pytest.raises(ValueError):
            _parse_asn_number("notanumber")

    def test_negative_asn(self):
        with pytest.raises(ValueError):
            _parse_asn_number("-1")

    def test_zero_asn(self):
        with pytest.raises(ValueError):
            _parse_asn_number("0")

    def test_parse_details_response(self):
        report = ASNReport(query="15169")
        _parse_details(report, SAMPLE_ASN_DETAILS["data"])
        assert report.asn_name == "GOOGLE"
        assert report.description == "Google LLC"
        assert report.country_code == "US"
        assert report.rir == "ARIN"
        assert report.allocation_date == "2000-03-30"
        assert report.abuse_contact == "network-abuse@google.com"

    def test_parse_details_none(self):
        report = ASNReport(query="15169")
        _parse_details(report, None)
        assert report.asn_name == ""

    def test_parse_details_no_rir(self):
        report = ASNReport(query="12345")
        data = {"name": "TEST", "description_short": "Test ASN"}
        _parse_details(report, data)
        assert report.asn_name == "TEST"
        assert report.rir == ""

    def test_parse_prefixes_response(self):
        report = ASNReport(query="15169")
        _parse_prefixes(report, SAMPLE_ASN_PREFIXES["data"])
        assert report.prefix_count_v4 == 2
        assert report.prefix_count_v6 == 1
        assert report.prefixes_v4[0]["prefix"] == "8.8.8.0/24"
        assert report.prefixes_v6[0]["prefix"] == "2001:4860::/32"

    def test_parse_prefixes_none(self):
        report = ASNReport(query="15169")
        _parse_prefixes(report, None)
        assert report.prefix_count_v4 == 0
        assert report.prefix_count_v6 == 0

    def test_parse_peers_response(self):
        report = ASNReport(query="15169")
        _parse_peers(report, SAMPLE_ASN_PEERS["data"])
        assert len(report.upstream_peers) == 1
        assert report.upstream_peers[0]["asn"] == 13335
        assert report.upstream_peers[0]["name"] == "CLOUDFLARENET"
        assert len(report.downstream_peers) == 2  # FACEBOOK v4 + NETFLIX v6
        downstream_asns = {p["asn"] for p in report.downstream_peers}
        assert 32934 in downstream_asns
        assert 2906 in downstream_asns

    def test_parse_peers_none(self):
        report = ASNReport(query="15169")
        _parse_peers(report, None)
        assert report.upstream_peers == []
        assert report.downstream_peers == []

    def test_parse_peers_deduplicates_v6(self):
        """If the same ASN appears in both v4 and v6 peers, it should not duplicate."""
        data = {
            "ipv4_peers": [
                {"asn": 13335, "name": "CLOUDFLARENET", "description": "", "country_code": "US", "is_upstream": True},
            ],
            "ipv6_peers": [
                {"asn": 13335, "name": "CLOUDFLARENET", "description": "", "country_code": "US", "is_upstream": True},
            ],
        }
        report = ASNReport(query="test")
        _parse_peers(report, data)
        assert len(report.upstream_peers) == 1

    def test_parse_ixs_response(self):
        report = ASNReport(query="15169")
        _parse_ixs(report, SAMPLE_ASN_IXS["data"])
        assert len(report.ix_presence) == 2
        assert report.ix_presence[0]["name"] == "DE-CIX Frankfurt"
        assert report.ix_presence[0]["country"] == "DE"
        assert report.ix_presence[1]["speed"] == 400000

    def test_parse_ixs_none(self):
        report = ASNReport(query="15169")
        _parse_ixs(report, None)
        assert report.ix_presence == []

    def test_parse_ixs_dict_not_list(self):
        """If data is a dict instead of list, should not crash."""
        report = ASNReport(query="15169")
        _parse_ixs(report, {"some_key": "value"})
        assert report.ix_presence == []


# ---------------------------------------------------------------------------
# Investigation URL generation
# ---------------------------------------------------------------------------

class TestInvestigationUrls:

    def test_generates_all_expected_sites(self):
        urls = _generate_investigation_urls(15169)
        assert "bgpview" in urls
        assert "ripestat" in urls
        assert "he_bgp" in urls
        assert "peeringdb" in urls
        assert "bgp_tools" in urls

    def test_asn_in_urls(self):
        urls = _generate_investigation_urls(15169)
        for name, url in urls.items():
            assert "15169" in url, f"{name} URL doesn't contain ASN"

    def test_url_formats(self):
        urls = _generate_investigation_urls(13335)
        assert urls["bgpview"] == "https://bgpview.io/asn/13335"
        assert urls["ripestat"] == "https://stat.ripe.net/AS13335"
        assert urls["he_bgp"] == "https://bgp.he.net/AS13335"
        assert urls["peeringdb"] == "https://www.peeringdb.com/asn/13335"
        assert urls["bgp_tools"] == "https://bgp.tools/as/13335"

    def test_url_count(self):
        urls = _generate_investigation_urls(15169)
        assert len(urls) == 5


# ---------------------------------------------------------------------------
# Helper to build mock responses for BGPView endpoints
# ---------------------------------------------------------------------------

def _mock_bgpview_get(responses: dict):
    """Return an AsyncMock for httpx.AsyncClient.get that dispatches by URL path.

    *responses* maps URL substrings to (status_code, json_body) tuples.
    """
    async def _side_effect(url, **kwargs):
        # Handle /search?query_term=... separately
        if "/search" in str(url):
            key = "/search"
        else:
            key = None
            for fragment in responses:
                if fragment in str(url):
                    key = fragment
                    break

        if key and key in responses:
            status, body = responses[key]
            mock_resp = MagicMock()
            mock_resp.status_code = status
            mock_resp.json.return_value = body
            return mock_resp

        # Default: 404
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.json.return_value = {"status": "error"}
        return mock_resp

    return AsyncMock(side_effect=_side_effect)


# ---------------------------------------------------------------------------
# ASN lookup tests (mocked httpx)
# ---------------------------------------------------------------------------

class TestASNLookup:

    @pytest.mark.asyncio
    async def test_empty_query(self):
        report = await asn_lookup("")
        assert report.error is not None
        assert "required" in report.error.lower()

    @pytest.mark.asyncio
    async def test_invalid_asn(self):
        report = await asn_lookup("ASXYZ", query_type="asn")
        assert report.error is not None
        assert "Invalid" in report.error

    @pytest.mark.asyncio
    async def test_unknown_query_type(self):
        report = await asn_lookup("test", query_type="unknown")
        assert report.error is not None
        assert "Unknown" in report.error

    @pytest.mark.asyncio
    async def test_asn_lookup_by_number(self):
        """Mock all 4 BGPView endpoints and verify full report population."""
        mock_get = _mock_bgpview_get({
            "/asn/15169/prefixes": (200, SAMPLE_ASN_PREFIXES),
            "/asn/15169/peers": (200, SAMPLE_ASN_PEERS),
            "/asn/15169/ixs": (200, SAMPLE_ASN_IXS),
            "/asn/15169": (200, SAMPLE_ASN_DETAILS),
        })

        with patch("httpx.AsyncClient.get", mock_get):
            report = await asn_lookup("AS15169")

        assert report.error is None
        assert report.asn == 15169
        assert report.query_type == "asn"
        assert report.asn_name == "GOOGLE"
        assert report.description == "Google LLC"
        assert report.rir == "ARIN"
        assert report.abuse_contact == "network-abuse@google.com"
        assert report.prefix_count_v4 == 2
        assert report.prefix_count_v6 == 1
        assert len(report.upstream_peers) >= 1
        assert len(report.downstream_peers) >= 1
        assert len(report.ix_presence) == 2
        assert "bgpview" in report.investigation_urls

    @pytest.mark.asyncio
    async def test_ip_to_asn(self):
        """Mock IP endpoint + follow-up ASN endpoints."""
        mock_get = _mock_bgpview_get({
            "/ip/8.8.8.8": (200, SAMPLE_IP_RESPONSE),
            "/asn/15169/prefixes": (200, SAMPLE_ASN_PREFIXES),
            "/asn/15169/peers": (200, SAMPLE_ASN_PEERS),
            "/asn/15169/ixs": (200, SAMPLE_ASN_IXS),
            "/asn/15169": (200, SAMPLE_ASN_DETAILS),
        })

        with patch("httpx.AsyncClient.get", mock_get):
            report = await asn_lookup("8.8.8.8")

        assert report.error is None
        assert report.query_type == "ip"
        assert report.asn == 15169
        assert report.asn_name == "GOOGLE"

    @pytest.mark.asyncio
    async def test_ip_to_asn_no_prefixes(self):
        """IP lookup returns empty prefixes → error."""
        empty_ip = {"status": "ok", "data": {"prefixes": []}}
        mock_get = _mock_bgpview_get({"/ip/1.2.3.4": (200, empty_ip)})

        with patch("httpx.AsyncClient.get", mock_get):
            report = await asn_lookup("1.2.3.4")

        assert report.error is not None
        assert "Could not resolve" in report.error

    @pytest.mark.asyncio
    async def test_org_search(self):
        """Mock search endpoint + follow-up ASN endpoints."""
        mock_get = _mock_bgpview_get({
            "/search": (200, SAMPLE_SEARCH_RESPONSE),
            "/asn/15169/prefixes": (200, SAMPLE_ASN_PREFIXES),
            "/asn/15169/peers": (200, SAMPLE_ASN_PEERS),
            "/asn/15169/ixs": (200, SAMPLE_ASN_IXS),
            "/asn/15169": (200, SAMPLE_ASN_DETAILS),
        })

        with patch("httpx.AsyncClient.get", mock_get):
            report = await asn_lookup("Google LLC")

        assert report.error is None
        assert report.query_type == "org"
        assert report.asn == 15169

    @pytest.mark.asyncio
    async def test_org_search_no_results(self):
        """Org search returns no ASNs → error."""
        empty_search = {"status": "ok", "data": {"asns": [], "ipv4_prefixes": [], "ipv6_prefixes": []}}
        mock_get = _mock_bgpview_get({"/search": (200, empty_search)})

        with patch("httpx.AsyncClient.get", mock_get):
            report = await asn_lookup("Nonexistent Corp")

        assert report.error is not None
        assert "No ASN found" in report.error

    @pytest.mark.asyncio
    async def test_partial_api_failure(self):
        """Prefixes endpoint fails (404), but peers/details/ixs succeed → partial data."""
        mock_get = _mock_bgpview_get({
            "/asn/15169/prefixes": (404, {"status": "error"}),
            "/asn/15169/peers": (200, SAMPLE_ASN_PEERS),
            "/asn/15169/ixs": (200, SAMPLE_ASN_IXS),
            "/asn/15169": (200, SAMPLE_ASN_DETAILS),
        })

        with patch("httpx.AsyncClient.get", mock_get):
            report = await asn_lookup("15169")

        # Should still succeed — partial data is fine
        assert report.error is None
        assert report.asn == 15169
        assert report.asn_name == "GOOGLE"
        assert report.prefix_count_v4 == 0  # prefixes failed
        assert report.prefix_count_v6 == 0
        assert len(report.upstream_peers) >= 1  # peers succeeded
        assert len(report.ix_presence) == 2  # ixs succeeded

    @pytest.mark.asyncio
    async def test_all_endpoints_fail(self):
        """All 4 ASN data endpoints fail → report with asn set, error message, and investigation URLs."""
        mock_get = _mock_bgpview_get({
            "/asn/99999/prefixes": (500, {"status": "error"}),
            "/asn/99999/peers": (500, {"status": "error"}),
            "/asn/99999/ixs": (500, {"status": "error"}),
            "/asn/99999": (500, {"status": "error"}),
        })

        with patch("httpx.AsyncClient.get", mock_get):
            report = await asn_lookup("99999")

        # Error reported when all endpoints fail
        assert report.error is not None
        assert "unreachable" in report.error.lower()
        assert report.asn == 99999
        assert report.asn_name == ""
        assert report.prefix_count_v4 == 0
        # Investigation URLs still populated for manual lookup
        assert "bgpview" in report.investigation_urls

    @pytest.mark.asyncio
    async def test_bgpview_timeout(self):
        """All requests time out → empty data, no crash."""
        import httpx as _httpx

        async def _timeout(*args, **kwargs):
            raise _httpx.TimeoutException("Connection timed out")

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=_timeout):
            report = await asn_lookup("15169")

        # Timeout during data fetch → partial empty report, no hard error
        assert report.asn == 15169
        assert report.asn_name == ""
        assert report.prefix_count_v4 == 0

    @pytest.mark.asyncio
    async def test_bgpview_connect_error(self):
        """Connection error → graceful degradation."""
        import httpx as _httpx

        async def _connect_err(*args, **kwargs):
            raise _httpx.ConnectError("Connection refused")

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=_connect_err):
            report = await asn_lookup("15169")

        assert report.asn == 15169
        assert report.asn_name == ""

    @pytest.mark.asyncio
    async def test_ip_lookup_timeout(self):
        """IP resolution times out → error (can't resolve ASN)."""
        import httpx as _httpx

        async def _timeout(*args, **kwargs):
            raise _httpx.TimeoutException("timed out")

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=_timeout):
            report = await asn_lookup("8.8.8.8")

        assert report.error is not None
        assert "Could not resolve" in report.error

    @pytest.mark.asyncio
    async def test_numeric_asn_no_prefix(self):
        """Plain number (no AS prefix) works."""
        mock_get = _mock_bgpview_get({
            "/asn/13335/prefixes": (200, {"status": "ok", "data": {"ipv4_prefixes": [], "ipv6_prefixes": []}}),
            "/asn/13335/peers": (200, {"status": "ok", "data": {"ipv4_peers": [], "ipv6_peers": []}}),
            "/asn/13335/ixs": (200, {"status": "ok", "data": []}),
            "/asn/13335": (200, {"status": "ok", "data": {"name": "CLOUDFLARENET", "description_short": "Cloudflare Inc", "country_code": "US"}}),
        })

        with patch("httpx.AsyncClient.get", mock_get):
            report = await asn_lookup("13335")

        assert report.error is None
        assert report.asn == 13335
        assert report.asn_name == "CLOUDFLARENET"

    @pytest.mark.asyncio
    async def test_investigation_urls_populated(self):
        """Investigation URLs are generated after successful lookup."""
        mock_get = _mock_bgpview_get({
            "/asn/15169/prefixes": (200, SAMPLE_ASN_PREFIXES),
            "/asn/15169/peers": (200, SAMPLE_ASN_PEERS),
            "/asn/15169/ixs": (200, SAMPLE_ASN_IXS),
            "/asn/15169": (200, SAMPLE_ASN_DETAILS),
        })

        with patch("httpx.AsyncClient.get", mock_get):
            report = await asn_lookup("15169")

        assert len(report.investigation_urls) == 5
        assert "15169" in report.investigation_urls["bgpview"]
        assert "AS15169" in report.investigation_urls["ripestat"]


# ---------------------------------------------------------------------------
# Integration test (real API, skipped by default)
# ---------------------------------------------------------------------------

class TestIntegration:

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_real_asn_lookup_google(self):
        """Live lookup of AS15169 (Google) against real BGPView API."""
        report = await asn_lookup("AS15169")

        assert report.error is None
        assert report.asn == 15169
        assert report.asn_name  # Should have a name
        assert report.prefix_count_v4 > 0  # Google announces many prefixes
        assert report.investigation_urls

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_real_ip_lookup(self):
        """Live IP → ASN resolution for 8.8.8.8."""
        report = await asn_lookup("8.8.8.8")

        assert report.error is None
        assert report.asn == 15169
        assert report.query_type == "ip"

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_real_org_search(self):
        """Live org search for 'Cloudflare'."""
        report = await asn_lookup("Cloudflare")

        assert report.error is None
        assert report.asn > 0
        assert report.query_type == "org"
