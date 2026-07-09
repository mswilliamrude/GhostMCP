"""Tests for threat intelligence feeds — URLhaus, ThreatFox, RansomWatch, Feodo."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ghostmcp.recon.threats import (
    ThreatEntry,
    ThreatReport,
    _detect_indicator_type,
    query_urlhaus,
    query_threatfox_iocs,
    query_ransomwatch,
    query_feodo,
    threat_lookup,
)


# ---------------------------------------------------------------------------
# Sample API responses
# ---------------------------------------------------------------------------

SAMPLE_URLHAUS_URL_RESPONSE = {
    "query_status": "ok",
    "url": "http://evil.com/malware.exe",
    "threat": "malware_download",
    "tags": ["emotet", "banking"],
    "date_added": "2024-06-01 10:00:00",
    "urlhaus_reference": "https://urlhaus.abuse.ch/url/12345/",
}

SAMPLE_URLHAUS_HOST_RESPONSE = {
    "query_status": "ok",
    "urls": [
        {
            "url": "http://evil.com/payload1.exe",
            "threat": "malware_download",
            "tags": ["dridex"],
            "date_added": "2024-06-01 08:00:00",
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/11111/",
        },
        {
            "url": "http://evil.com/payload2.dll",
            "threat": "malware_download",
            "tags": None,
            "date_added": "2024-06-02 12:00:00",
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/22222/",
        },
    ],
}

SAMPLE_THREATFOX_RESPONSE = {
    "query_status": "ok",
    "data": [
        {
            "ioc": "http://c2.evil.com:8080/gate",
            "ioc_type": "url",
            "threat_type": "payload_delivery",
            "malware_printable": "Cobalt Strike",
            "tags": ["cobalt", "apt"],
            "first_seen_utc": "2024-07-01 00:00:00",
            "reference": "https://threatfox.abuse.ch/ioc/999/",
        },
        {
            "ioc": "192.168.1.100:443",
            "ioc_type": "ip:port",
            "threat_type": "botnet_cc",
            "malware_printable": "Emotet",
            "tags": ["emotet"],
            "first_seen_utc": "2024-07-02 00:00:00",
            "reference": "",
        },
    ],
}

SAMPLE_RANSOMWATCH_RESPONSE = [
    {
        "post_title": "victim-company.com",
        "group_name": "lockbit",
        "discovered": "2024-08-01 00:00:00",
        "post_url": "http://lockbit.onion/post/123",
    },
    {
        "post_title": "another-victim.org",
        "group_name": "alphv",
        "discovered": "2024-08-02 00:00:00",
        "post_url": "http://alphv.onion/post/456",
    },
]

SAMPLE_FEODO_RESPONSE = [
    {
        "ip_address": "10.0.0.1",
        "malware": "Dridex",
        "status": "online",
        "first_seen": "2024-09-01",
    },
    {
        "ip_address": "10.0.0.2",
        "malware": "TrickBot",
        "status": "offline",
        "first_seen": "2024-09-02",
    },
]


# ---------------------------------------------------------------------------
# Indicator type detection tests
# ---------------------------------------------------------------------------

class TestDetectIndicatorType:
    """Tests for _detect_indicator_type()."""

    def test_http_url(self):
        assert _detect_indicator_type("http://evil.com/malware.exe") == "url"

    def test_https_url(self):
        assert _detect_indicator_type("https://evil.com/path") == "url"

    def test_ipv4(self):
        assert _detect_indicator_type("192.168.1.1") == "ip"

    def test_ipv4_with_high_octets(self):
        assert _detect_indicator_type("255.255.255.255") == "ip"

    def test_ipv6(self):
        assert _detect_indicator_type("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "ip"

    def test_md5_hash(self):
        assert _detect_indicator_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"

    def test_sha256_hash(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert _detect_indicator_type(h) == "hash"

    def test_domain(self):
        assert _detect_indicator_type("evil.com") == "domain"

    def test_subdomain(self):
        assert _detect_indicator_type("malware.evil.com") == "domain"

    def test_invalid_ip_falls_to_domain(self):
        assert _detect_indicator_type("999.999.999.999") == "domain"


# ---------------------------------------------------------------------------
# URLhaus tests
# ---------------------------------------------------------------------------

class TestQueryUrlhaus:
    """Tests for query_urlhaus()."""

    @pytest.mark.asyncio
    async def test_url_lookup(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_URLHAUS_URL_RESPONSE

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            entries = await query_urlhaus("http://evil.com/malware.exe")

        assert len(entries) == 1
        assert entries[0].source == "urlhaus"
        assert entries[0].indicator_type == "url"
        assert "emotet" in entries[0].tags

    @pytest.mark.asyncio
    async def test_host_lookup(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_URLHAUS_HOST_RESPONSE

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            entries = await query_urlhaus("evil.com")

        assert len(entries) == 2
        assert entries[0].indicator == "http://evil.com/payload1.exe"
        assert entries[1].malware_family == ""  # tags is None

    @pytest.mark.asyncio
    async def test_no_results(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"query_status": "no_results"}

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            entries = await query_urlhaus("http://safe.example.com")

        assert entries == []

    @pytest.mark.asyncio
    async def test_timeout(self):
        import httpx

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = httpx.TimeoutException("timed out")
            entries = await query_urlhaus("http://evil.com/malware.exe")

        assert entries == []

    @pytest.mark.asyncio
    async def test_http_error(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 500

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            entries = await query_urlhaus("evil.com")

        assert entries == []


# ---------------------------------------------------------------------------
# ThreatFox tests
# ---------------------------------------------------------------------------

class TestQueryThreatfox:
    """Tests for query_threatfox_iocs()."""

    @pytest.mark.asyncio
    async def test_returns_iocs(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_THREATFOX_RESPONSE

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            entries = await query_threatfox_iocs(days=7)

        assert len(entries) == 2
        assert entries[0].source == "threatfox"
        assert entries[0].malware_family == "Cobalt Strike"
        assert entries[0].indicator_type == "url"

    @pytest.mark.asyncio
    async def test_maps_ip_type(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_THREATFOX_RESPONSE

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            entries = await query_threatfox_iocs()

        # Second entry is ip:port type
        assert entries[1].indicator_type == "ip"

    @pytest.mark.asyncio
    async def test_maps_botnet_to_c2(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_THREATFOX_RESPONSE

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            entries = await query_threatfox_iocs()

        # Second entry has botnet_cc -> c2
        assert entries[1].threat_type == "c2"

    @pytest.mark.asyncio
    async def test_no_results(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"query_status": "no_result", "data": None}

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            entries = await query_threatfox_iocs()

        assert entries == []

    @pytest.mark.asyncio
    async def test_timeout(self):
        import httpx

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = httpx.TimeoutException("timed out")
            entries = await query_threatfox_iocs()

        assert entries == []


# ---------------------------------------------------------------------------
# RansomWatch tests
# ---------------------------------------------------------------------------

class TestQueryRansomwatch:
    """Tests for query_ransomwatch()."""

    @pytest.mark.asyncio
    async def test_returns_entries(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_RANSOMWATCH_RESPONSE

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            entries = await query_ransomwatch()

        assert len(entries) == 2
        assert entries[0].source == "ransomwatch"
        assert entries[0].threat_type == "ransomware"
        assert entries[0].malware_family == "lockbit"
        assert entries[1].malware_family == "alphv"

    @pytest.mark.asyncio
    async def test_empty_response(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = []

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            entries = await query_ransomwatch()

        assert entries == []

    @pytest.mark.asyncio
    async def test_non_list_response(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"error": "unexpected"}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            entries = await query_ransomwatch()

        assert entries == []

    @pytest.mark.asyncio
    async def test_timeout(self):
        import httpx

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.TimeoutException("timed out")
            entries = await query_ransomwatch()

        assert entries == []


# ---------------------------------------------------------------------------
# Feodo tests
# ---------------------------------------------------------------------------

class TestQueryFeodo:
    """Tests for query_feodo()."""

    @pytest.mark.asyncio
    async def test_returns_entries(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_FEODO_RESPONSE

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            entries = await query_feodo()

        assert len(entries) == 2
        assert entries[0].source == "feodo"
        assert entries[0].indicator_type == "ip"
        assert entries[0].threat_type == "c2"
        assert entries[0].malware_family == "Dridex"
        assert entries[1].indicator == "10.0.0.2"

    @pytest.mark.asyncio
    async def test_empty_response(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = []

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            entries = await query_feodo()

        assert entries == []

    @pytest.mark.asyncio
    async def test_non_list_response(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"error": "bad format"}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            entries = await query_feodo()

        assert entries == []

    @pytest.mark.asyncio
    async def test_timeout(self):
        import httpx

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.TimeoutException("timed out")
            entries = await query_feodo()

        assert entries == []

    @pytest.mark.asyncio
    async def test_http_error(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 503

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            entries = await query_feodo()

        assert entries == []


# ---------------------------------------------------------------------------
# threat_lookup aggregation tests
# ---------------------------------------------------------------------------

class TestThreatLookup:
    """Tests for threat_lookup() aggregation."""

    @pytest.mark.asyncio
    async def test_aggregates_multiple_sources(self):
        with patch("src.recon.threats.query_urlhaus", new_callable=AsyncMock) as mock_uh, \
             patch("src.recon.threats.query_threatfox_iocs", new_callable=AsyncMock) as mock_tf, \
             patch("src.recon.threats.query_ransomwatch", new_callable=AsyncMock) as mock_rw, \
             patch("src.recon.threats.query_feodo", new_callable=AsyncMock) as mock_fe:

            mock_uh.return_value = [
                ThreatEntry("urlhaus", "http://evil.com", "url", "malware", "emotet", [], "", ""),
            ]
            mock_tf.return_value = [
                ThreatEntry("threatfox", "evil.com:443", "ip", "c2", "cobalt", [], "", ""),
            ]
            mock_rw.return_value = []
            mock_fe.return_value = [
                ThreatEntry("feodo", "evil.com", "ip", "c2", "dridex", [], "", ""),
            ]

            report = await threat_lookup("evil.com")

        assert len(report.entries) == 3
        assert len(report.sources_queried) == 4
        assert report.errors == {}

    @pytest.mark.asyncio
    async def test_filters_by_source(self):
        with patch("src.recon.threats.query_urlhaus", new_callable=AsyncMock) as mock_uh:
            mock_uh.return_value = [
                ThreatEntry("urlhaus", "http://evil.com", "url", "malware", "", [], "", ""),
            ]

            report = await threat_lookup("evil.com", sources=["urlhaus"])

        assert len(report.entries) == 1
        assert report.sources_queried == ["urlhaus"]

    @pytest.mark.asyncio
    async def test_handles_source_error(self):
        with patch("src.recon.threats.query_urlhaus", new_callable=AsyncMock) as mock_uh, \
             patch("src.recon.threats.query_threatfox_iocs", new_callable=AsyncMock) as mock_tf:

            mock_uh.side_effect = RuntimeError("connection failed")
            mock_tf.return_value = []

            report = await threat_lookup("evil.com", sources=["urlhaus", "threatfox"])

        assert "urlhaus" in report.errors
        assert "connection failed" in report.errors["urlhaus"]
        assert "threatfox" not in report.errors

    @pytest.mark.asyncio
    async def test_unknown_source_reports_error(self):
        report = await threat_lookup("evil.com", sources=["nonexistent"])

        assert "nonexistent" in report.errors
        assert "Unknown source" in report.errors["nonexistent"]
        assert report.entries == []

    @pytest.mark.asyncio
    async def test_query_stored_in_report(self):
        with patch("src.recon.threats.query_urlhaus", new_callable=AsyncMock) as mock_uh:
            mock_uh.return_value = []
            report = await threat_lookup("192.168.1.1", sources=["urlhaus"])

        assert report.query == "192.168.1.1"

    @pytest.mark.asyncio
    async def test_default_sources_includes_all(self):
        with patch("src.recon.threats.query_urlhaus", new_callable=AsyncMock) as mock_uh, \
             patch("src.recon.threats.query_threatfox_iocs", new_callable=AsyncMock) as mock_tf, \
             patch("src.recon.threats.query_ransomwatch", new_callable=AsyncMock) as mock_rw, \
             patch("src.recon.threats.query_feodo", new_callable=AsyncMock) as mock_fe:

            mock_uh.return_value = []
            mock_tf.return_value = []
            mock_rw.return_value = []
            mock_fe.return_value = []

            report = await threat_lookup("test.com")

        assert set(report.sources_queried) == {"urlhaus", "threatfox", "ransomwatch", "feodo"}
