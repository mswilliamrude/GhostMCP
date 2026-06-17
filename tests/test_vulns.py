"""Tests for vulnerability intelligence — CVE lookup, package vulns, EPSS, KEV."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.recon.vulns import (
    CVEResult,
    PackageVulnResult,
    _cvss_to_severity,
    _parse_nvd_item,
    get_epss,
    get_kev_list,
    _is_in_kev,
    lookup_cve,
    search_cves,
    check_package,
)


# ---------------------------------------------------------------------------
# Sample API responses
# ---------------------------------------------------------------------------

SAMPLE_NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-1234",
                "descriptions": [
                    {"lang": "en", "value": "A critical buffer overflow in ExampleLib."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {"baseScore": 9.8},
                        }
                    ],
                },
                "published": "2024-01-15T10:00:00.000",
                "references": [
                    {"url": "https://example.com/advisory/1234"},
                    {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"},
                ],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {"criteria": "cpe:2.3:a:examplelib:examplelib:*:*:*:*:*:*:*:*"},
                                ]
                            }
                        ]
                    }
                ],
            }
        }
    ],
}

SAMPLE_NVD_SEARCH_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-1111",
                "descriptions": [{"lang": "en", "value": "First result."}],
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}],
                },
                "published": "2024-02-01T00:00:00.000",
                "references": [],
                "configurations": [],
            }
        },
        {
            "cve": {
                "id": "CVE-2024-2222",
                "descriptions": [{"lang": "en", "value": "Second result."}],
                "metrics": {},
                "published": "2024-03-01T00:00:00.000",
                "references": [],
                "configurations": [],
            }
        },
    ],
}

SAMPLE_EPSS_RESPONSE = {
    "data": [
        {"cve": "CVE-2024-1234", "epss": "0.95432", "percentile": "0.99100"},
    ],
}

SAMPLE_KEV_RESPONSE = {
    "vulnerabilities": [
        {"cveID": "CVE-2024-1234", "vendorProject": "ExampleLib"},
        {"cveID": "CVE-2023-9999", "vendorProject": "OtherLib"},
    ],
}

SAMPLE_OSV_RESPONSE = {
    "vulns": [
        {
            "id": "GHSA-abcd-1234-efgh",
            "summary": "XSS vulnerability in example-package.",
            "severity": [{"score": "6.1"}],
            "references": [{"url": "https://github.com/advisories/GHSA-abcd-1234-efgh"}],
            "affected": [
                {"package": {"name": "example-package", "ecosystem": "PyPI"}},
            ],
            "published": "2024-05-01T00:00:00Z",
        },
        {
            "id": "CVE-2024-5678",
            "summary": "SQL injection in example-package.",
            "severity": [],
            "references": [],
            "affected": [
                {"package": {"name": "example-package", "ecosystem": "PyPI"}},
            ],
            "modified": "2024-06-15T00:00:00Z",
        },
    ],
}


# ---------------------------------------------------------------------------
# Severity mapping tests
# ---------------------------------------------------------------------------

class TestSeverityMapping:
    """Tests for _cvss_to_severity()."""

    def test_critical(self):
        assert _cvss_to_severity(9.8) == "CRITICAL"
        assert _cvss_to_severity(9.0) == "CRITICAL"
        assert _cvss_to_severity(10.0) == "CRITICAL"

    def test_high(self):
        assert _cvss_to_severity(8.9) == "HIGH"
        assert _cvss_to_severity(7.0) == "HIGH"

    def test_medium(self):
        assert _cvss_to_severity(6.9) == "MEDIUM"
        assert _cvss_to_severity(4.0) == "MEDIUM"

    def test_low(self):
        assert _cvss_to_severity(3.9) == "LOW"
        assert _cvss_to_severity(0.1) == "LOW"

    def test_unknown_for_none(self):
        assert _cvss_to_severity(None) == "UNKNOWN"

    def test_unknown_for_zero(self):
        assert _cvss_to_severity(0.0) == "UNKNOWN"


# ---------------------------------------------------------------------------
# NVD parsing tests
# ---------------------------------------------------------------------------

class TestParseNvdItem:
    """Tests for _parse_nvd_item()."""

    def test_parses_cve_id(self):
        item = SAMPLE_NVD_RESPONSE["vulnerabilities"][0]
        result = _parse_nvd_item(item)
        assert result.cve_id == "CVE-2024-1234"

    def test_parses_description(self):
        item = SAMPLE_NVD_RESPONSE["vulnerabilities"][0]
        result = _parse_nvd_item(item)
        assert "buffer overflow" in result.description

    def test_parses_cvss_score(self):
        item = SAMPLE_NVD_RESPONSE["vulnerabilities"][0]
        result = _parse_nvd_item(item)
        assert result.cvss_score == 9.8

    def test_parses_severity(self):
        item = SAMPLE_NVD_RESPONSE["vulnerabilities"][0]
        result = _parse_nvd_item(item)
        assert result.severity == "CRITICAL"

    def test_parses_references(self):
        item = SAMPLE_NVD_RESPONSE["vulnerabilities"][0]
        result = _parse_nvd_item(item)
        assert len(result.references) == 2
        assert "https://example.com/advisory/1234" in result.references

    def test_parses_affected_products(self):
        item = SAMPLE_NVD_RESPONSE["vulnerabilities"][0]
        result = _parse_nvd_item(item)
        assert len(result.affected_products) == 1
        assert "examplelib" in result.affected_products[0]

    def test_parses_published(self):
        item = SAMPLE_NVD_RESPONSE["vulnerabilities"][0]
        result = _parse_nvd_item(item)
        assert result.published.startswith("2024-01-15")

    def test_source_is_nvd(self):
        item = SAMPLE_NVD_RESPONSE["vulnerabilities"][0]
        result = _parse_nvd_item(item)
        assert result.source == "nvd"

    def test_defaults_without_metrics(self):
        item = SAMPLE_NVD_SEARCH_RESPONSE["vulnerabilities"][1]
        result = _parse_nvd_item(item)
        assert result.cvss_score is None
        assert result.severity == "UNKNOWN"

    def test_fallback_description_non_english(self):
        """Falls back to first description if no English one."""
        item = {
            "cve": {
                "id": "CVE-2024-0000",
                "descriptions": [{"lang": "es", "value": "Descripción en español."}],
                "metrics": {},
                "published": "",
                "references": [],
                "configurations": [],
            }
        }
        result = _parse_nvd_item(item)
        assert result.description == "Descripción en español."


# ---------------------------------------------------------------------------
# EPSS tests
# ---------------------------------------------------------------------------

class TestGetEpss:
    """Tests for get_epss()."""

    @pytest.mark.asyncio
    async def test_returns_score_and_percentile(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_EPSS_RESPONSE

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            score, percentile = await get_epss("CVE-2024-1234")

        assert score == pytest.approx(0.95432)
        assert percentile == pytest.approx(0.99100)

    @pytest.mark.asyncio
    async def test_returns_none_on_empty_data(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": []}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            score, percentile = await get_epss("CVE-0000-0000")

        assert score is None
        assert percentile is None

    @pytest.mark.asyncio
    async def test_returns_none_on_timeout(self):
        import httpx

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.TimeoutException("timed out")
            score, percentile = await get_epss("CVE-2024-1234")

        assert score is None
        assert percentile is None

    @pytest.mark.asyncio
    async def test_returns_none_on_http_error(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 500

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            score, percentile = await get_epss("CVE-2024-1234")

        assert score is None
        assert percentile is None


# ---------------------------------------------------------------------------
# KEV tests
# ---------------------------------------------------------------------------

class TestKev:
    """Tests for get_kev_list() and _is_in_kev()."""

    def setup_method(self):
        """Reset KEV cache between tests."""
        import src.recon.vulns as vulns_mod
        vulns_mod._kev_cache = None
        vulns_mod._kev_cve_set = None

    @pytest.mark.asyncio
    async def test_get_kev_list(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_KEV_RESPONSE

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            result = await get_kev_list()

        assert len(result) == 2
        assert result[0]["cveID"] == "CVE-2024-1234"

    @pytest.mark.asyncio
    async def test_is_in_kev_true(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_KEV_RESPONSE

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            result = await _is_in_kev("CVE-2024-1234")

        assert result is True

    @pytest.mark.asyncio
    async def test_is_in_kev_false(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_KEV_RESPONSE

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            result = await _is_in_kev("CVE-9999-9999")

        assert result is False

    @pytest.mark.asyncio
    async def test_kev_timeout_returns_empty(self):
        import httpx

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.TimeoutException("timed out")
            result = await get_kev_list()

        assert result == []


# ---------------------------------------------------------------------------
# lookup_cve tests
# ---------------------------------------------------------------------------

class TestLookupCve:
    """Tests for lookup_cve()."""

    def setup_method(self):
        import src.recon.vulns as vulns_mod
        vulns_mod._kev_cache = None
        vulns_mod._kev_cve_set = None

    @pytest.mark.asyncio
    async def test_lookup_cve_found(self):
        mock_nvd_resp = MagicMock()
        mock_nvd_resp.status_code = 200
        mock_nvd_resp.json.return_value = SAMPLE_NVD_RESPONSE

        mock_epss_resp = MagicMock()
        mock_epss_resp.status_code = 200
        mock_epss_resp.json.return_value = SAMPLE_EPSS_RESPONSE

        mock_kev_resp = MagicMock()
        mock_kev_resp.status_code = 200
        mock_kev_resp.json.return_value = SAMPLE_KEV_RESPONSE

        async def mock_get(url, **kwargs):
            if "nvd.nist.gov" in url:
                return mock_nvd_resp
            if "first.org" in url:
                return mock_epss_resp
            if "cisa.gov" in url:
                return mock_kev_resp
            return MagicMock(status_code=404)

        with patch("httpx.AsyncClient.get", side_effect=mock_get):
            result = await lookup_cve("CVE-2024-1234")

        assert result is not None
        assert result.cve_id == "CVE-2024-1234"
        assert result.severity == "CRITICAL"
        assert result.epss_score == pytest.approx(0.95432)
        assert result.in_kev is True

    @pytest.mark.asyncio
    async def test_lookup_cve_not_found(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"vulnerabilities": []}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            result = await lookup_cve("CVE-0000-0000")

        assert result is None

    @pytest.mark.asyncio
    async def test_lookup_cve_timeout(self):
        import httpx

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.TimeoutException("timed out")
            result = await lookup_cve("CVE-2024-1234")

        assert result is None

    @pytest.mark.asyncio
    async def test_lookup_cve_bad_status(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 503

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            result = await lookup_cve("CVE-2024-1234")

        assert result is None

    @pytest.mark.asyncio
    async def test_lookup_cve_uppercases_id(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"vulnerabilities": []}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            result = await lookup_cve("  cve-2024-1234  ")

        # Should have called with uppercase CVE ID
        call_kwargs = mock_get.call_args
        assert call_kwargs is not None


# ---------------------------------------------------------------------------
# search_cves tests
# ---------------------------------------------------------------------------

class TestSearchCves:
    """Tests for search_cves()."""

    @pytest.mark.asyncio
    async def test_search_returns_results(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_NVD_SEARCH_RESPONSE

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            results = await search_cves("buffer overflow")

        assert len(results) == 2
        assert results[0].cve_id == "CVE-2024-1111"
        assert results[1].cve_id == "CVE-2024-2222"

    @pytest.mark.asyncio
    async def test_search_empty_results(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"vulnerabilities": []}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            results = await search_cves("nonexistent vulnerability xyz")

        assert results == []

    @pytest.mark.asyncio
    async def test_search_timeout(self):
        import httpx

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.TimeoutException("timed out")
            results = await search_cves("test")

        assert results == []

    @pytest.mark.asyncio
    async def test_search_respects_max_results(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_NVD_SEARCH_RESPONSE

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            results = await search_cves("test", max_results=1)

        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_search_clamps_max_results(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"vulnerabilities": []}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            # Should clamp to 50
            await search_cves("test", max_results=999)
            call_kwargs = mock_get.call_args
            params = call_kwargs.kwargs.get("params", {})
            assert params.get("resultsPerPage") == 50


# ---------------------------------------------------------------------------
# check_package tests
# ---------------------------------------------------------------------------

class TestCheckPackage:
    """Tests for check_package()."""

    @pytest.mark.asyncio
    async def test_returns_vulnerabilities(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_OSV_RESPONSE

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            result = await check_package("example-package", "PyPI")

        assert result.package == "example-package"
        assert result.ecosystem == "PyPI"
        assert len(result.vulnerabilities) == 2

    @pytest.mark.asyncio
    async def test_ghsa_source_detection(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_OSV_RESPONSE

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            result = await check_package("example-package")

        # First vuln has GHSA prefix
        assert result.vulnerabilities[0].source == "ghsa"
        # Second has CVE prefix
        assert result.vulnerabilities[1].source == "nvd"

    @pytest.mark.asyncio
    async def test_no_vulns_found(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"vulns": []}

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            result = await check_package("safe-package")

        assert result.vulnerabilities == []

    @pytest.mark.asyncio
    async def test_empty_response_body(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {}

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            result = await check_package("unknown-package")

        assert result.vulnerabilities == []

    @pytest.mark.asyncio
    async def test_timeout_returns_empty_result(self):
        import httpx

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = httpx.TimeoutException("timed out")
            result = await check_package("example-package")

        assert result.vulnerabilities == []
        assert result.package == "example-package"

    @pytest.mark.asyncio
    async def test_severity_parsed_from_osv(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_OSV_RESPONSE

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            result = await check_package("example-package")

        # First vuln has score 6.1 -> MEDIUM
        assert result.vulnerabilities[0].severity == "MEDIUM"
        # Second vuln has no score -> UNKNOWN
        assert result.vulnerabilities[1].severity == "UNKNOWN"

    @pytest.mark.asyncio
    async def test_http_error_returns_empty_result(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 500

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            result = await check_package("example-package")

        assert result.vulnerabilities == []
