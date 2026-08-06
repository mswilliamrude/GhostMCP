"""Tests for phone number intelligence — validation, formatting, carrier, CNAM, search URLs."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ghostmcp.recon.phone import (
    PhoneReport,
    _offline_analysis,
    _query_veriphone,
    _query_twilio_cnam,
    _query_opencnam,
    _generate_search_urls,
    phone_lookup,
    _HAS_PHONENUMBERS,
)


# ---------------------------------------------------------------------------
# Sample API responses
# ---------------------------------------------------------------------------

SAMPLE_VERIPHONE_RESPONSE = {
    "phone_valid": True,
    "phone_type": "mobile",
    "phone_region": "Texas",
    "country": "United States",
    "country_code": "+1",
    "international_number": "+1 214-555-1234",
    "local_number": "(214) 555-1234",
    "carrier": "T-Mobile USA",
}

SAMPLE_TWILIO_CNAM_RESPONSE = {
    "caller_name": {
        "caller_name": "JOHN DOE",
        "caller_type": "CONSUMER",
        "error_code": None,
    },
    "phone_number": "+12145551234",
}

SAMPLE_OPENCNAM_RESPONSE = {
    "name": "JANE SMITH",
    "number": "+12145551234",
    "price": 0.004,
}


# ---------------------------------------------------------------------------
# Offline analysis tests (phonenumbers library)
# ---------------------------------------------------------------------------


class TestOfflineAnalysis:
    """Tests for _offline_analysis() — pure offline parsing."""

    @pytest.mark.skipif(not _HAS_PHONENUMBERS, reason="phonenumbers not installed")
    def test_valid_us_number(self):
        report = _offline_analysis("+12145551234", "US")
        assert report.valid is True
        assert report.country_code == "1"
        assert report.country == "US"

    @pytest.mark.skipif(not _HAS_PHONENUMBERS, reason="phonenumbers not installed")
    def test_invalid_number(self):
        report = _offline_analysis("+1999", "US")
        assert report.valid is False

    @pytest.mark.skipif(not _HAS_PHONENUMBERS, reason="phonenumbers not installed")
    def test_formatting_output(self):
        report = _offline_analysis("+12145551234", "US")
        assert "e164" in report.formatted
        assert "national" in report.formatted
        assert "international" in report.formatted
        assert report.formatted["e164"] == "+12145551234"

    @pytest.mark.skipif(not _HAS_PHONENUMBERS, reason="phonenumbers not installed")
    def test_carrier_type_detection(self):
        # +12145551234 is a valid US number — carrier_type should be a known value
        report = _offline_analysis("+12145551234", "US")
        assert report.carrier_type in ("mobile", "landline", "voip", "unknown")

    @pytest.mark.skipif(not _HAS_PHONENUMBERS, reason="phonenumbers not installed")
    def test_timezone_populated(self):
        report = _offline_analysis("+12145551234", "US")
        # Dallas, TX is in America/Chicago
        assert report.timezone != ""

    @pytest.mark.skipif(not _HAS_PHONENUMBERS, reason="phonenumbers not installed")
    def test_unparseable_garbage(self):
        report = _offline_analysis("not-a-number-at-all", "US")
        assert report.valid is False
        assert report.error is not None
        assert "Parse error" in report.error

    def test_graceful_degradation_no_phonenumbers(self):
        """When phonenumbers is not installed, _offline_analysis returns an error."""
        with patch("ghostmcp.recon.phone._HAS_PHONENUMBERS", False):
            report = _offline_analysis("+12145551234", "US")
            assert report.error is not None
            assert "phonenumbers library not installed" in report.error


# ---------------------------------------------------------------------------
# Mocked phonenumbers tests (always run, no library dependency)
# ---------------------------------------------------------------------------


class TestOfflineAnalysisMocked:
    """Tests using mocked phonenumbers — always run regardless of install state."""

    def test_valid_number_with_mock(self):
        mock_parsed = MagicMock()
        mock_parsed.country_code = 1

        with patch("ghostmcp.recon.phone._HAS_PHONENUMBERS", True), \
             patch("ghostmcp.recon.phone.phonenumbers", create=True) as mock_pn, \
             patch("ghostmcp.recon.phone.pn_carrier", create=True) as mock_carrier, \
             patch("ghostmcp.recon.phone.pn_geocoder", create=True) as mock_geo, \
             patch("ghostmcp.recon.phone.pn_timezone", create=True) as mock_tz:

            mock_pn.parse.return_value = mock_parsed
            mock_pn.is_valid_number.return_value = True
            mock_pn.format_number.side_effect = [
                "+12145551234",   # E164
                "(214) 555-1234", # NATIONAL
                "+1 214-555-1234", # INTERNATIONAL
            ]
            mock_pn.PhoneNumberFormat.E164 = 0
            mock_pn.PhoneNumberFormat.NATIONAL = 2
            mock_pn.PhoneNumberFormat.INTERNATIONAL = 1
            mock_pn.region_code_for_number.return_value = "US"
            mock_pn.number_type.return_value = 0
            mock_pn.PhoneNumberType.MOBILE = 0
            mock_pn.PhoneNumberType.FIXED_LINE = 1
            mock_pn.PhoneNumberType.FIXED_LINE_OR_MOBILE = 2
            mock_pn.PhoneNumberType.VOIP = 6
            mock_pn.PhoneNumberType.TOLL_FREE = 4
            mock_pn.PhoneNumberType.PREMIUM_RATE = 5
            mock_pn.PhoneNumberType.PAGER = 7

            mock_carrier.name_for_number.return_value = "T-Mobile"
            mock_geo.description_for_number.return_value = "Dallas, TX"
            mock_tz.time_zones_for_number.return_value = ["America/Chicago"]

            report = _offline_analysis("+12145551234", "US")

        assert report.valid is True
        assert report.formatted["e164"] == "+12145551234"
        assert report.carrier_name == "T-Mobile"
        assert report.carrier_type == "mobile"
        assert report.region == "Dallas, TX"
        assert report.timezone == "America/Chicago"

    def test_parse_exception_with_mock(self):
        with patch("ghostmcp.recon.phone._HAS_PHONENUMBERS", True), \
             patch("ghostmcp.recon.phone.phonenumbers", create=True) as mock_pn:

            mock_pn.NumberParseException = type("NumberParseException", (Exception,), {})
            mock_pn.parse.side_effect = mock_pn.NumberParseException("bad number")

            report = _offline_analysis("garbage", "US")

        assert report.valid is False
        assert report.error is not None
        assert "Parse error" in report.error


# ---------------------------------------------------------------------------
# Veriphone API tests
# ---------------------------------------------------------------------------


class TestQueryVeriphone:
    """Tests for _query_veriphone() with mocked HTTP."""

    @pytest.mark.asyncio
    async def test_veriphone_success(self):
        report = PhoneReport(number="+12145551234")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_VERIPHONE_RESPONSE

        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch.dict(os.environ, {"GHOST_VERIPHONE_KEY": "test-key"}):
            await _query_veriphone(mock_client, "+12145551234", report)

        assert report.veriphone is not None
        assert report.veriphone["phone_valid"] is True
        assert report.veriphone["carrier"] == "T-Mobile USA"

    @pytest.mark.asyncio
    async def test_veriphone_no_key_skips(self):
        report = PhoneReport(number="+12145551234")
        mock_client = MagicMock()
        mock_client.get = AsyncMock()

        with patch.dict(os.environ, {}, clear=True):
            # Remove the key if set
            os.environ.pop("GHOST_VERIPHONE_KEY", None)
            await _query_veriphone(mock_client, "+12145551234", report)

        assert report.veriphone is None
        mock_client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_veriphone_http_error(self):
        report = PhoneReport(number="+12145551234")
        mock_resp = MagicMock()
        mock_resp.status_code = 429

        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch.dict(os.environ, {"GHOST_VERIPHONE_KEY": "test-key"}):
            await _query_veriphone(mock_client, "+12145551234", report)

        assert report.veriphone == {"error": "HTTP 429"}

    @pytest.mark.asyncio
    async def test_veriphone_timeout(self):
        import httpx

        report = PhoneReport(number="+12145551234")
        mock_client = MagicMock()
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timed out"))

        with patch.dict(os.environ, {"GHOST_VERIPHONE_KEY": "test-key"}):
            await _query_veriphone(mock_client, "+12145551234", report)

        assert report.veriphone is not None
        assert "error" in report.veriphone

    @pytest.mark.asyncio
    async def test_veriphone_supplements_carrier(self):
        """Veriphone carrier fills in if offline carrier was empty."""
        report = PhoneReport(number="+12145551234", carrier_name="", carrier_type="unknown")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_VERIPHONE_RESPONSE

        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch.dict(os.environ, {"GHOST_VERIPHONE_KEY": "test-key"}):
            await _query_veriphone(mock_client, "+12145551234", report)

        assert report.carrier_name == "T-Mobile USA"
        assert report.carrier_type == "mobile"


# ---------------------------------------------------------------------------
# Twilio CNAM tests
# ---------------------------------------------------------------------------


class TestQueryTwilioCnam:
    """Tests for _query_twilio_cnam() with mocked HTTP."""

    @pytest.mark.asyncio
    async def test_twilio_cnam_success(self):
        report = PhoneReport(number="+12145551234")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_TWILIO_CNAM_RESPONSE

        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch.dict(os.environ, {
            "GHOST_TWILIO_SID": "ACtest",
            "GHOST_TWILIO_TOKEN": "testtoken",
        }):
            await _query_twilio_cnam(mock_client, "+12145551234", report)

        assert report.cnam_name == "JOHN DOE"

    @pytest.mark.asyncio
    async def test_twilio_no_credentials_skips(self):
        report = PhoneReport(number="+12145551234")
        mock_client = MagicMock()
        mock_client.get = AsyncMock()

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GHOST_TWILIO_SID", None)
            os.environ.pop("GHOST_TWILIO_TOKEN", None)
            await _query_twilio_cnam(mock_client, "+12145551234", report)

        assert report.cnam_name is None
        mock_client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_twilio_timeout_graceful(self):
        import httpx

        report = PhoneReport(number="+12145551234")
        mock_client = MagicMock()
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timed out"))

        with patch.dict(os.environ, {
            "GHOST_TWILIO_SID": "ACtest",
            "GHOST_TWILIO_TOKEN": "testtoken",
        }):
            await _query_twilio_cnam(mock_client, "+12145551234", report)

        # Should not raise — graceful degradation
        assert report.cnam_name is None


# ---------------------------------------------------------------------------
# OpenCNAM tests
# ---------------------------------------------------------------------------


class TestQueryOpenCnam:
    """Tests for _query_opencnam() with mocked HTTP."""

    @pytest.mark.asyncio
    async def test_opencnam_success(self):
        report = PhoneReport(number="+12145551234")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_OPENCNAM_RESPONSE

        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch.dict(os.environ, {
            "GHOST_OPENCNAM_SID": "test-sid",
            "GHOST_OPENCNAM_TOKEN": "test-token",
        }):
            await _query_opencnam(mock_client, "+12145551234", report)

        assert report.cnam_name == "JANE SMITH"

    @pytest.mark.asyncio
    async def test_opencnam_skips_when_twilio_resolved(self):
        """OpenCNAM is skipped if CNAM was already resolved by Twilio."""
        report = PhoneReport(number="+12145551234", cnam_name="ALREADY SET")
        mock_client = MagicMock()
        mock_client.get = AsyncMock()

        with patch.dict(os.environ, {
            "GHOST_OPENCNAM_SID": "test-sid",
            "GHOST_OPENCNAM_TOKEN": "test-token",
        }):
            await _query_opencnam(mock_client, "+12145551234", report)

        assert report.cnam_name == "ALREADY SET"
        mock_client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_opencnam_unavailable_ignored(self):
        """Name 'unavailable' should not be set as CNAM."""
        report = PhoneReport(number="+12145551234")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"name": "Unavailable", "number": "+12145551234"}

        mock_client = MagicMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch.dict(os.environ, {
            "GHOST_OPENCNAM_SID": "test-sid",
            "GHOST_OPENCNAM_TOKEN": "test-token",
        }):
            await _query_opencnam(mock_client, "+12145551234", report)

        assert report.cnam_name is None

    @pytest.mark.asyncio
    async def test_opencnam_no_credentials_skips(self):
        report = PhoneReport(number="+12145551234")
        mock_client = MagicMock()
        mock_client.get = AsyncMock()

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GHOST_OPENCNAM_SID", None)
            os.environ.pop("GHOST_OPENCNAM_TOKEN", None)
            await _query_opencnam(mock_client, "+12145551234", report)

        assert report.cnam_name is None
        mock_client.get.assert_not_called()


# ---------------------------------------------------------------------------
# Search URL generation tests
# ---------------------------------------------------------------------------


class TestSearchUrlGeneration:
    """Tests for _generate_search_urls()."""

    def test_generates_reverse_phone_category(self):
        report = PhoneReport(
            number="+12145551234",
            formatted={"e164": "+12145551234", "national": "(214) 555-1234"},
        )
        urls = _generate_search_urls(report)
        assert "reverse_phone" in urls
        assert len(urls["reverse_phone"]) >= 5

    def test_url_contains_digits(self):
        report = PhoneReport(
            number="+12145551234",
            formatted={"e164": "+12145551234", "national": "(214) 555-1234"},
        )
        urls = _generate_search_urls(report)
        for entry in urls["reverse_phone"]:
            # Digits should appear somewhere in the URL
            assert "12145551234" in entry["url"] or "214" in entry["url"]

    def test_each_url_has_name_and_url(self):
        report = PhoneReport(
            number="+12145551234",
            formatted={"e164": "+12145551234", "national": "(214) 555-1234"},
        )
        urls = _generate_search_urls(report)
        for entry in urls["reverse_phone"]:
            assert "name" in entry
            assert "url" in entry
            assert entry["url"].startswith("http")

    def test_fallback_to_raw_number(self):
        """When formatted is empty, falls back to raw number."""
        report = PhoneReport(number="2145551234", formatted={})
        urls = _generate_search_urls(report)
        assert "reverse_phone" in urls
        assert len(urls["reverse_phone"]) >= 1

    def test_expected_sites_present(self):
        report = PhoneReport(
            number="+12145551234",
            formatted={"e164": "+12145551234", "national": "(214) 555-1234"},
        )
        urls = _generate_search_urls(report)
        site_names = {e["name"] for e in urls["reverse_phone"]}
        assert "USPhonebook" in site_names
        assert "ThatsThem" in site_names
        assert "Spokeo" in site_names


# ---------------------------------------------------------------------------
# Full phone_lookup integration test (all APIs mocked)
# ---------------------------------------------------------------------------


class TestPhoneLookup:
    """Tests for the full phone_lookup() async entry point."""

    @pytest.mark.asyncio
    async def test_full_lookup_with_mocked_apis(self):
        """End-to-end test with all external calls mocked."""
        mock_veriphone_resp = MagicMock()
        mock_veriphone_resp.status_code = 200
        mock_veriphone_resp.json.return_value = SAMPLE_VERIPHONE_RESPONSE

        mock_twilio_resp = MagicMock()
        mock_twilio_resp.status_code = 200
        mock_twilio_resp.json.return_value = SAMPLE_TWILIO_CNAM_RESPONSE

        mock_opencnam_resp = MagicMock()
        mock_opencnam_resp.status_code = 200
        mock_opencnam_resp.json.return_value = SAMPLE_OPENCNAM_RESPONSE

        async def mock_get(url, **kwargs):
            if "lookups.twilio.com" in url:
                return mock_twilio_resp
            if "opencnam" in url:
                return mock_opencnam_resp
            if "veriphone" in url:
                return mock_veriphone_resp
            return MagicMock(status_code=404)

        with patch("httpx.AsyncClient.get", side_effect=mock_get), \
             patch.dict(os.environ, {
                 "GHOST_VERIPHONE_KEY": "test-key",
                 "GHOST_TWILIO_SID": "ACtest",
                 "GHOST_TWILIO_TOKEN": "testtoken",
                 "GHOST_OPENCNAM_SID": "test-sid",
                 "GHOST_OPENCNAM_TOKEN": "test-token",
             }):
            report = await phone_lookup("+12145551234")

        assert isinstance(report, PhoneReport)
        assert report.number == "+12145551234"
        assert report.search_urls is not None
        assert "reverse_phone" in report.search_urls

        # Veriphone should have been populated
        assert report.veriphone is not None

        # CNAM should come from Twilio (runs first in gather)
        assert report.cnam_name == "JOHN DOE"

    @pytest.mark.asyncio
    async def test_lookup_no_api_keys(self):
        """Lookup without any API keys — only offline + URLs."""
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get, \
             patch.dict(os.environ, {}, clear=True):
            # Strip all API keys
            for key in ["GHOST_VERIPHONE_KEY", "GHOST_TWILIO_SID",
                        "GHOST_TWILIO_TOKEN", "GHOST_OPENCNAM_SID",
                        "GHOST_OPENCNAM_TOKEN"]:
                os.environ.pop(key, None)

            report = await phone_lookup("+12145551234")

        assert isinstance(report, PhoneReport)
        assert report.veriphone is None
        assert report.cnam_name is None
        assert "reverse_phone" in report.search_urls

    @pytest.mark.asyncio
    async def test_phone_report_dataclass_defaults(self):
        """Verify PhoneReport default field values."""
        report = PhoneReport(number="test")
        assert report.valid is None
        assert report.carrier_type == "unknown"
        assert report.carrier_name == ""
        assert report.formatted == {}
        assert report.search_urls == {}
        assert report.error is None
        assert report.cnam_name is None
