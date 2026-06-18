"""Tests for vehicle intelligence — VIN validation, NHTSA decoding, recalls, complaints."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.recon.vehicles import (
    VehicleReport,
    _validate_vin,
    _parse_vin_decode,
    _parse_recalls,
    _generate_search_urls,
    vehicle_lookup,
)


# ---------------------------------------------------------------------------
# Sample API responses
# ---------------------------------------------------------------------------

SAMPLE_VPIC_RESPONSE = {
    "Results": [{
        "Make": "HONDA",
        "Model": "Accord",
        "ModelYear": "2003",
        "Trim": "EX",
        "BodyClass": "Sedan",
        "DisplacementL": "2.4",
        "EngineCylinders": "4",
        "FuelTypePrimary": "Gasoline",
        "DriveType": "FWD",
        "TransmissionStyle": "Automatic",
        "Manufacturer": "HONDA MOTOR CO., LTD",
        "PlantCountry": "UNITED STATES (USA)",
        "AirBagLocFront": "1st Row (Driver and Passenger)",
        "ESC": "Standard",
        "TPMS": "Direct",
    }],
}

# Same data in the Variable/Value format per the user spec
SAMPLE_VPIC_VARIABLE_FORMAT = {
    "Results": [
        {"Variable": "Make", "Value": "HONDA"},
        {"Variable": "Model", "Value": "Accord"},
        {"Variable": "Model Year", "Value": "2003"},
        {"Variable": "Body Class", "Value": "Sedan"},
        {"Variable": "Displacement (L)", "Value": "2.4"},
        {"Variable": "Engine Number of Cylinders", "Value": "4"},
        {"Variable": "Fuel Type - Primary", "Value": "Gasoline"},
        {"Variable": "Drive Type", "Value": "FWD"},
        {"Variable": "Transmission Style", "Value": "Automatic"},
        {"Variable": "Manufacturer Name", "Value": "HONDA MOTOR CO., LTD"},
        {"Variable": "Plant Country", "Value": "UNITED STATES (USA)"},
    ],
}

SAMPLE_RECALLS_RESPONSE = {
    "results": [
        {
            "NHTSACampaignNumber": "03V123000",
            "Component": "AIR BAGS",
            "Summary": "Certain passenger vehicles have a defective air bag inflator.",
            "Consequence": "The inflator may rupture during deployment.",
            "Remedy": "Dealers will replace the air bag inflator.",
            "ReportReceivedDate": "06/15/2003",
        },
        {
            "NHTSACampaignNumber": "04V456000",
            "Component": "ELECTRICAL SYSTEM",
            "Summary": "The battery cable terminal may corrode.",
            "Consequence": "Could cause the vehicle to stall.",
            "Remedy": "Dealers will replace the battery cable.",
            "ReportReceivedDate": "02/20/2004",
        },
    ],
}

SAMPLE_COMPLAINTS_RESPONSE = {
    "results": [
        {"odiNumber": "1001", "components": "BRAKES"},
        {"odiNumber": "1002", "components": "STEERING"},
        {"odiNumber": "1003", "components": "ENGINE"},
    ],
}


# ---------------------------------------------------------------------------
# VIN validation tests
# ---------------------------------------------------------------------------


class TestValidateVin:
    """Tests for _validate_vin()."""

    def test_valid_vin_17_chars(self):
        # Real Honda Accord VIN structure — 17 alphanumeric chars, no I/O/Q
        vin = "1HGCG5655WA014428"
        result = _validate_vin(vin)
        assert result is None  # None means valid

    def test_too_short(self):
        result = _validate_vin("1HGCG5655WA01")
        assert result is not None
        assert "17 characters" in result

    def test_too_long(self):
        result = _validate_vin("1HGCG5655WA014428X")
        assert result is not None
        assert "17 characters" in result

    def test_invalid_char_I(self):
        vin = "1HGCG5655IA014428"  # 'I' is invalid
        result = _validate_vin(vin)
        assert result is not None
        assert "invalid character" in result.lower()
        assert "I" in result

    def test_invalid_char_O(self):
        vin = "1HGCG5655OA014428"  # 'O' is invalid
        result = _validate_vin(vin)
        assert result is not None
        assert "O" in result

    def test_invalid_char_Q(self):
        vin = "1HGCG5655QA014428"  # 'Q' is invalid
        result = _validate_vin(vin)
        assert result is not None
        assert "Q" in result

    def test_empty_string(self):
        result = _validate_vin("")
        assert result is not None
        assert "17 characters" in result

    def test_strips_whitespace(self):
        vin = "  1HGCG5655WA014428  "
        result = _validate_vin(vin)
        assert result is None

    def test_case_insensitive(self):
        vin = "1hgcg5655wa014428"
        result = _validate_vin(vin)
        assert result is None

    def test_all_digits_valid(self):
        vin = "12345678901234567"
        result = _validate_vin(vin)
        assert result is None  # All digits are valid VIN chars


# ---------------------------------------------------------------------------
# vPIC response parsing tests
# ---------------------------------------------------------------------------


class TestParseVinDecode:
    """Tests for _parse_vin_decode()."""

    def test_parses_make_model_year(self):
        report = VehicleReport(vin="1HGCG5655WA014428")
        _parse_vin_decode(SAMPLE_VPIC_RESPONSE, report)
        assert report.make == "HONDA"
        assert report.model == "Accord"
        assert report.year == "2003"

    def test_parses_body_and_drivetrain(self):
        report = VehicleReport(vin="1HGCG5655WA014428")
        _parse_vin_decode(SAMPLE_VPIC_RESPONSE, report)
        assert report.body_type == "Sedan"
        assert report.drive_type == "FWD"
        assert report.transmission == "Automatic"

    def test_parses_engine(self):
        report = VehicleReport(vin="1HGCG5655WA014428")
        _parse_vin_decode(SAMPLE_VPIC_RESPONSE, report)
        assert report.engine["displacement"] == "2.4"
        assert report.engine["cylinders"] == "4"
        assert report.engine["fuel_type"] == "Gasoline"

    def test_parses_manufacturer(self):
        report = VehicleReport(vin="1HGCG5655WA014428")
        _parse_vin_decode(SAMPLE_VPIC_RESPONSE, report)
        assert report.manufacturer["name"] == "HONDA MOTOR CO., LTD"
        assert report.manufacturer["country"] == "UNITED STATES (USA)"

    def test_parses_safety_features(self):
        report = VehicleReport(vin="1HGCG5655WA014428")
        _parse_vin_decode(SAMPLE_VPIC_RESPONSE, report)
        # Should contain AirBagLocFront, ESC, TPMS
        safety_names = [s.split(":")[0] for s in report.safety_features]
        assert "AirBagLocFront" in safety_names
        assert "ESC" in safety_names
        assert "TPMS" in safety_names

    def test_empty_results(self):
        report = VehicleReport(vin="TEST")
        _parse_vin_decode({"Results": []}, report)
        assert report.make == ""
        assert report.model == ""
        assert report.year == ""

    def test_missing_results_key(self):
        report = VehicleReport(vin="TEST")
        _parse_vin_decode({}, report)
        assert report.make == ""

    def test_none_values_become_empty_string(self):
        """Null values from API should be converted to empty strings."""
        report = VehicleReport(vin="TEST")
        _parse_vin_decode({"Results": [{"Make": None, "Model": None}]}, report)
        assert report.make == ""
        assert report.model == ""

    def test_safety_excludes_not_applicable(self):
        """Safety features with value 'Not Applicable' should be excluded."""
        report = VehicleReport(vin="TEST")
        data = {"Results": [{"AirBagLocFront": "Not Applicable", "ESC": "Standard"}]}
        _parse_vin_decode(data, report)
        safety_names = [s.split(":")[0] for s in report.safety_features]
        assert "AirBagLocFront" not in safety_names
        assert "ESC" in safety_names


# ---------------------------------------------------------------------------
# Recall parsing tests
# ---------------------------------------------------------------------------


class TestParseRecalls:
    """Tests for _parse_recalls()."""

    def test_parses_recall_records(self):
        recalls = _parse_recalls(SAMPLE_RECALLS_RESPONSE)
        assert len(recalls) == 2

    def test_recall_fields(self):
        recalls = _parse_recalls(SAMPLE_RECALLS_RESPONSE)
        first = recalls[0]
        assert first["campaign_number"] == "03V123000"
        assert first["component"] == "AIR BAGS"
        assert "defective air bag" in first["summary"]
        assert first["report_date"] == "06/15/2003"

    def test_empty_results(self):
        recalls = _parse_recalls({"results": []})
        assert recalls == []

    def test_missing_results_key(self):
        recalls = _parse_recalls({})
        assert recalls == []


# ---------------------------------------------------------------------------
# Search URL generation tests
# ---------------------------------------------------------------------------


class TestSearchUrlGeneration:
    """Tests for _generate_search_urls()."""

    def test_generates_vehicle_history_category(self):
        report = VehicleReport(vin="1HGCG5655WA014428", make="HONDA",
                               model="Accord", year="2003")
        urls = _generate_search_urls(report)
        assert "vehicle_history" in urls
        assert len(urls["vehicle_history"]) >= 3

    def test_generates_nhtsa_category(self):
        report = VehicleReport(vin="1HGCG5655WA014428", make="HONDA",
                               model="Accord", year="2003")
        urls = _generate_search_urls(report)
        assert "nhtsa" in urls
        assert len(urls["nhtsa"]) >= 2

    def test_vin_in_urls(self):
        report = VehicleReport(vin="1HGCG5655WA014428", make="HONDA",
                               model="Accord", year="2003")
        urls = _generate_search_urls(report)
        for entry in urls["vehicle_history"]:
            assert "1HGCG5655WA014428" in entry["url"]

    def test_expected_sites(self):
        report = VehicleReport(vin="1HGCG5655WA014428", make="HONDA",
                               model="Accord", year="2003")
        urls = _generate_search_urls(report)
        site_names = {e["name"] for e in urls["vehicle_history"]}
        assert "Carfax" in site_names
        assert "AutoCheck" in site_names

    def test_each_url_has_name_and_url(self):
        report = VehicleReport(vin="1HGCG5655WA014428", make="HONDA",
                               model="Accord", year="2003")
        urls = _generate_search_urls(report)
        for category_urls in urls.values():
            for entry in category_urls:
                assert "name" in entry
                assert "url" in entry
                assert entry["url"].startswith("http")


# ---------------------------------------------------------------------------
# Complaint count tests
# ---------------------------------------------------------------------------


class TestComplaintCount:
    """Tests for complaint count handling in vehicle_lookup."""

    def test_complaint_count_from_results(self):
        """Complaint count is len(results)."""
        data = SAMPLE_COMPLAINTS_RESPONSE
        results = data.get("results", [])
        assert len(results) == 3

    def test_report_default_complaint_count(self):
        report = VehicleReport(vin="TEST")
        assert report.complaint_count == 0


# ---------------------------------------------------------------------------
# Full vehicle_lookup integration test (all APIs mocked)
# ---------------------------------------------------------------------------


class TestVehicleLookup:
    """Tests for vehicle_lookup() with mocked HTTP."""

    @pytest.mark.asyncio
    async def test_invalid_vin_returns_error(self):
        report = await vehicle_lookup("SHORT")
        assert report.error is not None
        assert "17 characters" in report.error

    @pytest.mark.asyncio
    async def test_invalid_char_vin_returns_error(self):
        report = await vehicle_lookup("1HGCG5655IA014428")  # 'I' invalid
        assert report.error is not None
        assert "invalid character" in report.error.lower()

    @pytest.mark.asyncio
    async def test_full_lookup_success(self):
        """Full decode + recalls + complaints with mocked APIs."""
        mock_decode_resp = MagicMock()
        mock_decode_resp.status_code = 200
        mock_decode_resp.json.return_value = SAMPLE_VPIC_RESPONSE

        mock_recalls_resp = MagicMock()
        mock_recalls_resp.status_code = 200
        mock_recalls_resp.json.return_value = SAMPLE_RECALLS_RESPONSE

        mock_complaints_resp = MagicMock()
        mock_complaints_resp.status_code = 200
        mock_complaints_resp.json.return_value = SAMPLE_COMPLAINTS_RESPONSE

        async def mock_get(url, **kwargs):
            if "DecodeVinValues" in url:
                return mock_decode_resp
            if "recallsByVehicle" in url:
                return mock_recalls_resp
            if "complaintsByVehicle" in url:
                return mock_complaints_resp
            return MagicMock(status_code=404)

        with patch("httpx.AsyncClient.get", side_effect=mock_get):
            report = await vehicle_lookup("1HGCG5655WA014428")

        assert report.error is None
        assert report.make == "HONDA"
        assert report.model == "Accord"
        assert report.year == "2003"
        assert len(report.recalls) == 2
        assert report.complaint_count == 3
        assert "vehicle_history" in report.search_urls

    @pytest.mark.asyncio
    async def test_decode_timeout(self):
        """VIN decode timeout should set error and return early."""
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.TimeoutException("timed out")
            report = await vehicle_lookup("1HGCG5655WA014428")

        assert report.error is not None
        assert "failed" in report.error.lower()

    @pytest.mark.asyncio
    async def test_decode_http_error(self):
        """VIN decode HTTP error should set error."""
        mock_resp = MagicMock()
        mock_resp.status_code = 500

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            report = await vehicle_lookup("1HGCG5655WA014428")

        assert report.error is not None
        assert "HTTP 500" in report.error

    @pytest.mark.asyncio
    async def test_recalls_timeout_graceful(self):
        """Recall/complaint timeout should not crash — just skip."""
        mock_decode_resp = MagicMock()
        mock_decode_resp.status_code = 200
        mock_decode_resp.json.return_value = SAMPLE_VPIC_RESPONSE

        call_count = 0

        async def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if "DecodeVinValues" in url:
                return mock_decode_resp
            # Recalls and complaints time out
            raise httpx.TimeoutException("timed out")

        with patch("httpx.AsyncClient.get", side_effect=mock_get):
            report = await vehicle_lookup("1HGCG5655WA014428")

        # Decode should succeed, recalls/complaints fail gracefully
        assert report.error is None
        assert report.make == "HONDA"
        assert report.recalls == []
        assert report.complaint_count == 0

    @pytest.mark.asyncio
    async def test_vin_uppercased(self):
        """VIN should be uppercased."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"Results": [{"Make": "TEST"}]}

        mock_empty = MagicMock()
        mock_empty.status_code = 200
        mock_empty.json.return_value = {"results": []}

        async def mock_get(url, **kwargs):
            if "DecodeVinValues" in url:
                assert "1HGCG5655WA014428" in url  # uppercased
                return mock_resp
            return mock_empty

        with patch("httpx.AsyncClient.get", side_effect=mock_get):
            report = await vehicle_lookup("1hgcg5655wa014428")

        assert report.vin == "1HGCG5655WA014428"

    @pytest.mark.asyncio
    async def test_report_dataclass_defaults(self):
        """Verify VehicleReport default field values."""
        report = VehicleReport(vin="TEST")
        assert report.make == ""
        assert report.model == ""
        assert report.year == ""
        assert report.engine == {}
        assert report.recalls == []
        assert report.complaint_count == 0
        assert report.search_urls == {}
        assert report.error is None
