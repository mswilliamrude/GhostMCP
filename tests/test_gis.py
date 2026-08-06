"""Tests for GIS property/parcel lookup module."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ghostmcp.recon.gis import (
    GISResult,
    GISError,
    gis_lookup,
    geocode_address,
    reverse_geocode,
    regrid_lookup,
    state_gis_lookup,
    arcgis_query,
    _detect_owner_type,
    _generate_search_urls,
    STATE_ENDPOINTS,
)


# ---------------------------------------------------------------------------
# Sample API responses
# ---------------------------------------------------------------------------

SAMPLE_NOMINATIM_RESPONSE = [
    {
        "lat": "30.2672",
        "lon": "-97.7431",
        "display_name": "Austin, Travis County, Texas, USA",
        "address": {
            "city": "Austin",
            "county": "Travis County",
            "state": "Texas",
            "country": "United States",
        },
    }
]

SAMPLE_NOMINATIM_REVERSE = {
    "lat": "30.2672",
    "lon": "-97.7431",
    "display_name": "123 Main St, Austin, TX 78701",
    "address": {
        "house_number": "123",
        "road": "Main Street",
        "city": "Austin",
        "state": "Texas",
        "postcode": "78701",
    },
}

SAMPLE_REGRID_RESPONSE = {
    "results": [
        {
            "ll_uuid": "abc123-def456",
            "properties": {
                "parcel_id": "123-456-789",
                "address": "123 MAIN ST",
                "city": "AUSTIN",
                "state2": "TX",
                "zip": "78701",
                "county": "Travis",
                "lat": 30.2672,
                "lon": -97.7431,
                "owner": "DOE, JOHN",
                "mail_address": "PO BOX 456",
                "mail_city": "AUSTIN",
                "mail_state2": "TX",
                "mail_zip": "78702",
                "acreage": 0.25,
                "zoning": "SF-3",
                "land_use_code": "A1",
                "land_value": 150000,
                "improvement_value": 350000,
                "total_value": 500000,
                "year_built": 1985,
                "building_sq_ft": 2200,
                "bedrooms": 3,
                "bathrooms": 2.5,
            },
        }
    ]
}

SAMPLE_ARCGIS_RESPONSE = {
    "features": [
        {
            "attributes": {
                "PARCEL_ID": "TX-12345",
                "prop_id": "TX-12345",
                "situs_num": "123",
                "situs_street": "MAIN ST",
                "situs_city": "AUSTIN",
                "owner": "SMITH, JANE",
                "acres": 0.5,
                "legal_desc": "LOT 1 BLK 2 SUBDIVISION",
            },
            "geometry": {
                "rings": [[[-97.74, 30.26], [-97.74, 30.27], [-97.73, 30.27], [-97.73, 30.26], [-97.74, 30.26]]]
            },
        }
    ]
}

EMPTY_REGRID_RESPONSE = {"results": []}

EMPTY_ARCGIS_RESPONSE = {"features": []}


# ---------------------------------------------------------------------------
# Owner type detection tests
# ---------------------------------------------------------------------------

class TestOwnerTypeDetection:

    def test_detect_individual(self):
        assert _detect_owner_type("DOE, JOHN") == "individual"
        assert _detect_owner_type("Smith Jane") == "individual"
        assert _detect_owner_type("JOHNSON ROBERT M") == "individual"

    def test_detect_llc(self):
        assert _detect_owner_type("ACME PROPERTIES LLC") == "llc"
        assert _detect_owner_type("XYZ Holdings L.L.C.") == "llc"
        assert _detect_owner_type("Smith Family Limited Liability") == "llc"

    def test_detect_corporation(self):
        assert _detect_owner_type("ACME INC") == "corporation"
        assert _detect_owner_type("XYZ Corporation") == "corporation"
        assert _detect_owner_type("Smith & Co.") == "corporation"
        assert _detect_owner_type("ABC COMPANY") == "corporation"

    def test_detect_trust(self):
        assert _detect_owner_type("SMITH FAMILY TRUST") == "trust"
        assert _detect_owner_type("John Doe TR") == "trust"
        assert _detect_owner_type("Jane Smith Trustee") == "trust"
        assert _detect_owner_type("DOE LIVING TRUST") == "trust"

    def test_detect_partnership(self):
        assert _detect_owner_type("ACME LP") == "partnership"
        assert _detect_owner_type("Smith Holdings L.P.") == "partnership"
        assert _detect_owner_type("XYZ Limited Partnership") == "partnership"

    def test_detect_financial(self):
        assert _detect_owner_type("FIRST NATIONAL BANK") == "financial"
        assert _detect_owner_type("XYZ CREDIT UNION") == "financial"
        assert _detect_owner_type("ABC MORTGAGE COMPANY") == "financial"

    def test_detect_government(self):
        assert _detect_owner_type("CITY OF AUSTIN") == "government"
        assert _detect_owner_type("COUNTY OF TRAVIS") == "government"
        assert _detect_owner_type("STATE OF TEXAS") == "government"
        assert _detect_owner_type("UNITED STATES OF AMERICA") == "government"

    def test_detect_empty(self):
        assert _detect_owner_type("") == "unknown"
        assert _detect_owner_type(None) == "unknown"


# ---------------------------------------------------------------------------
# Search URL generation tests
# ---------------------------------------------------------------------------

class TestSearchUrlGeneration:

    def test_generates_county_assessor_url(self):
        result = GISResult(
            parcel_id="123",
            county="Travis",
            state="TX",
        )
        urls = _generate_search_urls(result)
        assert "county_assessor" in urls
        assert "Travis" in urls["county_assessor"]

    def test_generates_people_search_urls_for_individual(self):
        result = GISResult(
            owner_name="DOE, JOHN",
            owner_type="individual",
            state="TX",
        )
        urls = _generate_search_urls(result)
        assert "truepeoplesearch" in urls
        assert "fastpeoplesearch" in urls
        assert "whitepages" in urls

    def test_generates_business_search_urls_for_llc(self):
        result = GISResult(
            owner_name="ACME PROPERTIES LLC",
            owner_type="llc",
            state="TX",
        )
        urls = _generate_search_urls(result)
        assert "opencorporates" in urls
        assert "sec_edgar" in urls

    def test_generates_property_urls(self):
        result = GISResult(
            address="123 Main St",
            city="Austin",
            state="TX",
        )
        urls = _generate_search_urls(result)
        assert "zillow" in urls
        assert "redfin" in urls

    def test_generates_map_urls_with_coordinates(self):
        result = GISResult(
            coordinates=(30.2672, -97.7431),
        )
        urls = _generate_search_urls(result)
        assert "google_maps" in urls
        assert "regrid" in urls
        assert "30.2672" in urls["google_maps"]


# ---------------------------------------------------------------------------
# Geocoding tests
# ---------------------------------------------------------------------------

class TestGeocoding:

    @pytest.mark.asyncio
    async def test_geocode_address_success(self, mock_httpx_response):
        mock_resp = mock_httpx_response(status_code=200, json_data=SAMPLE_NOMINATIM_RESPONSE)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            lat, lon = await geocode_address("123 Main St, Austin, TX")

        assert lat == pytest.approx(30.2672, abs=0.001)
        assert lon == pytest.approx(-97.7431, abs=0.001)

    @pytest.mark.asyncio
    async def test_geocode_address_not_found(self, mock_httpx_response):
        mock_resp = mock_httpx_response(status_code=200, json_data=[])

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            with pytest.raises(GISError) as exc:
                await geocode_address("xyzzy nonexistent address")

        assert "Could not geocode" in str(exc.value)

    @pytest.mark.asyncio
    async def test_reverse_geocode_success(self, mock_httpx_response):
        mock_resp = mock_httpx_response(status_code=200, json_data=SAMPLE_NOMINATIM_REVERSE)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await reverse_geocode(30.2672, -97.7431)

        assert "address" in result
        assert result["address"]["city"] == "Austin"


# ---------------------------------------------------------------------------
# Regrid API tests
# ---------------------------------------------------------------------------

class TestRegridLookup:

    @pytest.mark.asyncio
    async def test_regrid_no_key_raises_error(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GHOST_REGRID_KEY", None)
            with pytest.raises(GISError) as exc:
                await regrid_lookup(address="123 Main St")
        assert "GHOST_REGRID_KEY not set" in str(exc.value)

    @pytest.mark.asyncio
    async def test_regrid_address_lookup(self, mock_httpx_response):
        mock_resp = mock_httpx_response(status_code=200, json_data=SAMPLE_REGRID_RESPONSE)

        with patch.dict(os.environ, {"GHOST_REGRID_KEY": "test-key"}):
            with patch("httpx.AsyncClient") as mock_client:
                mock_instance = AsyncMock()
                mock_instance.get = AsyncMock(return_value=mock_resp)
                mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
                mock_instance.__aexit__ = AsyncMock(return_value=None)
                mock_client.return_value = mock_instance

                result = await regrid_lookup(address="123 Main St, Austin, TX")

        assert result.parcel_id == "123-456-789"
        assert result.address == "123 MAIN ST"
        assert result.city == "AUSTIN"
        assert result.state == "TX"
        assert result.owner_name == "DOE, JOHN"
        assert result.owner_type == "individual"
        assert result.total_value == 500000
        assert result.source == "regrid"

    @pytest.mark.asyncio
    async def test_regrid_coordinate_lookup(self, mock_httpx_response):
        mock_resp = mock_httpx_response(status_code=200, json_data=SAMPLE_REGRID_RESPONSE)

        with patch.dict(os.environ, {"GHOST_REGRID_KEY": "test-key"}):
            with patch("httpx.AsyncClient") as mock_client:
                mock_instance = AsyncMock()
                mock_instance.get = AsyncMock(return_value=mock_resp)
                mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
                mock_instance.__aexit__ = AsyncMock(return_value=None)
                mock_client.return_value = mock_instance

                result = await regrid_lookup(lat=30.2672, lon=-97.7431)

        assert result.parcel_id == "123-456-789"

    @pytest.mark.asyncio
    async def test_regrid_parcel_id_lookup(self, mock_httpx_response):
        mock_resp = mock_httpx_response(status_code=200, json_data=SAMPLE_REGRID_RESPONSE)

        with patch.dict(os.environ, {"GHOST_REGRID_KEY": "test-key"}):
            with patch("httpx.AsyncClient") as mock_client:
                mock_instance = AsyncMock()
                mock_instance.get = AsyncMock(return_value=mock_resp)
                mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
                mock_instance.__aexit__ = AsyncMock(return_value=None)
                mock_client.return_value = mock_instance

                result = await regrid_lookup(parcel_id="123-456-789", state="TX", county="Travis")

        assert result.parcel_id == "123-456-789"

    @pytest.mark.asyncio
    async def test_regrid_no_results(self, mock_httpx_response):
        mock_resp = mock_httpx_response(status_code=200, json_data=EMPTY_REGRID_RESPONSE)

        with patch.dict(os.environ, {"GHOST_REGRID_KEY": "test-key"}):
            with patch("httpx.AsyncClient") as mock_client:
                mock_instance = AsyncMock()
                mock_instance.get = AsyncMock(return_value=mock_resp)
                mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
                mock_instance.__aexit__ = AsyncMock(return_value=None)
                mock_client.return_value = mock_instance

                with pytest.raises(GISError) as exc:
                    await regrid_lookup(address="nonexistent address")

        assert "No parcel found" in str(exc.value)

    @pytest.mark.asyncio
    async def test_regrid_rate_limit_error(self, mock_httpx_response):
        mock_resp = mock_httpx_response(status_code=403)

        with patch.dict(os.environ, {"GHOST_REGRID_KEY": "test-key"}):
            with patch("httpx.AsyncClient") as mock_client:
                mock_instance = AsyncMock()
                mock_instance.get = AsyncMock(return_value=mock_resp)
                mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
                mock_instance.__aexit__ = AsyncMock(return_value=None)
                mock_client.return_value = mock_instance

                with pytest.raises(GISError) as exc:
                    await regrid_lookup(address="123 Main St")

        assert "rate limit" in str(exc.value).lower()

    @pytest.mark.asyncio
    async def test_regrid_invalid_key(self, mock_httpx_response):
        mock_resp = mock_httpx_response(status_code=401)

        with patch.dict(os.environ, {"GHOST_REGRID_KEY": "bad-key"}):
            with patch("httpx.AsyncClient") as mock_client:
                mock_instance = AsyncMock()
                mock_instance.get = AsyncMock(return_value=mock_resp)
                mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
                mock_instance.__aexit__ = AsyncMock(return_value=None)
                mock_client.return_value = mock_instance

                with pytest.raises(GISError) as exc:
                    await regrid_lookup(address="123 Main St")

        assert "Invalid" in str(exc.value)


# ---------------------------------------------------------------------------
# State GIS endpoint tests
# ---------------------------------------------------------------------------

class TestStateEndpoints:

    def test_state_endpoints_registry(self):
        """Verify expected states are in the registry."""
        assert "TX" in STATE_ENDPOINTS
        assert "NY" in STATE_ENDPOINTS
        assert "FL" in STATE_ENDPOINTS
        assert "CO" in STATE_ENDPOINTS

    def test_state_endpoint_has_required_fields(self):
        """Verify each state endpoint has required configuration."""
        for state, config in STATE_ENDPOINTS.items():
            assert "name" in config
            assert "url" in config
            assert "fields" in config
            assert config["url"].startswith("http")


class TestArcGISQuery:

    @pytest.mark.asyncio
    async def test_arcgis_coordinate_query(self, mock_httpx_response):
        mock_resp = mock_httpx_response(status_code=200, json_data=SAMPLE_ARCGIS_RESPONSE)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            attrs = await arcgis_query(
                "https://example.com/arcgis/rest/services/Parcels/MapServer/0",
                lat=30.2672,
                lon=-97.7431,
            )

        assert attrs["PARCEL_ID"] == "TX-12345"
        assert attrs["owner"] == "SMITH, JANE"

    @pytest.mark.asyncio
    async def test_arcgis_parcel_id_query(self, mock_httpx_response):
        mock_resp = mock_httpx_response(status_code=200, json_data=SAMPLE_ARCGIS_RESPONSE)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            attrs = await arcgis_query(
                "https://example.com/arcgis/rest/services/Parcels/MapServer/0",
                parcel_id="TX-12345",
                parcel_field="PARCEL_ID",
            )

        assert attrs["PARCEL_ID"] == "TX-12345"

    @pytest.mark.asyncio
    async def test_arcgis_no_features(self, mock_httpx_response):
        mock_resp = mock_httpx_response(status_code=200, json_data=EMPTY_ARCGIS_RESPONSE)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            with pytest.raises(GISError) as exc:
                await arcgis_query(
                    "https://example.com/arcgis",
                    lat=0,
                    lon=0,
                )

        assert "No parcel found" in str(exc.value)

    @pytest.mark.asyncio
    async def test_arcgis_error_response(self, mock_httpx_response):
        error_response = {"error": {"message": "Invalid geometry"}}
        mock_resp = mock_httpx_response(status_code=200, json_data=error_response)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            with pytest.raises(GISError) as exc:
                await arcgis_query(
                    "https://example.com/arcgis",
                    lat=30.0,
                    lon=-97.0,
                )

        assert "Invalid geometry" in str(exc.value)


class TestStateGISLookup:

    @pytest.mark.asyncio
    async def test_state_lookup_unsupported_state(self):
        with pytest.raises(GISError) as exc:
            await state_gis_lookup(state="ZZ", lat=30.0, lon=-97.0)
        assert "not supported" in str(exc.value)
        assert "TX" in str(exc.value)  # Should list available states

    @pytest.mark.asyncio
    async def test_state_lookup_texas(self, mock_httpx_response):
        mock_resp = mock_httpx_response(status_code=200, json_data=SAMPLE_ARCGIS_RESPONSE)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await state_gis_lookup(state="TX", lat=30.2672, lon=-97.7431)

        assert result.parcel_id == "TX-12345"
        assert result.state == "TX"
        assert result.source == "state:tx"
        assert result.owner_name == "SMITH, JANE"


# ---------------------------------------------------------------------------
# Main gis_lookup function tests
# ---------------------------------------------------------------------------

class TestGISLookup:

    @pytest.mark.asyncio
    async def test_lookup_requires_input(self):
        with pytest.raises(GISError) as exc:
            await gis_lookup()
        # The function returns error string, not raises
        # Let's test through the actual behavior

    @pytest.mark.asyncio
    async def test_lookup_auto_provider_with_regrid_key(self, mock_httpx_response):
        """When GHOST_REGRID_KEY is set, auto should use Regrid."""
        mock_resp = mock_httpx_response(status_code=200, json_data=SAMPLE_REGRID_RESPONSE)

        with patch.dict(os.environ, {"GHOST_REGRID_KEY": "test-key"}):
            with patch("httpx.AsyncClient") as mock_client:
                mock_instance = AsyncMock()
                mock_instance.get = AsyncMock(return_value=mock_resp)
                mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
                mock_instance.__aexit__ = AsyncMock(return_value=None)
                mock_client.return_value = mock_instance

                # Mock geocoding too
                with patch("ghostmcp.recon.gis.geocode_address", return_value=(30.2672, -97.7431)):
                    result = await gis_lookup(address="123 Main St, Austin, TX", provider="auto")

        assert result.source == "regrid"

    @pytest.mark.asyncio
    async def test_lookup_auto_provider_falls_back_to_state(self, mock_httpx_response):
        """When no Regrid key but state is supported, auto should use state endpoint."""
        mock_resp = mock_httpx_response(status_code=200, json_data=SAMPLE_ARCGIS_RESPONSE)

        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GHOST_REGRID_KEY", None)
            with patch("httpx.AsyncClient") as mock_client:
                mock_instance = AsyncMock()
                mock_instance.get = AsyncMock(return_value=mock_resp)
                mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
                mock_instance.__aexit__ = AsyncMock(return_value=None)
                mock_client.return_value = mock_instance

                # Mock geocoding
                with patch("ghostmcp.recon.gis.geocode_address", return_value=(30.2672, -97.7431)):
                    result = await gis_lookup(
                        address="123 Main St, Austin, TX 78701",
                        state="TX",
                        provider="auto",
                    )

        assert result.source == "state:tx"

    @pytest.mark.asyncio
    async def test_lookup_explicit_regrid_provider(self, mock_httpx_response):
        mock_resp = mock_httpx_response(status_code=200, json_data=SAMPLE_REGRID_RESPONSE)

        with patch.dict(os.environ, {"GHOST_REGRID_KEY": "test-key"}):
            with patch("httpx.AsyncClient") as mock_client:
                mock_instance = AsyncMock()
                mock_instance.get = AsyncMock(return_value=mock_resp)
                mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
                mock_instance.__aexit__ = AsyncMock(return_value=None)
                mock_client.return_value = mock_instance

                result = await gis_lookup(lat=30.2672, lon=-97.7431, provider="regrid")

        assert result.source == "regrid"

    @pytest.mark.asyncio
    async def test_lookup_explicit_state_provider(self, mock_httpx_response):
        mock_resp = mock_httpx_response(status_code=200, json_data=SAMPLE_ARCGIS_RESPONSE)

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_resp)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await gis_lookup(lat=30.2672, lon=-97.7431, state="TX", provider="state")

        assert result.source == "state:tx"

    @pytest.mark.asyncio
    async def test_lookup_geocodes_address_automatically(self, mock_httpx_response):
        """When address is provided without coordinates, should geocode first."""
        mock_regrid_resp = mock_httpx_response(status_code=200, json_data=SAMPLE_REGRID_RESPONSE)

        with patch.dict(os.environ, {"GHOST_REGRID_KEY": "test-key"}):
            with patch("httpx.AsyncClient") as mock_client:
                mock_instance = AsyncMock()
                mock_instance.get = AsyncMock(return_value=mock_regrid_resp)
                mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
                mock_instance.__aexit__ = AsyncMock(return_value=None)
                mock_client.return_value = mock_instance

                with patch("ghostmcp.recon.gis.geocode_address", return_value=(30.2672, -97.7431)) as mock_geo:
                    result = await gis_lookup(address="123 Main St, Austin, TX", provider="regrid")
                    mock_geo.assert_called_once()


# ---------------------------------------------------------------------------
# GISResult dataclass tests
# ---------------------------------------------------------------------------

class TestGISResult:

    def test_default_values(self):
        result = GISResult()
        assert result.parcel_id == ""
        assert result.address == ""
        assert result.coordinates == (0.0, 0.0)
        assert result.owner_name == ""
        assert result.owner_type == ""
        assert result.alternate_addresses == []
        assert result.phone_numbers == []
        assert result.search_urls == {}

    def test_full_result(self):
        result = GISResult(
            parcel_id="123-456",
            address="123 Main St",
            city="Austin",
            state="TX",
            zip_code="78701",
            county="Travis",
            coordinates=(30.2672, -97.7431),
            owner_name="DOE, JOHN",
            owner_type="individual",
            total_value=500000,
            source="regrid",
        )
        assert result.parcel_id == "123-456"
        assert result.owner_name == "DOE, JOHN"
        assert result.total_value == 500000


# ---------------------------------------------------------------------------
# Integration tests (require live APIs)
# ---------------------------------------------------------------------------

class TestGISIntegration:

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_live_geocoding(self):
        """Test live Nominatim geocoding."""
        lat, lon = await geocode_address("1600 Pennsylvania Avenue NW, Washington, DC")
        assert 38.8 < lat < 39.0
        assert -77.1 < lon < -76.9

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_live_regrid_lookup(self):
        """Test live Regrid API lookup.

        Requires: GHOST_REGRID_KEY environment variable
        """
        if not os.environ.get("GHOST_REGRID_KEY"):
            pytest.skip("GHOST_REGRID_KEY not set")

        result = await regrid_lookup(address="1600 Pennsylvania Avenue NW, Washington, DC")
        assert result.parcel_id
        assert result.owner_name
        assert result.source == "regrid"

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_live_texas_gis(self):
        """Test live Texas TNRIS GIS endpoint."""
        # Austin coordinates
        result = await state_gis_lookup(state="TX", lat=30.2672, lon=-97.7431)
        assert result.state == "TX"
        assert result.source == "state:tx"
        # May or may not have owner data depending on county participation

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_live_florida_gis(self):
        """Test live Florida statewide GIS endpoint."""
        # Miami coordinates
        result = await state_gis_lookup(state="FL", lat=25.7617, lon=-80.1918)
        assert result.state == "FL"
        assert result.source == "state:fl"
