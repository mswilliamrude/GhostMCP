"""Tests for court record search — CourtListener API, URL generation, parsing."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import quote_plus

import pytest

from src.recon.court import (
    CourtCase,
    CourtSearchResult,
    _build_search_urls,
    _parse_case,
    _query_courtlistener,
    court_search,
)


# ---------------------------------------------------------------------------
# Sample API responses
# ---------------------------------------------------------------------------

SAMPLE_COURTLISTENER_RESPONSE = {
    "count": 2,
    "results": [
        {
            "caseName": "Smith v. Jones",
            "docketNumber": "1:20-cv-01234",
            "court": "District Court, N.D. Texas",
            "date_filed": "2020-03-15",
            "date_terminated": "2021-06-20",
            "nature_of_suit": "Contract",
            "party": ["John Smith", "Bob Jones"],
            "attorney": ["Jane Lawyer"],
            "absolute_url": "/docket/12345/smith-v-jones/",
        },
        {
            "caseName": "Doe v. State of California",
            "docketNumber": "2:21-cv-05678",
            "court": "C.D. California",
            "date_filed": "2021-01-10",
            "date_terminated": "",
            "nature_of_suit": "Civil Rights",
            "party": "Jane Doe; State of California",
            "attorney": "Public Defender; State AG",
            "absolute_url": "/docket/67890/doe-v-state/",
        },
    ],
}

EMPTY_COURTLISTENER_RESPONSE = {
    "count": 0,
    "results": [],
}


# ---------------------------------------------------------------------------
# Search URL generation
# ---------------------------------------------------------------------------


class TestBuildSearchUrls:
    """Tests for _build_search_urls()."""

    def test_returns_expected_keys(self):
        urls = _build_search_urls("John Smith")
        assert "courtlistener" in urls
        assert "judyrecords" in urls
        assert "pacer" in urls
        assert "nsopw" in urls

    def test_courtlistener_url_contains_query(self):
        urls = _build_search_urls("John Smith")
        assert quote_plus("John Smith") in urls["courtlistener"]

    def test_nsopw_splits_first_last_name(self):
        urls = _build_search_urls("John Smith")
        assert "FirstName=" in urls["nsopw"]
        assert "LastName=" in urls["nsopw"]

    def test_nsopw_single_name_uses_last_name(self):
        urls = _build_search_urls("Smith")
        assert "LastName=" in urls["nsopw"]
        assert "FirstName=" not in urls["nsopw"]

    def test_judyrecords_contains_query(self):
        urls = _build_search_urls("John Doe")
        assert "judyrecords" in urls
        assert "John" in urls["judyrecords"] or "john" in urls["judyrecords"].lower()

    def test_pacer_is_static(self):
        """PACER doesn't support query params in URL — always same base URL."""
        urls = _build_search_urls("John Smith")
        assert "pcl.uscourts.gov" in urls["pacer"]

    def test_multi_word_name(self):
        urls = _build_search_urls("John Michael Smith III")
        # First name = "John", last name = "III"
        assert "FirstName=" in urls["nsopw"]
        assert "LastName=" in urls["nsopw"]


# ---------------------------------------------------------------------------
# CourtCase dataclass / _parse_case
# ---------------------------------------------------------------------------


class TestParseCase:
    """Tests for _parse_case() helper."""

    def test_basic_case_parsing(self):
        item = SAMPLE_COURTLISTENER_RESPONSE["results"][0]
        case = _parse_case(item)
        assert case.case_name == "Smith v. Jones"
        assert case.docket_number == "1:20-cv-01234"
        assert case.court == "District Court, N.D. Texas"
        assert case.date_filed == "2020-03-15"
        assert case.date_terminated == "2021-06-20"
        assert case.nature_of_suit == "Contract"

    def test_parties_as_list(self):
        item = SAMPLE_COURTLISTENER_RESPONSE["results"][0]
        case = _parse_case(item)
        assert "John Smith" in case.parties
        assert "Bob Jones" in case.parties

    def test_parties_as_semicolon_string(self):
        item = SAMPLE_COURTLISTENER_RESPONSE["results"][1]
        case = _parse_case(item)
        assert "Jane Doe" in case.parties
        assert "State of California" in case.parties

    def test_attorneys_as_list(self):
        item = SAMPLE_COURTLISTENER_RESPONSE["results"][0]
        case = _parse_case(item)
        assert "Jane Lawyer" in case.attorneys

    def test_attorneys_as_semicolon_string(self):
        item = SAMPLE_COURTLISTENER_RESPONSE["results"][1]
        case = _parse_case(item)
        assert "Public Defender" in case.attorneys
        assert "State AG" in case.attorneys

    def test_source_url_from_absolute_url(self):
        item = SAMPLE_COURTLISTENER_RESPONSE["results"][0]
        case = _parse_case(item)
        assert case.source_url == "https://www.courtlistener.com/docket/12345/smith-v-jones/"

    def test_source_url_from_docket_id_fallback(self):
        item = {"docket_id": "99999"}
        case = _parse_case(item)
        assert "99999" in case.source_url

    def test_empty_item(self):
        case = _parse_case({})
        assert case.case_name == ""
        assert case.docket_number == ""
        assert case.parties == []
        assert case.attorneys == []

    def test_alternative_field_names(self):
        """CourtListener sometimes uses camelCase or snake_case."""
        item = {
            "case_name": "Alt v. Case",
            "docket_number": "3:22-cv-00001",
            "dateFiled": "2022-05-01",
            "suitNature": "Tort",
        }
        case = _parse_case(item)
        assert case.case_name == "Alt v. Case"
        assert case.date_filed == "2022-05-01"
        assert case.nature_of_suit == "Tort"


# ---------------------------------------------------------------------------
# CourtCase dataclass defaults
# ---------------------------------------------------------------------------


class TestCourtCaseDefaults:
    """Tests for CourtCase dataclass default values."""

    def test_defaults(self):
        case = CourtCase()
        assert case.case_name == ""
        assert case.docket_number == ""
        assert case.court == ""
        assert case.date_filed == ""
        assert case.date_terminated == ""
        assert case.parties == []
        assert case.attorneys == []
        assert case.nature_of_suit == ""
        assert case.source_url == ""


# ---------------------------------------------------------------------------
# _query_courtlistener tests
# ---------------------------------------------------------------------------


class TestQueryCourtlistener:
    """Tests for _query_courtlistener() — mocked HTTP."""

    @pytest.mark.asyncio
    async def test_successful_party_search(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_COURTLISTENER_RESPONSE

        with patch.dict("os.environ", {"GHOST_COURTLISTENER_TOKEN": "test-token"}), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                total, cases, error = await _query_courtlistener(client, "Smith", "party")

        assert total == 2
        assert len(cases) == 2
        assert error is None
        assert cases[0].case_name == "Smith v. Jones"

    @pytest.mark.asyncio
    async def test_docket_number_search(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_COURTLISTENER_RESPONSE

        with patch.dict("os.environ", {"GHOST_COURTLISTENER_TOKEN": "test-token"}), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                total, cases, error = await _query_courtlistener(client, "1:20-cv-01234", "docket")

        assert error is None
        # Verify the query param was set for docket search
        call_kwargs = mock_get.call_args
        params = call_kwargs.kwargs.get("params") or call_kwargs[1].get("params", {})
        assert "docketNumber" in params.get("q", "")

    @pytest.mark.asyncio
    async def test_no_token_returns_error(self):
        with patch.dict("os.environ", {}, clear=True):
            async with __import__("httpx").AsyncClient() as client:
                total, cases, error = await _query_courtlistener(client, "Smith", "party")

        assert total == 0
        assert cases == []
        assert error is not None
        assert "GHOST_COURTLISTENER_TOKEN" in error

    @pytest.mark.asyncio
    async def test_invalid_token_401(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 401

        with patch.dict("os.environ", {"GHOST_COURTLISTENER_TOKEN": "bad-token"}), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                total, cases, error = await _query_courtlistener(client, "Smith", "party")

        assert total == 0
        assert "Invalid" in error

    @pytest.mark.asyncio
    async def test_rate_limit_429(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 429

        with patch.dict("os.environ", {"GHOST_COURTLISTENER_TOKEN": "test-token"}), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                total, cases, error = await _query_courtlistener(client, "Smith", "party")

        assert "rate limit" in error.lower()

    @pytest.mark.asyncio
    async def test_server_error_500(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 500

        with patch.dict("os.environ", {"GHOST_COURTLISTENER_TOKEN": "test-token"}), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                total, cases, error = await _query_courtlistener(client, "Smith", "party")

        assert "500" in error

    @pytest.mark.asyncio
    async def test_timeout(self):
        import httpx

        with patch.dict("os.environ", {"GHOST_COURTLISTENER_TOKEN": "test-token"}), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.TimeoutException("timed out")
            async with httpx.AsyncClient() as client:
                total, cases, error = await _query_courtlistener(client, "Smith", "party")

        assert total == 0
        assert error is not None

    @pytest.mark.asyncio
    async def test_empty_results(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = EMPTY_COURTLISTENER_RESPONSE

        with patch.dict("os.environ", {"GHOST_COURTLISTENER_TOKEN": "test-token"}), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                total, cases, error = await _query_courtlistener(client, "Nonexistent Person", "party")

        assert total == 0
        assert cases == []
        assert error is None


# ---------------------------------------------------------------------------
# court_search public API
# ---------------------------------------------------------------------------


class TestCourtSearch:
    """Tests for court_search() public API."""

    @pytest.mark.asyncio
    async def test_empty_query(self):
        result = await court_search("")
        assert result.error is not None
        assert "Empty" in result.error

    @pytest.mark.asyncio
    async def test_no_token_returns_urls_only(self):
        with patch.dict("os.environ", {}, clear=True):
            result = await court_search("John Smith")

        assert result.cases == []
        assert "courtlistener" in result.search_urls
        assert result.error is not None
        assert "GHOST_COURTLISTENER_TOKEN" in result.error

    @pytest.mark.asyncio
    async def test_successful_search(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_COURTLISTENER_RESPONSE

        with patch.dict("os.environ", {"GHOST_COURTLISTENER_TOKEN": "test-token"}), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            result = await court_search("Smith")

        assert result.total_results == 2
        assert len(result.cases) == 2
        assert result.error is None

    @pytest.mark.asyncio
    async def test_query_stored_in_result(self):
        with patch.dict("os.environ", {}, clear=True):
            result = await court_search("John Smith")

        assert result.query == "John Smith"

    @pytest.mark.asyncio
    async def test_search_urls_always_populated(self):
        with patch.dict("os.environ", {}, clear=True):
            result = await court_search("Jane Doe")

        assert "courtlistener" in result.search_urls
        assert "judyrecords" in result.search_urls
        assert "pacer" in result.search_urls
        assert "nsopw" in result.search_urls

    @pytest.mark.asyncio
    async def test_pagination_total_vs_returned(self):
        """total_results can exceed len(cases) — only first page returned."""
        paginated_response = {
            "count": 150,
            "results": SAMPLE_COURTLISTENER_RESPONSE["results"],
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = paginated_response

        with patch.dict("os.environ", {"GHOST_COURTLISTENER_TOKEN": "test-token"}), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            result = await court_search("Common Name")

        assert result.total_results == 150
        assert len(result.cases) == 2  # Only 2 in this page

    @pytest.mark.asyncio
    async def test_query_whitespace_stripped(self):
        with patch.dict("os.environ", {}, clear=True):
            result = await court_search("  John Smith  ")

        assert result.query == "John Smith"

    @pytest.mark.asyncio
    async def test_api_error_propagated(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 401

        with patch.dict("os.environ", {"GHOST_COURTLISTENER_TOKEN": "bad-token"}), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            result = await court_search("Smith")

        assert result.error is not None
        assert "Invalid" in result.error
