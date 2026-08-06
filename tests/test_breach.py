"""Tests for breach data search — HIBP metadata, Snusbase, DeHashed, LeakCheck."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ghostmcp.recon.breach import (
    BreachRecord,
    BreachSearchResult,
    _build_search_urls,
    _classify_severity,
    _data_classes_from_details,
    _query_dehashed,
    _query_hibp,
    _query_leakcheck,
    _query_snusbase,
    breach_search,
)


# ---------------------------------------------------------------------------
# Sample API responses
# ---------------------------------------------------------------------------

SAMPLE_HIBP_RESPONSE = [
    {
        "Name": "Adobe",
        "Title": "Adobe",
        "Domain": "adobe.com",
        "BreachDate": "2013-10-04",
        "PwnCount": 152445165,
        "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"],
    },
    {
        "Name": "LinkedIn",
        "Title": "LinkedIn",
        "BreachDate": "2012-05-05",
        "PwnCount": 164611595,
        "DataClasses": ["Email addresses", "Passwords"],
    },
]

SAMPLE_SNUSBASE_RESPONSE = {
    "took": 23,
    "size": 2,
    "results": {
        "ExampleDB_2022": [
            {
                "email": "test@example.com",
                "password": "hashed123",
                "name": "John Doe",
                "ip": "1.2.3.4",
            },
        ],
        "AnotherDB_2021": [
            {
                "email": "test@example.com",
                "username": "johndoe",
                "phone": "2145551234",
            },
        ],
    },
}

SAMPLE_DEHASHED_RESPONSE = {
    "balance": 100,
    "entries": [
        {
            "id": "abc123",
            "email": "test@example.com",
            "password": "pass123",
            "hashed_password": "5f4dcc3b",
            "name": "John Doe",
            "database_name": "ExampleDB",
        },
    ],
}

SAMPLE_LEAKCHECK_RESPONSE = {
    "success": True,
    "found": 2,
    "fields": ["Email addresses", "Passwords", "Usernames"],
    "sources": [
        {"name": "BreachDB_2020", "date": "2020-01-15"},
        {"name": "LeakDB_2021", "date": "2021-06-01"},
    ],
}


# ---------------------------------------------------------------------------
# Severity classification
# ---------------------------------------------------------------------------


class TestClassifySeverity:
    """Tests for _classify_severity()."""

    def test_critical_passwords_and_financial(self):
        classes = ["Passwords", "Credit cards", "Email addresses"]
        assert _classify_severity(classes) == "critical"

    def test_critical_password_hints_and_financial(self):
        classes = ["Password hints", "Financial data"]
        assert _classify_severity(classes) == "critical"

    def test_high_passwords_only(self):
        classes = ["Passwords", "Email addresses"]
        assert _classify_severity(classes) == "high"

    def test_high_ssn(self):
        classes = ["Social security numbers", "Email addresses"]
        assert _classify_severity(classes) == "high"

    def test_high_national_ids(self):
        classes = ["National ids", "Names"]
        assert _classify_severity(classes) == "high"

    def test_medium_names_and_addresses(self):
        classes = ["Names", "Physical addresses", "Email addresses"]
        assert _classify_severity(classes) == "medium"

    def test_medium_dob(self):
        classes = ["Dates of birth", "Email addresses"]
        assert _classify_severity(classes) == "medium"

    def test_low_emails_only(self):
        classes = ["Email addresses"]
        assert _classify_severity(classes) == "low"

    def test_low_empty(self):
        assert _classify_severity([]) == "low"

    def test_case_insensitive(self):
        classes = ["PASSWORDS", "CREDIT CARDS"]
        assert _classify_severity(classes) == "critical"

    def test_passwords_override_medium(self):
        """Passwords present → at least high, even with medium classes."""
        classes = ["Passwords", "Names", "Dates of birth"]
        assert _classify_severity(classes) == "high"


# ---------------------------------------------------------------------------
# Data class inference from details
# ---------------------------------------------------------------------------


class TestDataClassesFromDetails:
    """Tests for _data_classes_from_details()."""

    def test_email_field(self):
        classes = _data_classes_from_details({"email": "test@example.com"})
        assert "Email addresses" in classes

    def test_password_field(self):
        classes = _data_classes_from_details({"password": "pass123"})
        assert "Passwords" in classes

    def test_multiple_fields(self):
        classes = _data_classes_from_details({
            "email": "test@example.com",
            "name": "John",
            "phone": "555-1234",
        })
        assert "Email addresses" in classes
        assert "Names" in classes
        assert "Phone numbers" in classes

    def test_deduplication(self):
        """ip and lastip should both map to 'IP addresses' but appear once."""
        classes = _data_classes_from_details({"ip": "1.2.3.4", "lastip": "5.6.7.8"})
        assert classes.count("IP addresses") == 1

    def test_empty_details(self):
        assert _data_classes_from_details({}) == []

    def test_unknown_field_ignored(self):
        classes = _data_classes_from_details({"unknown_field": "value"})
        assert classes == []


# ---------------------------------------------------------------------------
# Search URL generation
# ---------------------------------------------------------------------------


class TestBuildSearchUrls:
    """Tests for _build_search_urls()."""

    def test_returns_expected_keys(self):
        urls = _build_search_urls("test@example.com")
        assert "haveibeenpwned" in urls
        assert "dehashed" in urls
        assert "snusbase" in urls
        assert "leakcheck" in urls

    def test_hibp_url_contains_query(self):
        urls = _build_search_urls("test@example.com")
        assert "test" in urls["haveibeenpwned"]

    def test_dehashed_url_contains_query(self):
        urls = _build_search_urls("test@example.com")
        assert "test" in urls["dehashed"]


# ---------------------------------------------------------------------------
# HIBP metadata query (Layer 1)
# ---------------------------------------------------------------------------


class TestQueryHibp:
    """Tests for _query_hibp()."""

    @pytest.mark.asyncio
    async def test_successful_lookup(self):
        result = BreachSearchResult(query="test@example.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_HIBP_RESPONSE

        with patch.dict("os.environ", {"GHOST_HIBP_KEY": "test-key"}), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                await _query_hibp(client, "test@example.com", result)

        assert len(result.records) == 2
        assert result.records[0].source == "hibp"
        assert result.records[0].breach_name == "Adobe"
        assert result.records[0].record_count == 152445165
        assert result.records[1].breach_name == "LinkedIn"

    @pytest.mark.asyncio
    async def test_severity_classified(self):
        result = BreachSearchResult(query="test@example.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_HIBP_RESPONSE

        with patch.dict("os.environ", {"GHOST_HIBP_KEY": "test-key"}), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                await _query_hibp(client, "test@example.com", result)

        # Adobe has passwords → at least "high"
        assert result.records[0].severity in ("high", "critical")

    @pytest.mark.asyncio
    async def test_no_api_key_skips(self):
        result = BreachSearchResult(query="test@example.com")

        with patch.dict("os.environ", {}, clear=True):
            async with __import__("httpx").AsyncClient() as client:
                await _query_hibp(client, "test@example.com", result)

        assert "hibp" in result.providers_failed
        assert "GHOST_HIBP_KEY" in result.providers_failed["hibp"]

    @pytest.mark.asyncio
    async def test_404_no_breaches(self):
        result = BreachSearchResult(query="clean@example.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch.dict("os.environ", {"GHOST_HIBP_KEY": "test-key"}), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                await _query_hibp(client, "clean@example.com", result)

        assert result.records == []
        assert "hibp" not in result.providers_failed

    @pytest.mark.asyncio
    async def test_401_invalid_key(self):
        result = BreachSearchResult(query="test@example.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 401

        with patch.dict("os.environ", {"GHOST_HIBP_KEY": "bad-key"}), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                await _query_hibp(client, "test@example.com", result)

        assert "hibp" in result.providers_failed
        assert "Invalid" in result.providers_failed["hibp"]

    @pytest.mark.asyncio
    async def test_timeout(self):
        import httpx

        result = BreachSearchResult(query="test@example.com")

        with patch.dict("os.environ", {"GHOST_HIBP_KEY": "test-key"}), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.TimeoutException("timed out")
            async with httpx.AsyncClient() as client:
                await _query_hibp(client, "test@example.com", result)

        assert "hibp" in result.providers_failed
        assert "timed out" in result.providers_failed["hibp"].lower()


# ---------------------------------------------------------------------------
# Snusbase (Layer 2)
# ---------------------------------------------------------------------------


class TestQuerySnusbase:
    """Tests for _query_snusbase()."""

    @pytest.mark.asyncio
    async def test_successful_lookup(self):
        result = BreachSearchResult(query="test@example.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_SNUSBASE_RESPONSE

        with patch.dict("os.environ", {"GHOST_SNUSBASE_KEY": "snusbase-key"}), \
             patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                await _query_snusbase(client, "test@example.com", "email", result)

        assert len(result.records) == 2
        assert result.records[0].source == "snusbase"
        assert result.records[0].breach_name == "ExampleDB_2022"
        assert result.records[0].details is not None
        assert result.records[0].details["email"] == "test@example.com"
        assert result.records[0].details["password"] == "hashed123"

    @pytest.mark.asyncio
    async def test_no_api_key_skips(self):
        result = BreachSearchResult(query="test@example.com")

        with patch.dict("os.environ", {}, clear=True):
            async with __import__("httpx").AsyncClient() as client:
                await _query_snusbase(client, "test@example.com", "email", result)

        assert "snusbase" in result.providers_failed

    @pytest.mark.asyncio
    async def test_401_invalid_key(self):
        result = BreachSearchResult(query="test@example.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 401

        with patch.dict("os.environ", {"GHOST_SNUSBASE_KEY": "bad-key"}), \
             patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                await _query_snusbase(client, "test@example.com", "email", result)

        assert "snusbase" in result.providers_failed
        assert "Invalid" in result.providers_failed["snusbase"]


# ---------------------------------------------------------------------------
# DeHashed (Layer 2)
# ---------------------------------------------------------------------------


class TestQueryDehashed:
    """Tests for _query_dehashed()."""

    @pytest.mark.asyncio
    async def test_successful_lookup(self):
        result = BreachSearchResult(query="test@example.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_DEHASHED_RESPONSE

        with patch.dict("os.environ", {
            "GHOST_DEHASHED_EMAIL": "user@example.com",
            "GHOST_DEHASHED_KEY": "dehashed-key",
        }), patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                await _query_dehashed(client, "test@example.com", "email", result)

        assert len(result.records) == 1
        assert result.records[0].source == "dehashed"
        assert result.records[0].breach_name == "ExampleDB"
        assert result.records[0].details["password"] == "pass123"

    @pytest.mark.asyncio
    async def test_no_credentials_skips(self):
        result = BreachSearchResult(query="test@example.com")

        with patch.dict("os.environ", {}, clear=True):
            async with __import__("httpx").AsyncClient() as client:
                await _query_dehashed(client, "test@example.com", "email", result)

        assert "dehashed" in result.providers_failed

    @pytest.mark.asyncio
    async def test_401_invalid_credentials(self):
        result = BreachSearchResult(query="test@example.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 401

        with patch.dict("os.environ", {
            "GHOST_DEHASHED_EMAIL": "user@example.com",
            "GHOST_DEHASHED_KEY": "bad-key",
        }), patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                await _query_dehashed(client, "test@example.com", "email", result)

        assert "dehashed" in result.providers_failed
        assert "Invalid" in result.providers_failed["dehashed"]

    @pytest.mark.asyncio
    async def test_402_insufficient_balance(self):
        result = BreachSearchResult(query="test@example.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 402

        with patch.dict("os.environ", {
            "GHOST_DEHASHED_EMAIL": "user@example.com",
            "GHOST_DEHASHED_KEY": "key",
        }), patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                await _query_dehashed(client, "test@example.com", "email", result)

        assert "dehashed" in result.providers_failed
        assert "balance" in result.providers_failed["dehashed"].lower()

    @pytest.mark.asyncio
    async def test_empty_entries(self):
        result = BreachSearchResult(query="test@example.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"balance": 100, "entries": None}

        with patch.dict("os.environ", {
            "GHOST_DEHASHED_EMAIL": "user@example.com",
            "GHOST_DEHASHED_KEY": "key",
        }), patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                await _query_dehashed(client, "test@example.com", "email", result)

        assert result.records == []


# ---------------------------------------------------------------------------
# LeakCheck (Layer 2)
# ---------------------------------------------------------------------------


class TestQueryLeakcheck:
    """Tests for _query_leakcheck()."""

    @pytest.mark.asyncio
    async def test_successful_lookup(self):
        result = BreachSearchResult(query="test@example.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_LEAKCHECK_RESPONSE

        with patch.dict("os.environ", {"GHOST_LEAKCHECK_KEY": "leakcheck-key"}), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                await _query_leakcheck(client, "test@example.com", "email", result)

        assert len(result.records) == 2
        assert result.records[0].source == "leakcheck"
        assert result.records[0].breach_name == "BreachDB_2020"
        assert result.records[0].date == "2020-01-15"

    @pytest.mark.asyncio
    async def test_no_api_key_skips(self):
        result = BreachSearchResult(query="test@example.com")

        with patch.dict("os.environ", {}, clear=True):
            async with __import__("httpx").AsyncClient() as client:
                await _query_leakcheck(client, "test@example.com", "email", result)

        assert "leakcheck" in result.providers_failed

    @pytest.mark.asyncio
    async def test_unsupported_query_type(self):
        result = BreachSearchResult(query="John Doe")

        with patch.dict("os.environ", {"GHOST_LEAKCHECK_KEY": "key"}):
            async with __import__("httpx").AsyncClient() as client:
                await _query_leakcheck(client, "John Doe", "name", result)

        assert "leakcheck" in result.providers_failed
        assert "does not support" in result.providers_failed["leakcheck"]

    @pytest.mark.asyncio
    async def test_rate_limited_429(self):
        result = BreachSearchResult(query="test@example.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 429

        with patch.dict("os.environ", {"GHOST_LEAKCHECK_KEY": "key"}), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                await _query_leakcheck(client, "test@example.com", "email", result)

        assert "leakcheck" in result.providers_failed
        assert "Rate limited" in result.providers_failed["leakcheck"]


# ---------------------------------------------------------------------------
# breach_search public API
# ---------------------------------------------------------------------------


class TestBreachSearch:
    """Tests for breach_search() public API."""

    @pytest.mark.asyncio
    async def test_invalid_mode(self):
        result = await breach_search("test@example.com", mode="invalid")
        assert result.error is not None
        assert "Invalid mode" in result.error

    @pytest.mark.asyncio
    async def test_invalid_query_type(self):
        result = await breach_search("test@example.com", query_type="invalid_type")
        assert result.error is not None
        assert "Invalid query_type" in result.error

    @pytest.mark.asyncio
    async def test_valid_query_types(self):
        """All valid query types should not produce a query_type error."""
        for qt in ("email", "phone", "username", "name", "ip"):
            with patch.dict("os.environ", {}, clear=True):
                result = await breach_search("test", query_type=qt, mode="metadata_only")
            assert result.error is None or "query_type" not in (result.error or "")

    @pytest.mark.asyncio
    async def test_metadata_only_checks_hibp(self):
        """metadata_only mode with email query should check HIBP."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_HIBP_RESPONSE

        with patch.dict("os.environ", {"GHOST_HIBP_KEY": "test-key"}), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            result = await breach_search("test@example.com", mode="metadata_only")

        assert "hibp" in result.providers_checked
        assert "snusbase" not in result.providers_checked
        assert "dehashed" not in result.providers_checked

    @pytest.mark.asyncio
    async def test_full_mode_checks_all_providers(self):
        """full mode should check HIBP + Snusbase + DeHashed + LeakCheck."""
        with patch("ghostmcp.recon.breach._query_hibp", new_callable=AsyncMock) as mock_hibp, \
             patch("ghostmcp.recon.breach._query_snusbase", new_callable=AsyncMock) as mock_snus, \
             patch("ghostmcp.recon.breach._query_dehashed", new_callable=AsyncMock) as mock_dh, \
             patch("ghostmcp.recon.breach._query_leakcheck", new_callable=AsyncMock) as mock_lc:
            result = await breach_search("test@example.com", mode="full")

        assert "hibp" in result.providers_checked
        assert "snusbase" in result.providers_checked
        assert "dehashed" in result.providers_checked
        assert "leakcheck" in result.providers_checked

    @pytest.mark.asyncio
    async def test_deduplication(self):
        """Duplicate records from different providers should be deduplicated."""
        async def add_dupes(client, query, qtype, result):
            result.records.append(BreachRecord(
                source="snusbase", breach_name="ExampleDB", date="",
                data_classes=["Email addresses"],
            ))
            result.records.append(BreachRecord(
                source="snusbase", breach_name="ExampleDB", date="",
                data_classes=["Email addresses"],
            ))

        with patch("ghostmcp.recon.breach._query_hibp", new_callable=AsyncMock), \
             patch("ghostmcp.recon.breach._query_snusbase", side_effect=add_dupes), \
             patch("ghostmcp.recon.breach._query_dehashed", new_callable=AsyncMock), \
             patch("ghostmcp.recon.breach._query_leakcheck", new_callable=AsyncMock):
            result = await breach_search("test@example.com", mode="full")

        # Same (source, breach_name) should appear only once
        snus_examples = [r for r in result.records if r.source == "snusbase" and r.breach_name == "ExampleDB"]
        assert len(snus_examples) == 1

    @pytest.mark.asyncio
    async def test_provider_failure_handling(self):
        """One provider failing should not prevent others from succeeding."""
        async def succeed_snusbase(client, query, qtype, result):
            result.records.append(BreachRecord(
                source="snusbase", breach_name="FoundDB", date="2022-01-01",
                data_classes=["Email addresses"],
            ))

        async def fail_dehashed(client, query, qtype, result):
            result.providers_failed["dehashed"] = "Connection error"

        with patch("ghostmcp.recon.breach._query_hibp", new_callable=AsyncMock), \
             patch("ghostmcp.recon.breach._query_snusbase", side_effect=succeed_snusbase), \
             patch("ghostmcp.recon.breach._query_dehashed", side_effect=fail_dehashed), \
             patch("ghostmcp.recon.breach._query_leakcheck", new_callable=AsyncMock):
            result = await breach_search("test@example.com", mode="full")

        assert len(result.records) >= 1
        assert "dehashed" in result.providers_failed
        assert result.error is None  # Overall search succeeded

    @pytest.mark.asyncio
    async def test_all_providers_missing_keys(self):
        """With no API keys, all providers should report errors gracefully."""
        with patch.dict("os.environ", {}, clear=True):
            result = await breach_search("test@example.com", mode="full")

        # Should have failure entries for all providers
        assert len(result.providers_failed) > 0
        # Should not crash
        assert isinstance(result.records, list)

    @pytest.mark.asyncio
    async def test_search_urls_populated(self):
        with patch.dict("os.environ", {}, clear=True):
            result = await breach_search("test@example.com", mode="metadata_only")

        assert "haveibeenpwned" in result.search_urls
        assert "dehashed" in result.search_urls

    @pytest.mark.asyncio
    async def test_total_breaches_count(self):
        async def add_records(client, email, result):
            result.records.append(BreachRecord(
                source="hibp", breach_name="DB1", date="2020-01-01",
                data_classes=["Email addresses"],
            ))
            result.records.append(BreachRecord(
                source="hibp", breach_name="DB2", date="2021-01-01",
                data_classes=["Passwords"],
            ))

        with patch("ghostmcp.recon.breach._query_hibp", side_effect=add_records):
            result = await breach_search("test@example.com", mode="metadata_only")

        assert result.total_breaches == 2

    @pytest.mark.asyncio
    async def test_non_email_skips_hibp(self):
        """HIBP only supports email — phone queries should skip it."""
        with patch("ghostmcp.recon.breach._query_hibp", new_callable=AsyncMock) as mock_hibp:
            with patch.dict("os.environ", {}, clear=True):
                result = await breach_search("2145551234", query_type="phone", mode="metadata_only")

        mock_hibp.assert_not_called()
        assert "hibp" not in result.providers_checked

    @pytest.mark.asyncio
    async def test_mode_stored_in_result(self):
        with patch.dict("os.environ", {}, clear=True):
            result = await breach_search("test@example.com", mode="metadata_only")

        assert result.mode == "metadata_only"

    @pytest.mark.asyncio
    async def test_query_type_stored_in_result(self):
        with patch.dict("os.environ", {}, clear=True):
            result = await breach_search("test@example.com", query_type="email")

        assert result.query_type == "email"
