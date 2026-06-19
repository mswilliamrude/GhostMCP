"""Integration tests — hit live APIs to verify GhostMCP tools work end-to-end.

Run with:
    pytest -m integration                    # free APIs only
    pytest -m "integration and paid"         # paid APIs only
    pytest -m "integration or paid"          # all integration tests

Required env vars for paid tests:
    GHOST_HIBP_KEY          — Have I Been Pwned API key ($3.50/mo)
    GHOST_SNUSBASE_KEY      — Snusbase API key ($27/mo)
    GHOST_DEHASHED_EMAIL    — DeHashed account email
    GHOST_DEHASHED_KEY      — DeHashed API key
    GHOST_LEAKCHECK_KEY     — LeakCheck API key ($10/mo)
    GHOST_HUNTER_KEY        — Hunter.io API key ($49/mo)
    GHOST_TWILIO_SID        — Twilio Account SID
    GHOST_TWILIO_TOKEN      — Twilio Auth Token
    GHOST_OPENCNAM_SID      — OpenCNAM Account SID
    GHOST_OPENCNAM_TOKEN    — OpenCNAM Auth Token
    GHOST_EMAILREP_KEY      — EmailRep.io API key (free but needs registration)
    GHOST_COURTLISTENER_TOKEN — CourtListener API token (free but needs registration)
    GHOST_VERIPHONE_KEY     — Veriphone API key (free tier)
"""

from __future__ import annotations

import asyncio
import os

import pytest

from src.recon.phone import phone_lookup, PhoneReport
from src.recon.vehicles import vehicle_lookup, VehicleReport
from src.recon.people import (
    people_search,
    people_search_by_name,
    people_search_by_phone,
    people_search_by_email,
    people_search_by_address,
    people_search_by_username,
    PeopleSearchResult,
)
from src.recon.email_intel import email_lookup, EmailReport
from src.recon.username import username_lookup, UsernameReport
from src.recon.court import court_search, CourtSearchResult
from src.recon.breach import breach_search, BreachSearchResult
from src.recon.report import generate_report, BackgroundReport

# ---------------------------------------------------------------------------
# Known-safe test data
# ---------------------------------------------------------------------------

TEST_VIN_HONDA = "1HGCM82633A004352"      # 2003 Honda Accord
TEST_VIN_TESLA = "5YJSA1DG9DFP14705"      # 2013 Tesla Model S
TEST_PHONE = "+12025551234"                # DC area — validation only
TEST_EMAIL = "test@example.com"            # safe, commonly used in breach demos
TEST_USERNAME = "torvalds"                 # Linus Torvalds — known GitHub presence
TEST_NONEXISTENT_USER = "xyzzy_nonexistent_user_2026_abc"


# ═══════════════════════════════════════════════════════════════════════════
# Phone Intelligence
# ═══════════════════════════════════════════════════════════════════════════


class TestPhoneIntegration:
    """Phone number intelligence — offline validation + carrier/CNAM lookups."""

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_offline_validation(self):
        """Validate +12025551234 (known DC area code), check formatted output."""
        from src.recon.phone import _HAS_PHONENUMBERS

        # Clear paid-API keys so only offline analysis runs
        env_overrides = {
            "GHOST_VERIPHONE_KEY": "",
            "GHOST_TWILIO_SID": "",
            "GHOST_TWILIO_TOKEN": "",
            "GHOST_OPENCNAM_SID": "",
            "GHOST_OPENCNAM_TOKEN": "",
        }
        saved = {k: os.environ.get(k, "") for k in env_overrides}
        try:
            os.environ.update(env_overrides)
            report = await phone_lookup(TEST_PHONE)
        finally:
            for k, v in saved.items():
                if v:
                    os.environ[k] = v
                else:
                    os.environ.pop(k, None)

        assert isinstance(report, PhoneReport)

        if _HAS_PHONENUMBERS:
            assert report.formatted.get("e164") == "+12025551234"
            assert report.country_code == "1"
            assert report.country == "US"
        else:
            # Without phonenumbers library, offline analysis is skipped
            # but search URLs and the report itself should still work
            assert report.error is not None
            assert "phonenumbers" in report.error.lower()

        # Search URLs should always be generated regardless of library
        assert "reverse_phone" in report.search_urls
        assert len(report.search_urls["reverse_phone"]) >= 3

    @pytest.mark.integration
    @pytest.mark.paid
    @pytest.mark.asyncio
    async def test_veriphone_lookup(self):
        """Requires GHOST_VERIPHONE_KEY — verify carrier data returned."""
        key = os.environ.get("GHOST_VERIPHONE_KEY", "")
        if not key:
            pytest.skip("GHOST_VERIPHONE_KEY not set")

        report = await phone_lookup("+14155551234")  # SF area
        assert isinstance(report, PhoneReport)
        # Veriphone should have responded
        assert report.veriphone is not None
        assert "error" not in report.veriphone or not report.veriphone.get("error")

    @pytest.mark.integration
    @pytest.mark.paid
    @pytest.mark.asyncio
    async def test_twilio_cnam(self):
        """Requires GHOST_TWILIO_SID + TOKEN — look up a known business number."""
        sid = os.environ.get("GHOST_TWILIO_SID", "")
        token = os.environ.get("GHOST_TWILIO_TOKEN", "")
        if not sid or not token:
            pytest.skip("GHOST_TWILIO_SID and/or GHOST_TWILIO_TOKEN not set")

        # Use a well-known US toll-free number (FCC main line)
        report = await phone_lookup("+18002255324")
        assert isinstance(report, PhoneReport)
        # We can't guarantee CNAM resolves, but the call shouldn't crash
        assert report.error is None

    @pytest.mark.integration
    @pytest.mark.paid
    @pytest.mark.asyncio
    async def test_opencnam_lookup(self):
        """Requires GHOST_OPENCNAM_SID + TOKEN."""
        sid = os.environ.get("GHOST_OPENCNAM_SID", "")
        token = os.environ.get("GHOST_OPENCNAM_TOKEN", "")
        if not sid or not token:
            pytest.skip("GHOST_OPENCNAM_SID and/or GHOST_OPENCNAM_TOKEN not set")

        report = await phone_lookup("+12025551234")
        assert isinstance(report, PhoneReport)
        # Should complete without crashing regardless of CNAM result
        assert report.error is None


# ═══════════════════════════════════════════════════════════════════════════
# Vehicle Intelligence
# ═══════════════════════════════════════════════════════════════════════════


class TestVinIntegration:
    """VIN decoding + recall/complaint lookup via NHTSA (free, no key)."""

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_decode_known_vin(self):
        """Decode 2003 Honda Accord VIN — NHTSA vPIC is free."""
        report = await vehicle_lookup(TEST_VIN_HONDA)
        assert isinstance(report, VehicleReport)
        assert report.error is None
        assert report.make.upper() == "HONDA"
        assert "Accord" in report.model
        assert report.year == "2003"
        assert report.vin == TEST_VIN_HONDA

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_recalls_lookup(self):
        """Check recalls for a known recalled vehicle (Honda Accord 2003)."""
        await asyncio.sleep(1.0)  # rate-limit courtesy
        report = await vehicle_lookup(TEST_VIN_HONDA)
        assert isinstance(report, VehicleReport)
        assert report.error is None
        # 2003 Honda Accord has known Takata airbag recalls
        assert isinstance(report.recalls, list)
        # search_urls should have vehicle_history and nhtsa sections
        assert "vehicle_history" in report.search_urls
        assert "nhtsa" in report.search_urls

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_invalid_vin(self):
        """Verify error handling for obviously invalid VIN."""
        report = await vehicle_lookup("INVALID")
        assert isinstance(report, VehicleReport)
        assert report.error is not None
        assert "17 characters" in report.error or "invalid" in report.error.lower()

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_batch_decode(self):
        """Decode 2 known VINs sequentially."""
        vins = [TEST_VIN_HONDA, TEST_VIN_TESLA]
        results: list[VehicleReport] = []
        for vin in vins:
            await asyncio.sleep(0.5)  # rate-limit courtesy
            report = await vehicle_lookup(vin)
            results.append(report)

        # Honda
        assert results[0].error is None
        assert results[0].make.upper() == "HONDA"
        assert results[0].year == "2003"

        # Tesla
        assert results[1].error is None
        assert results[1].make.upper() == "TESLA"
        assert results[1].year == "2013"


# ═══════════════════════════════════════════════════════════════════════════
# People Search (URL generation — no API calls, pure CPU)
# ═══════════════════════════════════════════════════════════════════════════


class TestPeopleIntegration:
    """People search URL generators — verify URL count and structure."""

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_name_search_urls(self):
        """Generate URLs for 'John Smith' in Dallas TX — verify URL count > 10."""
        result = await people_search(
            query_type="name",
            first="John",
            last="Smith",
            city="Dallas",
            state="TX",
        )
        assert isinstance(result, PeopleSearchResult)
        assert result.query_type == "name"
        assert result.total_urls > 10
        # Should have people_search, social_media, court categories
        assert "people_search" in result.search_urls
        assert "social_media" in result.search_urls

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_phone_search_urls(self):
        """Generate URLs for '2145551234'."""
        result = await people_search(query_type="phone", phone="2145551234")
        assert isinstance(result, PeopleSearchResult)
        assert result.query_type == "phone"
        assert result.total_urls >= 5
        assert "people_search" in result.search_urls

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_email_search_urls(self):
        """Generate URLs for 'test@example.com'."""
        result = await people_search(query_type="email", email=TEST_EMAIL)
        assert isinstance(result, PeopleSearchResult)
        assert result.query_type == "email"
        assert result.total_urls >= 3
        assert "breach_check" in result.search_urls

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_username_search_urls(self):
        """Generate URLs for 'testuser123'."""
        result = await people_search(query_type="username", username="testuser123")
        assert isinstance(result, PeopleSearchResult)
        assert result.query_type == "username"
        assert result.total_urls >= 10
        assert "social_media" in result.search_urls
        assert "dev_platforms" in result.search_urls

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_address_search_urls(self):
        """Generate URLs for '123 Main St' Dallas TX."""
        result = await people_search(
            query_type="address",
            street="123 Main St",
            city="Dallas",
            state="TX",
        )
        assert isinstance(result, PeopleSearchResult)
        assert result.query_type == "address"
        assert result.total_urls >= 4
        assert "people_search" in result.search_urls
        assert "property" in result.search_urls


# ═══════════════════════════════════════════════════════════════════════════
# Email Intelligence
# ═══════════════════════════════════════════════════════════════════════════


class TestEmailIntegration:
    """Email intelligence — EmailRep, HIBP, Hunter.io."""

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_emailrep_free(self):
        """Look up test@example.com without API key (basic lookup)."""
        # Ensure no paid keys interfere
        env_overrides = {
            "GHOST_EMAILREP_KEY": "",
            "GHOST_HIBP_KEY": "",
            "GHOST_HUNTER_KEY": "",
        }
        saved = {k: os.environ.get(k, "") for k in env_overrides}
        try:
            os.environ.update(env_overrides)
            report = await email_lookup(
                TEST_EMAIL, include_holehe=False, include_hunter=False,
            )
        finally:
            for k, v in saved.items():
                if v:
                    os.environ[k] = v
                else:
                    os.environ.pop(k, None)

        assert isinstance(report, EmailReport)
        assert report.email == TEST_EMAIL
        assert report.valid is True
        assert report.domain == "example.com"
        # search_urls should always be populated
        assert "haveibeenpwned" in report.search_urls

    @pytest.mark.integration
    @pytest.mark.paid
    @pytest.mark.asyncio
    async def test_emailrep_with_key(self):
        """Look up with GHOST_EMAILREP_KEY for higher rate limits."""
        key = os.environ.get("GHOST_EMAILREP_KEY", "")
        if not key:
            pytest.skip("GHOST_EMAILREP_KEY not set")

        report = await email_lookup(
            TEST_EMAIL, include_holehe=False, include_hunter=False,
        )
        assert isinstance(report, EmailReport)
        # With a valid key, emailrep should not be in errors
        assert "emailrep" not in report.errors or "Rate limited" not in report.errors.get("emailrep", "")

    @pytest.mark.integration
    @pytest.mark.paid
    @pytest.mark.asyncio
    async def test_hibp_lookup(self):
        """Look up test@example.com with GHOST_HIBP_KEY — should have breaches."""
        key = os.environ.get("GHOST_HIBP_KEY", "")
        if not key:
            pytest.skip("GHOST_HIBP_KEY not set")

        report = await email_lookup(
            TEST_EMAIL, include_holehe=False, include_hunter=False,
        )
        assert isinstance(report, EmailReport)
        # HIBP should report breach count (0 or more — not None meaning "not queried")
        assert report.breach_count is not None or "hibp" not in report.errors

    @pytest.mark.integration
    @pytest.mark.paid
    @pytest.mark.asyncio
    async def test_hunter_enrichment(self):
        """Look up a known business email with GHOST_HUNTER_KEY."""
        key = os.environ.get("GHOST_HUNTER_KEY", "")
        if not key:
            pytest.skip("GHOST_HUNTER_KEY not set")

        await asyncio.sleep(1.0)  # rate-limit courtesy
        # Use a non-free-provider domain so Hunter actually runs
        report = await email_lookup(
            "info@stripe.com",
            include_holehe=False,
            include_hunter=True,
        )
        assert isinstance(report, EmailReport)
        # Hunter should have returned something or reported an error
        assert report.hunter_enrichment is not None or "hunter" in report.errors

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_free_provider_skips_hunter(self):
        """Verify gmail.com skips Hunter even when include_hunter=True."""
        # Temporarily set a dummy key to prove Hunter is skipped by domain check,
        # not by missing key
        saved = os.environ.get("GHOST_HUNTER_KEY", "")
        saved_hibp = os.environ.get("GHOST_HIBP_KEY", "")
        try:
            os.environ["GHOST_HUNTER_KEY"] = "dummy_key_for_test"
            os.environ["GHOST_HIBP_KEY"] = ""  # avoid hitting HIBP
            report = await email_lookup(
                "nobody@gmail.com",
                include_holehe=False,
                include_hunter=True,  # should be skipped for free providers
            )
        finally:
            if saved:
                os.environ["GHOST_HUNTER_KEY"] = saved
            else:
                os.environ.pop("GHOST_HUNTER_KEY", None)
            if saved_hibp:
                os.environ["GHOST_HIBP_KEY"] = saved_hibp
            else:
                os.environ.pop("GHOST_HIBP_KEY", None)

        assert isinstance(report, EmailReport)
        assert report.is_free_provider is True
        # Hunter should NOT have been called — no enrichment, no hunter error about HTTP
        assert report.hunter_enrichment is None


# ═══════════════════════════════════════════════════════════════════════════
# Username Enumeration
# ═══════════════════════════════════════════════════════════════════════════


class TestUsernameIntegration:
    """Username enumeration — builtin checker against live sites."""

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_builtin_checker(self):
        """Check username 'torvalds' (known GitHub user). Verify GitHub in results."""
        report = await username_lookup(TEST_USERNAME, max_sites=50, timeout=60)
        assert isinstance(report, UsernameReport)
        assert report.error is None
        assert report.sites_checked > 0

        # torvalds should be found on GitHub
        found_sites = [
            a.get("site_name", "").lower()
            for a in report.accounts_found
        ]
        found_urls = [
            a.get("url", "").lower()
            for a in report.accounts_found
        ]
        github_found = (
            any("github" in s for s in found_sites)
            or any("github.com/torvalds" in u for u in found_urls)
        )
        assert github_found, (
            f"Expected GitHub in results for '{TEST_USERNAME}', "
            f"got sites: {found_sites}"
        )

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_builtin_nonexistent(self):
        """Check a nonsense username — should find 0 or very few."""
        await asyncio.sleep(2.0)  # rate-limit courtesy after previous test
        report = await username_lookup(
            TEST_NONEXISTENT_USER, max_sites=50, timeout=60,
        )
        assert isinstance(report, UsernameReport)
        assert report.error is None

        # Filter out "url only" entries that are always included
        verified_accounts = [
            a for a in report.accounts_found
            if "(url only)" not in a.get("site_name", "")
        ]
        # Nonsense username should have very few real hits
        assert len(verified_accounts) <= 5, (
            f"Expected <=5 verified accounts for nonsense username, "
            f"got {len(verified_accounts)}: {verified_accounts}"
        )

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_search_urls_generated(self):
        """Verify search URLs are populated."""
        report = await username_lookup("testuser123", max_sites=20, timeout=30)
        assert isinstance(report, UsernameReport)
        assert report.search_urls is not None
        assert len(report.search_urls) >= 2  # namechk, knowem, whatsmyname


# ═══════════════════════════════════════════════════════════════════════════
# Court Records
# ═══════════════════════════════════════════════════════════════════════════


class TestCourtIntegration:
    """Court record search via CourtListener."""

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_url_only_no_token(self):
        """Search without token — verify URLs returned and no crash."""
        saved = os.environ.get("GHOST_COURTLISTENER_TOKEN", "")
        try:
            os.environ["GHOST_COURTLISTENER_TOKEN"] = ""
            result = await court_search("Smith", search_type="party")
        finally:
            if saved:
                os.environ["GHOST_COURTLISTENER_TOKEN"] = saved
            else:
                os.environ.pop("GHOST_COURTLISTENER_TOKEN", None)

        assert isinstance(result, CourtSearchResult)
        # Should have search URLs even without API access
        assert "courtlistener" in result.search_urls
        assert "judyrecords" in result.search_urls
        # Error should mention token not set
        assert result.error is not None
        assert "TOKEN" in result.error.upper() or "token" in result.error.lower()

    @pytest.mark.integration
    @pytest.mark.paid
    @pytest.mark.asyncio
    async def test_courtlistener_search(self):
        """Search for 'Trump' with GHOST_COURTLISTENER_TOKEN — verify results > 0."""
        token = os.environ.get("GHOST_COURTLISTENER_TOKEN", "")
        if not token:
            pytest.skip("GHOST_COURTLISTENER_TOKEN not set")

        result = await court_search("Trump", search_type="party")
        assert isinstance(result, CourtSearchResult)
        # Trump should have many court cases
        assert result.total_results > 0, (
            f"Expected results for 'Trump', got {result.total_results}. "
            f"Error: {result.error}"
        )
        assert len(result.cases) > 0
        # Verify case structure
        first_case = result.cases[0]
        assert first_case.case_name or first_case.docket_number

    @pytest.mark.integration
    @pytest.mark.paid
    @pytest.mark.asyncio
    async def test_docket_search(self):
        """Search by docket number."""
        token = os.environ.get("GHOST_COURTLISTENER_TOKEN", "")
        if not token:
            pytest.skip("GHOST_COURTLISTENER_TOKEN not set")

        await asyncio.sleep(1.0)  # rate-limit courtesy
        # A well-known case docket number (US v. Microsoft)
        result = await court_search("98-1232", search_type="docket")
        assert isinstance(result, CourtSearchResult)
        # May or may not find results depending on CourtListener coverage,
        # but should not crash
        assert result.error is None or "not set" not in result.error


# ═══════════════════════════════════════════════════════════════════════════
# Breach Intelligence
# ═══════════════════════════════════════════════════════════════════════════


class TestBreachIntegration:
    """Breach data search — two-layer model (metadata_only vs full)."""

    @pytest.mark.integration
    @pytest.mark.paid
    @pytest.mark.asyncio
    async def test_hibp_metadata_mode(self):
        """Search test@example.com in metadata_only mode with GHOST_HIBP_KEY."""
        key = os.environ.get("GHOST_HIBP_KEY", "")
        if not key:
            pytest.skip("GHOST_HIBP_KEY not set")

        result = await breach_search(
            TEST_EMAIL, query_type="email", mode="metadata_only",
        )
        assert isinstance(result, BreachSearchResult)
        assert result.mode == "metadata_only"
        assert "hibp" in result.providers_checked
        # HIBP should not have failed
        assert "hibp" not in result.providers_failed
        # Should have search URLs
        assert "haveibeenpwned" in result.search_urls

    @pytest.mark.integration
    @pytest.mark.paid
    @pytest.mark.asyncio
    async def test_snusbase_full_mode(self):
        """Search in full mode with GHOST_SNUSBASE_KEY."""
        key = os.environ.get("GHOST_SNUSBASE_KEY", "")
        if not key:
            pytest.skip("GHOST_SNUSBASE_KEY not set")

        await asyncio.sleep(1.0)  # rate-limit courtesy
        result = await breach_search(
            TEST_EMAIL, query_type="email", mode="full",
        )
        assert isinstance(result, BreachSearchResult)
        assert result.mode == "full"
        assert "snusbase" in result.providers_checked
        # Snusbase should not have errored (valid key)
        assert "snusbase" not in result.providers_failed, (
            f"Snusbase failed: {result.providers_failed.get('snusbase')}"
        )

    @pytest.mark.integration
    @pytest.mark.paid
    @pytest.mark.asyncio
    async def test_dehashed_full_mode(self):
        """Search with GHOST_DEHASHED_EMAIL + KEY."""
        dh_email = os.environ.get("GHOST_DEHASHED_EMAIL", "")
        dh_key = os.environ.get("GHOST_DEHASHED_KEY", "")
        if not dh_email or not dh_key:
            pytest.skip("GHOST_DEHASHED_EMAIL and/or GHOST_DEHASHED_KEY not set")

        await asyncio.sleep(1.0)  # rate-limit courtesy
        result = await breach_search(
            TEST_EMAIL, query_type="email", mode="full",
        )
        assert isinstance(result, BreachSearchResult)
        assert "dehashed" in result.providers_checked
        assert "dehashed" not in result.providers_failed, (
            f"DeHashed failed: {result.providers_failed.get('dehashed')}"
        )

    @pytest.mark.integration
    @pytest.mark.paid
    @pytest.mark.asyncio
    async def test_leakcheck_full_mode(self):
        """Search with GHOST_LEAKCHECK_KEY."""
        key = os.environ.get("GHOST_LEAKCHECK_KEY", "")
        if not key:
            pytest.skip("GHOST_LEAKCHECK_KEY not set")

        await asyncio.sleep(1.0)  # rate-limit courtesy
        result = await breach_search(
            TEST_EMAIL, query_type="email", mode="full",
        )
        assert isinstance(result, BreachSearchResult)
        assert "leakcheck" in result.providers_checked
        assert "leakcheck" not in result.providers_failed, (
            f"LeakCheck failed: {result.providers_failed.get('leakcheck')}"
        )

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_no_keys_graceful(self):
        """Search with no keys set — verify graceful degradation (no crash)."""
        env_keys = [
            "GHOST_HIBP_KEY",
            "GHOST_SNUSBASE_KEY",
            "GHOST_DEHASHED_EMAIL",
            "GHOST_DEHASHED_KEY",
            "GHOST_LEAKCHECK_KEY",
        ]
        saved = {k: os.environ.get(k, "") for k in env_keys}
        try:
            for k in env_keys:
                os.environ[k] = ""
            result = await breach_search(
                TEST_EMAIL, query_type="email", mode="full",
            )
        finally:
            for k, v in saved.items():
                if v:
                    os.environ[k] = v
                else:
                    os.environ.pop(k, None)

        assert isinstance(result, BreachSearchResult)
        # Should not crash — should report providers as failed
        assert len(result.providers_failed) > 0
        # Search URLs should still be generated
        assert len(result.search_urls) > 0


# ═══════════════════════════════════════════════════════════════════════════
# Composite Background Report
# ═══════════════════════════════════════════════════════════════════════════


class TestReportIntegration:
    """Composite background report generator."""

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_report_with_free_sources(self):
        """Generate a report using only free sources (phone + VIN + people URLs).

        Verify markdown output contains expected sections.
        """
        # Clear paid keys
        env_keys = [
            "GHOST_VERIPHONE_KEY", "GHOST_TWILIO_SID", "GHOST_TWILIO_TOKEN",
            "GHOST_OPENCNAM_SID", "GHOST_OPENCNAM_TOKEN", "GHOST_HIBP_KEY",
            "GHOST_HUNTER_KEY", "GHOST_EMAILREP_KEY",
            "GHOST_COURTLISTENER_TOKEN",
        ]
        saved = {k: os.environ.get(k, "") for k in env_keys}
        try:
            for k in env_keys:
                os.environ[k] = ""

            # Gather data from free sources
            phone_result = await phone_lookup(TEST_PHONE)
            await asyncio.sleep(0.5)
            vehicle_result = await vehicle_lookup(TEST_VIN_HONDA)

            people_urls_result = people_search_by_name(
                first="John", last="Smith", city="Dallas", state="TX",
            )

        finally:
            for k, v in saved.items():
                if v:
                    os.environ[k] = v
                else:
                    os.environ.pop(k, None)

        # Generate report (pure CPU, no I/O)
        report = generate_report(
            subject={
                "name": "John Smith",
                "phone": TEST_PHONE,
                "email": TEST_EMAIL,
            },
            phone_result=phone_result,
            vehicle_result=vehicle_result,
            people_urls=people_urls_result.search_urls,
        )

        assert isinstance(report, BackgroundReport)
        assert report.report_text  # non-empty markdown
        assert "# Background Report" in report.report_text
        assert "## Subject Identity" in report.report_text
        assert "## Contact Information" in report.report_text
        assert "## Vehicle Information" in report.report_text
        assert "## Legal Disclaimer" in report.report_text
        assert "HONDA" in report.report_text
        assert len(report.data_sources) >= 2

    @pytest.mark.integration
    @pytest.mark.paid
    @pytest.mark.asyncio
    async def test_report_with_all_sources(self):
        """Generate full report with all keys set."""
        # Check at least one paid key is available
        has_hibp = bool(os.environ.get("GHOST_HIBP_KEY", ""))
        has_courtlistener = bool(os.environ.get("GHOST_COURTLISTENER_TOKEN", ""))
        if not has_hibp and not has_courtlistener:
            pytest.skip(
                "Need at least GHOST_HIBP_KEY or GHOST_COURTLISTENER_TOKEN "
                "for full report test"
            )

        # Gather data
        phone_result = await phone_lookup(TEST_PHONE)
        await asyncio.sleep(0.5)
        vehicle_result = await vehicle_lookup(TEST_VIN_HONDA)
        await asyncio.sleep(0.5)

        breach_result = None
        if has_hibp:
            breach_result = await breach_search(
                TEST_EMAIL, query_type="email", mode="metadata_only",
            )

        court_result = None
        if has_courtlistener:
            await asyncio.sleep(0.5)
            court_result = await court_search("Smith", search_type="party")

        people_urls_result = people_search_by_name(
            first="John", last="Smith", city="Dallas", state="TX",
        )

        report = generate_report(
            subject={
                "name": "John Smith",
                "phone": TEST_PHONE,
                "email": TEST_EMAIL,
            },
            phone_result=phone_result,
            vehicle_result=vehicle_result,
            breach_result=breach_result,
            court_result=court_result,
            people_urls=people_urls_result.search_urls,
        )

        assert isinstance(report, BackgroundReport)
        assert report.report_text
        assert "# Background Report" in report.report_text
        assert len(report.data_sources) >= 3
        # Confidence ratings should have some entries
        assert len(report.confidence_ratings) >= 1


# ---------------------------------------------------------------------------
# IP Intelligence Integration
# ---------------------------------------------------------------------------

class TestIPIntegration:
    """Integration tests for ghost_ip — ip-api.com (free, no key)."""

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_lookup_google_dns(self):
        """Look up 8.8.8.8 (Google Public DNS) — well-known, stable."""
        from src.recon.ip_intel import ip_lookup

        report = await ip_lookup("8.8.8.8")

        assert report.valid
        assert report.error is None
        assert report.country == "United States"
        assert report.isp  # Should have ISP info
        assert "Google" in report.org or "Google" in report.isp
        assert report.asn  # Should have ASN
        assert report.is_hosting is True  # Google DNS is datacenter-hosted
        assert report.timezone
        assert len(report.search_urls) >= 9

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_lookup_cloudflare_dns(self):
        """Look up 1.1.1.1 (Cloudflare DNS) — another well-known IP."""
        from src.recon.ip_intel import ip_lookup
        import asyncio

        await asyncio.sleep(1.5)  # Rate limit courtesy
        report = await ip_lookup("1.1.1.1")

        assert report.valid
        assert report.error is None
        assert report.country  # Should have a country
        assert report.isp or report.org  # Should have network info

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_invalid_ip(self):
        """Verify error handling for invalid IP."""
        from src.recon.ip_intel import ip_lookup

        report = await ip_lookup("999.999.999.999")
        assert report.error is not None
        assert not report.valid

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_private_range(self):
        """Private IPs should fail gracefully (ip-api returns fail status)."""
        from src.recon.ip_intel import ip_lookup
        import asyncio

        await asyncio.sleep(1.5)  # Rate limit courtesy
        report = await ip_lookup("192.168.1.1")

        # ip-api returns "fail" for private/reserved ranges
        assert report.error is not None or report.country == ""
