"""Tests for email intelligence — reputation, breach lookup, enrichment, Holehe."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.recon.email_intel import (
    EmailReport,
    FREE_PROVIDERS,
    _basic_validate,
    _build_search_urls,
    _query_emailrep,
    _query_hibp,
    _query_holehe,
    _query_hunter,
    email_lookup,
)


# ---------------------------------------------------------------------------
# Sample API responses
# ---------------------------------------------------------------------------

SAMPLE_EMAILREP_RESPONSE = {
    "email": "test@example.com",
    "reputation": "high",
    "suspicious": False,
    "references": 5,
    "details": {
        "credentials_leaked": True,
        "data_breach": True,
        "profiles": ["github", "twitter"],
    },
}

SAMPLE_HIBP_RESPONSE = [
    {
        "Name": "Adobe",
        "Title": "Adobe",
        "Domain": "adobe.com",
        "BreachDate": "2013-10-04",
        "AddedDate": "2013-12-04",
        "ModifiedDate": "2022-05-15",
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

SAMPLE_HUNTER_RESPONSE = {
    "data": {
        "first_name": "John",
        "last_name": "Doe",
        "position": "Software Engineer",
        "company": "Acme Corp",
        "linkedin_url": "https://linkedin.com/in/johndoe",
        "twitter": "johndoe",
        "phone_number": "+15551234567",
    },
}


# ---------------------------------------------------------------------------
# Free provider detection
# ---------------------------------------------------------------------------


class TestFreeProviderDetection:
    """Tests for FREE_PROVIDERS set and is_free_provider logic."""

    def test_gmail_is_free(self):
        assert "gmail.com" in FREE_PROVIDERS

    def test_yahoo_is_free(self):
        assert "yahoo.com" in FREE_PROVIDERS

    def test_hotmail_is_free(self):
        assert "hotmail.com" in FREE_PROVIDERS

    def test_protonmail_is_free(self):
        assert "protonmail.com" in FREE_PROVIDERS

    def test_corporate_not_free(self):
        assert "acmecorp.com" not in FREE_PROVIDERS

    def test_custom_domain_not_free(self):
        assert "mycompany.io" not in FREE_PROVIDERS

    def test_outlook_is_free(self):
        assert "outlook.com" in FREE_PROVIDERS

    def test_icloud_is_free(self):
        assert "icloud.com" in FREE_PROVIDERS


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


class TestBasicValidate:
    """Tests for _basic_validate()."""

    def test_valid_email(self):
        valid, domain = _basic_validate("user@example.com")
        assert valid is True
        assert domain == "example.com"

    def test_strips_whitespace(self):
        valid, domain = _basic_validate("  user@example.com  ")
        assert valid is True
        assert domain == "example.com"

    def test_lowercased(self):
        valid, domain = _basic_validate("User@Example.COM")
        assert valid is True
        assert domain == "example.com"

    def test_no_at_sign(self):
        valid, domain = _basic_validate("not-an-email")
        assert valid is False

    def test_empty_local(self):
        valid, domain = _basic_validate("@example.com")
        assert valid is False

    def test_empty_domain(self):
        valid, domain = _basic_validate("user@")
        assert valid is False

    def test_no_dot_in_domain(self):
        valid, domain = _basic_validate("user@localhost")
        assert valid is False

    def test_empty_string(self):
        valid, domain = _basic_validate("")
        assert valid is False


# ---------------------------------------------------------------------------
# Search URL generation
# ---------------------------------------------------------------------------


class TestBuildSearchUrls:
    """Tests for _build_search_urls()."""

    def test_returns_all_expected_keys(self):
        urls = _build_search_urls("test@example.com")
        assert "haveibeenpwned" in urls
        assert "emailrep" in urls
        assert "hunter" in urls
        assert "epieos" in urls

    def test_urls_contain_email(self):
        urls = _build_search_urls("test@example.com")
        for key, url in urls.items():
            assert "test" in url or "example" in url

    def test_special_chars_encoded(self):
        urls = _build_search_urls("user+tag@example.com")
        # '+' should be percent-encoded in the URL
        assert "user%2Btag" in urls["haveibeenpwned"]


# ---------------------------------------------------------------------------
# EmailRep.io tests
# ---------------------------------------------------------------------------


class TestQueryEmailrep:
    """Tests for _query_emailrep()."""

    @pytest.mark.asyncio
    async def test_successful_lookup(self):
        report = EmailReport(email="test@example.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_EMAILREP_RESPONSE

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                await _query_emailrep(client, "test@example.com", report)

        assert report.reputation is not None
        assert report.reputation["score"] == "high"
        assert report.reputation["suspicious"] is False
        assert report.reputation["references"] == 5

    @pytest.mark.asyncio
    async def test_no_api_key_still_works(self):
        """EmailRep works without an API key (lower rate limits)."""
        report = EmailReport(email="test@example.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_EMAILREP_RESPONSE

        with patch.dict("os.environ", {}, clear=False), \
             patch("os.environ.get", return_value=""), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                await _query_emailrep(client, "test@example.com", report)

        # Should still succeed — EmailRep allows unauthenticated requests
        assert report.reputation is not None

    @pytest.mark.asyncio
    async def test_rate_limited(self):
        report = EmailReport(email="test@example.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 429

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                await _query_emailrep(client, "test@example.com", report)

        assert "emailrep" in report.errors
        assert "Rate limited" in report.errors["emailrep"]

    @pytest.mark.asyncio
    async def test_http_error(self):
        report = EmailReport(email="test@example.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 500

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                await _query_emailrep(client, "test@example.com", report)

        assert "emailrep" in report.errors
        assert "500" in report.errors["emailrep"]

    @pytest.mark.asyncio
    async def test_timeout(self):
        import httpx

        report = EmailReport(email="test@example.com")

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.TimeoutException("timed out")
            async with httpx.AsyncClient() as client:
                await _query_emailrep(client, "test@example.com", report)

        assert "emailrep" in report.errors


# ---------------------------------------------------------------------------
# HIBP tests
# ---------------------------------------------------------------------------


class TestQueryHibp:
    """Tests for _query_hibp()."""

    @pytest.mark.asyncio
    async def test_successful_breach_lookup(self):
        report = EmailReport(email="test@example.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_HIBP_RESPONSE

        with patch.dict("os.environ", {"GHOST_HIBP_KEY": "test-key"}), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                await _query_hibp(client, "test@example.com", report)

        assert report.breach_count == 2
        assert "Adobe" in report.breaches
        assert "LinkedIn" in report.breaches

    @pytest.mark.asyncio
    async def test_no_breaches_found_404(self):
        report = EmailReport(email="clean@example.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch.dict("os.environ", {"GHOST_HIBP_KEY": "test-key"}), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                await _query_hibp(client, "clean@example.com", report)

        assert report.breach_count == 0
        assert report.breaches == []
        assert "hibp" not in report.errors

    @pytest.mark.asyncio
    async def test_bad_api_key_401(self):
        report = EmailReport(email="test@example.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 401

        with patch.dict("os.environ", {"GHOST_HIBP_KEY": "bad-key"}), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                await _query_hibp(client, "test@example.com", report)

        assert "hibp" in report.errors
        assert "Invalid" in report.errors["hibp"]

    @pytest.mark.asyncio
    async def test_no_api_key_skips(self):
        report = EmailReport(email="test@example.com")

        with patch.dict("os.environ", {}, clear=True):
            async with __import__("httpx").AsyncClient() as client:
                await _query_hibp(client, "test@example.com", report)

        assert "hibp" in report.errors
        assert "GHOST_HIBP_KEY" in report.errors["hibp"]

    @pytest.mark.asyncio
    async def test_rate_limited_429(self):
        report = EmailReport(email="test@example.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 429

        with patch.dict("os.environ", {"GHOST_HIBP_KEY": "test-key"}), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                await _query_hibp(client, "test@example.com", report)

        assert "hibp" in report.errors
        assert "rate limit" in report.errors["hibp"].lower()


# ---------------------------------------------------------------------------
# Hunter.io tests
# ---------------------------------------------------------------------------


class TestQueryHunter:
    """Tests for _query_hunter()."""

    @pytest.mark.asyncio
    async def test_successful_enrichment(self):
        report = EmailReport(email="john@acmecorp.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_HUNTER_RESPONSE

        with patch.dict("os.environ", {"GHOST_HUNTER_KEY": "hunter-key"}), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                await _query_hunter(client, "john@acmecorp.com", report)

        assert report.hunter_enrichment is not None
        assert report.hunter_enrichment["first_name"] == "John"
        assert report.hunter_enrichment["last_name"] == "Doe"
        assert report.hunter_enrichment["position"] == "Software Engineer"
        assert report.hunter_enrichment["company"] == "Acme Corp"

    @pytest.mark.asyncio
    async def test_no_api_key_skips(self):
        report = EmailReport(email="test@acmecorp.com")

        with patch.dict("os.environ", {}, clear=True):
            async with __import__("httpx").AsyncClient() as client:
                await _query_hunter(client, "test@acmecorp.com", report)

        assert report.hunter_enrichment is None
        assert "hunter" in report.errors
        assert "GHOST_HUNTER_KEY" in report.errors["hunter"]

    @pytest.mark.asyncio
    async def test_invalid_key_401(self):
        report = EmailReport(email="test@acmecorp.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 401

        with patch.dict("os.environ", {"GHOST_HUNTER_KEY": "bad-key"}), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                await _query_hunter(client, "test@acmecorp.com", report)

        assert "hunter" in report.errors
        assert "Invalid" in report.errors["hunter"]

    @pytest.mark.asyncio
    async def test_rate_limited_429(self):
        report = EmailReport(email="test@acmecorp.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 429

        with patch.dict("os.environ", {"GHOST_HUNTER_KEY": "hunter-key"}), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            async with __import__("httpx").AsyncClient() as client:
                await _query_hunter(client, "test@acmecorp.com", report)

        assert "hunter" in report.errors
        assert "rate limit" in report.errors["hunter"].lower()


# ---------------------------------------------------------------------------
# Holehe subprocess tests
# ---------------------------------------------------------------------------


class TestQueryHolehe:
    """Tests for _query_holehe()."""

    @pytest.mark.asyncio
    async def test_successful_scan(self):
        report = EmailReport(email="test@example.com")

        mock_proc = AsyncMock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(
            return_value=(
                b"[+] github.com\n[+] twitter.com\n[-] instagram.com\n[+] linkedin.com\n",
                b"",
            )
        )

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = mock_proc
            await _query_holehe("test@example.com", report)

        assert "github.com" in report.accounts_found
        assert "twitter.com" in report.accounts_found
        assert "linkedin.com" in report.accounts_found
        assert "instagram.com" not in report.accounts_found

    @pytest.mark.asyncio
    async def test_not_installed(self):
        """FileNotFoundError → graceful skip with error message."""
        report = EmailReport(email="test@example.com")

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_exec.side_effect = FileNotFoundError("holehe not found")
            await _query_holehe("test@example.com", report)

        assert "holehe" in report.errors
        assert "not installed" in report.errors["holehe"]
        assert report.accounts_found == []

    @pytest.mark.asyncio
    async def test_nonzero_exit(self):
        report = EmailReport(email="test@example.com")

        mock_proc = AsyncMock()
        mock_proc.returncode = 1
        mock_proc.communicate = AsyncMock(return_value=(b"", b"error output"))

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = mock_proc
            await _query_holehe("test@example.com", report)

        assert "holehe" in report.errors
        assert "Exit code" in report.errors["holehe"]

    @pytest.mark.asyncio
    async def test_timeout(self):
        report = EmailReport(email="test@example.com")

        mock_proc = AsyncMock()
        mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_proc.kill = AsyncMock()
        mock_proc.wait = AsyncMock()

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
            mock_exec.return_value = mock_proc
            # Patch wait_for to raise TimeoutError too
            with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
                await _query_holehe("test@example.com", report)

        assert "holehe" in report.errors
        assert "Timed out" in report.errors["holehe"]


# ---------------------------------------------------------------------------
# email_lookup integration tests
# ---------------------------------------------------------------------------


class TestEmailLookup:
    """Tests for the email_lookup() public API."""

    @pytest.mark.asyncio
    async def test_invalid_email_returns_early(self):
        report = await email_lookup("not-an-email")
        assert report.valid is False
        assert "validation" in report.errors

    @pytest.mark.asyncio
    async def test_sets_domain_and_free_provider(self):
        with patch("src.recon.email_intel._query_emailrep", new_callable=AsyncMock), \
             patch("src.recon.email_intel._query_hibp", new_callable=AsyncMock), \
             patch("src.recon.email_intel._query_holehe", new_callable=AsyncMock):
            report = await email_lookup("user@gmail.com", include_holehe=True)

        assert report.domain == "gmail.com"
        assert report.is_free_provider is True

    @pytest.mark.asyncio
    async def test_corporate_domain_not_free(self):
        with patch("src.recon.email_intel._query_emailrep", new_callable=AsyncMock), \
             patch("src.recon.email_intel._query_hibp", new_callable=AsyncMock), \
             patch("src.recon.email_intel._query_holehe", new_callable=AsyncMock):
            report = await email_lookup("ceo@acmecorp.com", include_holehe=True)

        assert report.is_free_provider is False

    @pytest.mark.asyncio
    async def test_hunter_skipped_for_free_provider(self):
        """Hunter.io should NOT be called for gmail.com even with include_hunter=True."""
        with patch("src.recon.email_intel._query_emailrep", new_callable=AsyncMock) as mock_rep, \
             patch("src.recon.email_intel._query_hibp", new_callable=AsyncMock) as mock_hibp, \
             patch("src.recon.email_intel._query_hunter", new_callable=AsyncMock) as mock_hunter, \
             patch("src.recon.email_intel._query_holehe", new_callable=AsyncMock):
            report = await email_lookup(
                "user@gmail.com", include_hunter=True, include_holehe=True,
            )

        mock_hunter.assert_not_called()

    @pytest.mark.asyncio
    async def test_hunter_called_for_corporate(self):
        """Hunter.io should be called for corporate domains when include_hunter=True."""
        with patch("src.recon.email_intel._query_emailrep", new_callable=AsyncMock) as mock_rep, \
             patch("src.recon.email_intel._query_hibp", new_callable=AsyncMock) as mock_hibp, \
             patch("src.recon.email_intel._query_hunter", new_callable=AsyncMock) as mock_hunter, \
             patch("src.recon.email_intel._query_holehe", new_callable=AsyncMock):
            report = await email_lookup(
                "ceo@acmecorp.com", include_hunter=True, include_holehe=True,
            )

        mock_hunter.assert_called_once()

    @pytest.mark.asyncio
    async def test_search_urls_populated(self):
        with patch("src.recon.email_intel._query_emailrep", new_callable=AsyncMock), \
             patch("src.recon.email_intel._query_hibp", new_callable=AsyncMock), \
             patch("src.recon.email_intel._query_holehe", new_callable=AsyncMock):
            report = await email_lookup("user@example.com", include_holehe=True)

        assert "haveibeenpwned" in report.search_urls
        assert "emailrep" in report.search_urls

    @pytest.mark.asyncio
    async def test_no_api_keys_graceful(self):
        """With no API keys at all, should still return a report with errors."""
        with patch.dict("os.environ", {}, clear=True):
            report = await email_lookup(
                "test@example.com", include_holehe=False, include_hunter=False,
            )

        # EmailRep might work (no key required) or fail — either way no crash.
        # HIBP should report missing key.
        assert report.valid is True
        assert report.email == "test@example.com"

    @pytest.mark.asyncio
    async def test_email_lowercased(self):
        with patch("src.recon.email_intel._query_emailrep", new_callable=AsyncMock), \
             patch("src.recon.email_intel._query_hibp", new_callable=AsyncMock), \
             patch("src.recon.email_intel._query_holehe", new_callable=AsyncMock):
            report = await email_lookup("USER@EXAMPLE.COM", include_holehe=True)

        assert report.email == "user@example.com"
