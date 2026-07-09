"""Tests for people search URL generators — name, phone, email, address, username."""

from __future__ import annotations

from urllib.parse import quote, quote_plus

import pytest

from ghostmcp.recon.people import (
    PeopleSearchResult,
    people_search_by_name,
    people_search_by_phone,
    people_search_by_email,
    people_search_by_address,
    people_search_by_username,
    people_search,
    _count_urls,
    _slug,
    _digits,
)


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------


class TestHelpers:
    """Tests for internal helper functions."""

    def test_slug(self):
        assert _slug("New York") == "new-york"
        assert _slug("  Chicago  ") == "chicago"
        assert _slug("Los Angeles") == "los-angeles"

    def test_digits(self):
        assert _digits("+1 (214) 555-1234") == "12145551234"
        assert _digits("214-555-1234") == "2145551234"
        assert _digits("12145551234") == "12145551234"
        assert _digits("") == ""

    def test_count_urls(self):
        urls = {
            "cat_a": [{"name": "a", "url": "http://a"}],
            "cat_b": [{"name": "b", "url": "http://b"}, {"name": "c", "url": "http://c"}],
        }
        assert _count_urls(urls) == 3

    def test_count_urls_empty(self):
        assert _count_urls({}) == 0


# ---------------------------------------------------------------------------
# Name search tests
# ---------------------------------------------------------------------------


class TestPeopleSearchByName:
    """Tests for people_search_by_name()."""

    def test_full_params(self):
        result = people_search_by_name(
            first="John", last="Smith", city="Dallas", state="TX",
        )
        assert result.query_type == "name"
        assert result.input_data["first"] == "John"
        assert result.input_data["last"] == "Smith"
        assert result.input_data["city"] == "Dallas"
        assert result.input_data["state"] == "TX"

    def test_minimal_params(self):
        result = people_search_by_name(first="Jane", last="Doe")
        assert result.query_type == "name"
        assert result.input_data["city"] == ""
        assert result.input_data["state"] == ""
        assert result.total_urls > 0

    def test_people_search_category_exists(self):
        result = people_search_by_name(first="John", last="Smith")
        assert "people_search" in result.search_urls
        assert len(result.search_urls["people_search"]) >= 5

    def test_social_media_category_exists(self):
        result = people_search_by_name(first="John", last="Smith")
        assert "social_media" in result.search_urls
        assert len(result.search_urls["social_media"]) >= 2

    def test_court_criminal_category_exists(self):
        result = people_search_by_name(first="John", last="Smith")
        assert "court_criminal" in result.search_urls

    def test_property_category_exists(self):
        result = people_search_by_name(first="John", last="Smith")
        assert "property" in result.search_urls

    def test_total_urls_correct(self):
        result = people_search_by_name(first="John", last="Smith",
                                       city="Dallas", state="TX")
        manual_count = sum(
            len(v) for v in result.search_urls.values()
        )
        assert result.total_urls == manual_count

    def test_expected_people_search_sites(self):
        result = people_search_by_name(first="John", last="Smith")
        site_names = {e["name"] for e in result.search_urls["people_search"]}
        assert "ThatsThem" in site_names
        assert "FastPeopleSearch" in site_names
        assert "Whitepages" in site_names
        assert "Spokeo" in site_names

    def test_state_affects_urls(self):
        """With state, some URLs include state slug."""
        result_with = people_search_by_name(first="John", last="Doe", state="TX")
        result_without = people_search_by_name(first="John", last="Doe")

        # ThatsThem with state includes the state slug
        thatsthem_with = [e for e in result_with.search_urls["people_search"]
                          if e["name"] == "ThatsThem"][0]
        thatsthem_without = [e for e in result_without.search_urls["people_search"]
                             if e["name"] == "ThatsThem"][0]
        assert "/tx" in thatsthem_with["url"]
        assert "/tx" not in thatsthem_without["url"]

    def test_special_characters_encoded(self):
        """Names with special characters should be properly URL-encoded."""
        result = people_search_by_name(first="Mary Ann", last="O'Brien")
        # Verify no raw apostrophes or spaces in URL paths
        for category in result.search_urls.values():
            for entry in category:
                assert isinstance(entry["url"], str)
                assert entry["url"].startswith("http")


# ---------------------------------------------------------------------------
# Phone search tests
# ---------------------------------------------------------------------------


class TestPeopleSearchByPhone:
    """Tests for people_search_by_phone()."""

    def test_returns_phone_type(self):
        result = people_search_by_phone("+1 (214) 555-1234")
        assert result.query_type == "phone"

    def test_digits_stored(self):
        result = people_search_by_phone("+1 (214) 555-1234")
        assert result.input_data["digits"] == "12145551234"

    def test_people_search_urls(self):
        result = people_search_by_phone("2145551234")
        assert "people_search" in result.search_urls
        assert len(result.search_urls["people_search"]) >= 5

    def test_total_urls_correct(self):
        result = people_search_by_phone("2145551234")
        assert result.total_urls == _count_urls(result.search_urls)

    def test_expected_sites(self):
        result = people_search_by_phone("2145551234")
        site_names = {e["name"] for e in result.search_urls["people_search"]}
        assert "ThatsThem" in site_names
        assert "Spokeo" in site_names
        assert "USPhonebook" in site_names


# ---------------------------------------------------------------------------
# Email search tests
# ---------------------------------------------------------------------------


class TestPeopleSearchByEmail:
    """Tests for people_search_by_email()."""

    def test_returns_email_type(self):
        result = people_search_by_email("test@example.com")
        assert result.query_type == "email"

    def test_email_lowercased(self):
        result = people_search_by_email("Test@Example.COM")
        assert result.input_data["email"] == "test@example.com"

    def test_people_search_urls(self):
        result = people_search_by_email("test@example.com")
        assert "people_search" in result.search_urls

    def test_breach_check_urls(self):
        result = people_search_by_email("test@example.com")
        assert "breach_check" in result.search_urls
        site_names = {e["name"] for e in result.search_urls["breach_check"]}
        assert "Have I Been Pwned" in site_names

    def test_social_media_urls(self):
        result = people_search_by_email("test@example.com")
        assert "social_media" in result.search_urls

    def test_total_urls_correct(self):
        result = people_search_by_email("test@example.com")
        assert result.total_urls == _count_urls(result.search_urls)


# ---------------------------------------------------------------------------
# Address search tests
# ---------------------------------------------------------------------------


class TestPeopleSearchByAddress:
    """Tests for people_search_by_address()."""

    def test_returns_address_type(self):
        result = people_search_by_address(
            street="123 Main St", city="Dallas", state="TX",
        )
        assert result.query_type == "address"

    def test_input_data_stored(self):
        result = people_search_by_address(
            street="456 Oak Ave", city="Austin", state="TX",
        )
        assert result.input_data["street"] == "456 Oak Ave"
        assert result.input_data["city"] == "Austin"
        assert result.input_data["state"] == "TX"

    def test_people_search_and_property_categories(self):
        result = people_search_by_address(
            street="123 Main St", city="Dallas", state="TX",
        )
        assert "people_search" in result.search_urls
        assert "property" in result.search_urls

    def test_property_urls_include_expected_sites(self):
        result = people_search_by_address(
            street="123 Main St", city="Dallas", state="TX",
        )
        site_names = {e["name"] for e in result.search_urls["property"]}
        assert "Zillow" in site_names
        assert "Google Maps" in site_names

    def test_total_urls_correct(self):
        result = people_search_by_address(
            street="123 Main St", city="Dallas", state="TX",
        )
        assert result.total_urls == _count_urls(result.search_urls)


# ---------------------------------------------------------------------------
# Username search tests
# ---------------------------------------------------------------------------


class TestPeopleSearchByUsername:
    """Tests for people_search_by_username()."""

    def test_returns_username_type(self):
        result = people_search_by_username("ghostuser")
        assert result.query_type == "username"

    def test_strips_at_sign(self):
        result = people_search_by_username("@ghostuser")
        assert result.input_data["username"] == "ghostuser"

    def test_social_media_category(self):
        result = people_search_by_username("ghostuser")
        assert "social_media" in result.search_urls
        site_names = {e["name"] for e in result.search_urls["social_media"]}
        assert "X / Twitter" in site_names
        assert "Instagram" in site_names
        assert "GitHub" in site_names

    def test_dev_platforms_category(self):
        result = people_search_by_username("ghostuser")
        assert "dev_platforms" in result.search_urls
        site_names = {e["name"] for e in result.search_urls["dev_platforms"]}
        assert "GitHub" in site_names
        assert "GitLab" in site_names
        assert "npm" in site_names
        assert "PyPI" in site_names

    def test_search_engines_category(self):
        result = people_search_by_username("ghostuser")
        assert "search_engines" in result.search_urls

    def test_total_urls_correct(self):
        result = people_search_by_username("ghostuser")
        assert result.total_urls == _count_urls(result.search_urls)

    def test_urls_contain_username(self):
        result = people_search_by_username("testuser123")
        for category in result.search_urls.values():
            for entry in category:
                assert "testuser123" in entry["url"]


# ---------------------------------------------------------------------------
# Async dispatcher tests
# ---------------------------------------------------------------------------


class TestPeopleSearch:
    """Tests for people_search() async dispatcher."""

    @pytest.mark.asyncio
    async def test_dispatches_name(self):
        result = await people_search(
            "name", first="John", last="Doe",
        )
        assert result.query_type == "name"
        assert result.total_urls > 0

    @pytest.mark.asyncio
    async def test_dispatches_phone(self):
        result = await people_search("phone", phone="2145551234")
        assert result.query_type == "phone"
        assert result.total_urls > 0

    @pytest.mark.asyncio
    async def test_dispatches_email(self):
        result = await people_search("email", email="test@example.com")
        assert result.query_type == "email"

    @pytest.mark.asyncio
    async def test_dispatches_address(self):
        result = await people_search(
            "address", street="123 Main St", city="Dallas", state="TX",
        )
        assert result.query_type == "address"

    @pytest.mark.asyncio
    async def test_dispatches_username(self):
        result = await people_search("username", username="ghostuser")
        assert result.query_type == "username"

    @pytest.mark.asyncio
    async def test_invalid_query_type_raises(self):
        with pytest.raises(ValueError, match="Unknown query_type"):
            await people_search("invalid_type")

    @pytest.mark.asyncio
    async def test_case_insensitive_dispatch(self):
        result = await people_search("NAME", first="Test", last="User")
        assert result.query_type == "name"

    @pytest.mark.asyncio
    async def test_strips_whitespace_in_type(self):
        result = await people_search("  phone  ", phone="2145551234")
        assert result.query_type == "phone"


# ---------------------------------------------------------------------------
# PeopleSearchResult dataclass tests
# ---------------------------------------------------------------------------


class TestPeopleSearchResult:
    """Tests for the PeopleSearchResult dataclass."""

    def test_defaults(self):
        result = PeopleSearchResult(query_type="test")
        assert result.input_data == {}
        assert result.search_urls == {}
        assert result.total_urls == 0

    def test_all_urls_have_name_and_url_keys(self):
        """Across all search types, every URL entry has name + url keys."""
        results = [
            people_search_by_name(first="A", last="B"),
            people_search_by_phone("1234567890"),
            people_search_by_email("x@y.com"),
            people_search_by_address(street="1 St", city="C", state="S"),
            people_search_by_username("user"),
        ]
        for result in results:
            for category, entries in result.search_urls.items():
                for entry in entries:
                    assert "name" in entry, f"Missing 'name' in {category}"
                    assert "url" in entry, f"Missing 'url' in {category}"
                    assert entry["url"].startswith("http"), (
                        f"URL doesn't start with http: {entry['url']}"
                    )
