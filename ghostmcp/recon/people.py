"""People search URL generator — IntelTechniques-style OSINT link builder.

Generates search URLs across people-search engines, social media, court
records, and property databases.  NO scraping, NO API calls — pure URL
construction for manual investigation.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from urllib.parse import quote, quote_plus


@dataclass
class PeopleSearchResult:
    """Collection of search URLs organized by category."""

    query_type: str  # name, phone, email, address, username
    input_data: dict = field(default_factory=dict)
    search_urls: dict = field(
        default_factory=dict
    )  # category -> list of {name, url}
    total_urls: int = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _count_urls(urls: dict[str, list[dict[str, str]]]) -> int:
    """Count total URLs across all categories."""
    return sum(len(v) for v in urls.values())


def _slug(text: str) -> str:
    """Convert text to URL-safe slug: 'New York' -> 'new-york'."""
    return text.strip().lower().replace(" ", "-")


def _digits(phone: str) -> str:
    """Strip a phone number to bare digits."""
    return "".join(c for c in phone if c.isdigit())


# ---------------------------------------------------------------------------
# Name search
# ---------------------------------------------------------------------------


def people_search_by_name(
    first: str,
    last: str,
    city: str = "",
    state: str = "",
) -> PeopleSearchResult:
    """Generate search URLs for a person's name.

    Args:
        first: First name.
        last:  Last name.
        city:  City (optional, improves specificity).
        state: US state abbreviation or full name (optional).

    Returns:
        PeopleSearchResult with URLs across people-search, social media,
        and court-record sites.
    """
    f, l = first.strip(), last.strip()
    c, s = city.strip(), state.strip()

    result = PeopleSearchResult(
        query_type="name",
        input_data={"first": f, "last": l, "city": c, "state": s},
    )

    f_slug = _slug(f)
    l_slug = _slug(l)
    c_slug = _slug(c)
    s_slug = _slug(s)
    f_enc = quote_plus(f)
    l_enc = quote_plus(l)
    c_enc = quote_plus(c)
    s_enc = quote_plus(s)

    urls: dict[str, list[dict[str, str]]] = {}

    # ── People search engines ────────────────────────────────────────
    people: list[dict[str, str]] = []

    if s:
        people.append({
            "name": "ThatsThem",
            "url": f"https://thatsthem.com/name/{f_slug}-{l_slug}/{s_slug}",
        })
    else:
        people.append({
            "name": "ThatsThem",
            "url": f"https://thatsthem.com/name/{f_slug}-{l_slug}",
        })

    if c and s:
        people.append({
            "name": "FastPeopleSearch",
            "url": (
                f"https://www.fastpeoplesearch.com/name/"
                f"{f_slug}-{l_slug}_{c_slug}-{s_slug}"
            ),
        })
    else:
        people.append({
            "name": "FastPeopleSearch",
            "url": f"https://www.fastpeoplesearch.com/name/{f_slug}-{l_slug}",
        })

    if c and s:
        people.append({
            "name": "Whitepages",
            "url": (
                f"https://www.whitepages.com/name/"
                f"{f_enc}-{l_enc}/{c_enc}-{s_enc}"
            ),
        })
    else:
        people.append({
            "name": "Whitepages",
            "url": f"https://www.whitepages.com/name/{f_enc}-{l_enc}",
        })

    csz = f"{c_enc}%20{s_enc}" if c and s else s_enc if s else ""
    people.append({
        "name": "TruePeopleSearch",
        "url": (
            f"https://www.truepeoplesearch.com/results"
            f"?name={f_enc}%20{l_enc}&citystatezip={csz}"
        ),
    })

    if s:
        people.append({
            "name": "USPhonebook",
            "url": f"https://www.usphonebook.com/{f_slug}-{l_slug}/{s_slug}",
        })
    else:
        people.append({
            "name": "USPhonebook",
            "url": f"https://www.usphonebook.com/{f_slug}-{l_slug}",
        })

    if c and s:
        people.append({
            "name": "411.com",
            "url": f"https://www.411.com/name/{f_enc}-{l_enc}/{c_enc}-{s_enc}",
        })
    else:
        people.append({
            "name": "411.com",
            "url": f"https://www.411.com/name/{f_enc}-{l_enc}",
        })

    people.append({
        "name": "Spokeo",
        "url": f"https://www.spokeo.com/{f_enc}-{l_enc}",
    })

    if s:
        people.append({
            "name": "PeopleFinder",
            "url": (
                f"https://www.peoplefinder.com/name/"
                f"{f_slug}-{l_slug}/{s_slug}"
            ),
        })
    else:
        people.append({
            "name": "PeopleFinder",
            "url": f"https://www.peoplefinder.com/name/{f_slug}-{l_slug}",
        })

    urls["people_search"] = people

    # ── Social media ─────────────────────────────────────────────────
    urls["social_media"] = [
        {
            "name": "Facebook",
            "url": f"https://www.facebook.com/search/people/?q={f_enc}%20{l_enc}",
        },
        {
            "name": "LinkedIn",
            "url": (
                f"https://www.linkedin.com/search/results/people/"
                f"?keywords={f_enc}%20{l_enc}"
            ),
        },
        {
            "name": "X / Twitter",
            "url": f"https://x.com/search?q={f_enc}%20{l_enc}&f=user",
        },
    ]

    # ── Court / Criminal ─────────────────────────────────────────────
    court: list[dict[str, str]] = [
        {
            "name": "Judyrecords",
            "url": (
                f"https://www.judyrecords.com/record"
                f"?q=%22{f_enc}+{l_enc}%22"
            ),
        },
    ]

    nsopw_params = f"FirstName={f_enc}&LastName={l_enc}"
    if s:
        nsopw_params += f"&State={s_enc}"
    court.append({
        "name": "NSOPW",
        "url": f"https://www.nsopw.gov/search-public?{nsopw_params}",
    })

    urls["court_criminal"] = court

    # ── Property ─────────────────────────────────────────────────────
    urls["property"] = [
        {
            "name": "County Property (Zillow)",
            "url": (
                f"https://www.zillow.com/owners/"
                f"{f_slug}-{l_slug}/"
            ),
        },
    ]

    result.search_urls = urls
    result.total_urls = _count_urls(urls)
    return result


# ---------------------------------------------------------------------------
# Phone search
# ---------------------------------------------------------------------------


def people_search_by_phone(phone: str) -> PeopleSearchResult:
    """Generate reverse-phone search URLs.

    Args:
        phone: Phone number in any format.

    Returns:
        PeopleSearchResult with reverse-phone lookup URLs.
    """
    digits = _digits(phone)

    result = PeopleSearchResult(
        query_type="phone",
        input_data={"phone": phone, "digits": digits},
    )

    urls: dict[str, list[dict[str, str]]] = {}

    urls["people_search"] = [
        {
            "name": "ThatsThem",
            "url": f"https://thatsthem.com/phone/{digits}",
        },
        {
            "name": "FastPeopleSearch",
            "url": f"https://www.fastpeoplesearch.com/{digits}",
        },
        {
            "name": "Whitepages",
            "url": f"https://www.whitepages.com/phone/{digits}",
        },
        {
            "name": "TruePeopleSearch",
            "url": f"https://www.truepeoplesearch.com/results?phoneno={digits}",
        },
        {
            "name": "USPhonebook",
            "url": f"https://www.usphonebook.com/{digits}",
        },
        {
            "name": "Spokeo",
            "url": f"https://www.spokeo.com/phone/{digits}",
        },
        {
            "name": "NumLookup",
            "url": f"https://www.numlookup.com/phone/{digits}",
        },
    ]

    result.search_urls = urls
    result.total_urls = _count_urls(urls)
    return result


# ---------------------------------------------------------------------------
# Email search
# ---------------------------------------------------------------------------


def people_search_by_email(email: str) -> PeopleSearchResult:
    """Generate reverse-email search URLs.

    Args:
        email: Email address.

    Returns:
        PeopleSearchResult with email lookup URLs.
    """
    email = email.strip().lower()
    email_enc = quote_plus(email)

    result = PeopleSearchResult(
        query_type="email",
        input_data={"email": email},
    )

    urls: dict[str, list[dict[str, str]]] = {}

    urls["people_search"] = [
        {
            "name": "ThatsThem",
            "url": f"https://thatsthem.com/email/{quote(email)}",
        },
        {
            "name": "Spokeo",
            "url": f"https://www.spokeo.com/email-search/search?q={email_enc}",
        },
        {
            "name": "EmailRep",
            "url": f"https://emailrep.io/{quote(email)}",
        },
    ]

    urls["social_media"] = [
        {
            "name": "Google (email)",
            "url": f"https://www.google.com/search?q=%22{email_enc}%22",
        },
    ]

    urls["breach_check"] = [
        {
            "name": "Have I Been Pwned",
            "url": f"https://haveibeenpwned.com/account/{quote(email)}",
        },
        {
            "name": "DeHashed",
            "url": f"https://www.dehashed.com/search?query={email_enc}",
        },
    ]

    result.search_urls = urls
    result.total_urls = _count_urls(urls)
    return result


# ---------------------------------------------------------------------------
# Address search
# ---------------------------------------------------------------------------


def people_search_by_address(
    street: str,
    city: str,
    state: str,
) -> PeopleSearchResult:
    """Generate address-based search URLs.

    Args:
        street: Street address (e.g. '123 Main St').
        city:   City name.
        state:  US state abbreviation or full name.

    Returns:
        PeopleSearchResult with address lookup and property URLs.
    """
    st, c, s = street.strip(), city.strip(), state.strip()
    st_slug = _slug(st)
    c_slug = _slug(c)
    s_slug = _slug(s)
    st_enc = quote_plus(st)
    c_enc = quote_plus(c)
    s_enc = quote_plus(s)

    result = PeopleSearchResult(
        query_type="address",
        input_data={"street": st, "city": c, "state": s},
    )

    urls: dict[str, list[dict[str, str]]] = {}

    urls["people_search"] = [
        {
            "name": "ThatsThem",
            "url": (
                f"https://thatsthem.com/address/"
                f"{st_slug}/{c_slug}/{s_slug}"
            ),
        },
        {
            "name": "FastPeopleSearch",
            "url": (
                f"https://www.fastpeoplesearch.com/address/"
                f"{st_slug}_{c_slug}-{s_slug}"
            ),
        },
        {
            "name": "Whitepages",
            "url": (
                f"https://www.whitepages.com/address/"
                f"{st_enc}/{c_enc}-{s_enc}"
            ),
        },
    ]

    urls["property"] = [
        {
            "name": "Zillow",
            "url": (
                f"https://www.zillow.com/homes/"
                f"{st_enc}-{c_enc},-{s_enc}_rb/"
            ),
        },
        {
            "name": "Realtor.com",
            "url": (
                f"https://www.realtor.com/realestateandhomes-detail/"
                f"{st_slug}_{c_slug}_{s_slug}"
            ),
        },
        {
            "name": "Google Maps",
            "url": (
                f"https://www.google.com/maps/search/"
                f"{st_enc}+{c_enc}+{s_enc}"
            ),
        },
    ]

    result.search_urls = urls
    result.total_urls = _count_urls(urls)
    return result


# ---------------------------------------------------------------------------
# Username search
# ---------------------------------------------------------------------------


def people_search_by_username(username: str) -> PeopleSearchResult:
    """Generate username search URLs across social platforms.

    Args:
        username: Handle / screen name (without leading @).

    Returns:
        PeopleSearchResult with social media profile and search URLs.
    """
    u = username.strip().lstrip("@")
    u_enc = quote_plus(u)
    u_path = quote(u)

    result = PeopleSearchResult(
        query_type="username",
        input_data={"username": u},
    )

    urls: dict[str, list[dict[str, str]]] = {}

    urls["social_media"] = [
        {"name": "X / Twitter", "url": f"https://x.com/{u_path}"},
        {"name": "Instagram", "url": f"https://www.instagram.com/{u_path}/"},
        {"name": "GitHub", "url": f"https://github.com/{u_path}"},
        {"name": "Reddit", "url": f"https://www.reddit.com/user/{u_path}"},
        {"name": "TikTok", "url": f"https://www.tiktok.com/@{u_path}"},
        {"name": "YouTube", "url": f"https://www.youtube.com/@{u_path}"},
        {"name": "Pinterest", "url": f"https://www.pinterest.com/{u_path}/"},
        {"name": "Medium", "url": f"https://medium.com/@{u_path}"},
        {"name": "Keybase", "url": f"https://keybase.io/{u_path}"},
    ]

    urls["dev_platforms"] = [
        {"name": "GitHub", "url": f"https://github.com/{u_path}"},
        {"name": "GitLab", "url": f"https://gitlab.com/{u_path}"},
        {"name": "Bitbucket", "url": f"https://bitbucket.org/{u_path}/"},
        {"name": "Stack Overflow", "url": f"https://stackoverflow.com/users/?q={u_enc}"},
        {"name": "npm", "url": f"https://www.npmjs.com/~{u_path}"},
        {"name": "PyPI", "url": f"https://pypi.org/user/{u_path}/"},
    ]

    urls["search_engines"] = [
        {
            "name": "Google",
            "url": f"https://www.google.com/search?q=%22{u_enc}%22",
        },
        {
            "name": "X Search",
            "url": f"https://x.com/search?q={u_enc}&f=user",
        },
    ]

    result.search_urls = urls
    result.total_urls = _count_urls(urls)
    return result


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


async def people_search(query_type: str, **kwargs: str) -> PeopleSearchResult:
    """Unified dispatcher for people search URL generation.

    Wraps the synchronous search functions for async callers.

    Args:
        query_type: One of 'name', 'phone', 'email', 'address', 'username'.
        **kwargs:   Arguments forwarded to the specific search function.

    Returns:
        PeopleSearchResult with generated URLs.

    Raises:
        ValueError: If query_type is not recognized.
    """
    dispatch = {
        "name": people_search_by_name,
        "phone": people_search_by_phone,
        "email": people_search_by_email,
        "address": people_search_by_address,
        "username": people_search_by_username,
    }

    func = dispatch.get(query_type.strip().lower())
    if func is None:
        valid = ", ".join(sorted(dispatch.keys()))
        raise ValueError(
            f"Unknown query_type: {query_type!r}. Must be one of: {valid}"
        )

    # Pure CPU work — use to_thread to avoid blocking the event loop
    # in case the caller is running in a tight async context
    return await asyncio.to_thread(func, **kwargs)
