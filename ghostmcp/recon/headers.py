"""HTTP security header analysis module — grade, fingerprint, and flag misconfigurations."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx

TIMEOUT = 10.0


@dataclass
class HeadersReport:
    """Result of an HTTP security header analysis."""

    url: str
    grade: str = ""  # A+ through F
    score: int = 0   # 0-100

    # Server fingerprint
    server: str = ""
    x_powered_by: str = ""

    # Security headers (each has value + rating)
    headers_present: dict = field(default_factory=dict)
    headers_missing: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    # CORS analysis
    cors: dict = field(default_factory=dict)

    # Raw headers
    raw_headers: dict = field(default_factory=dict)

    error: str | None = None


# ---------------------------------------------------------------------------
# Header grading constants
# ---------------------------------------------------------------------------

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
    "cache-control",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
]

FINGERPRINT_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "via",
]

_VERSION_RE = re.compile(r"[\d]+\.[\d]+")


# ---------------------------------------------------------------------------
# CSP analysis
# ---------------------------------------------------------------------------

def _analyze_csp(value: str) -> dict:
    """Parse a Content-Security-Policy header and return analysis details.

    Returns dict with keys: score (int 0-25), directives (dict),
    has_unsafe_inline, has_unsafe_eval, has_wildcard, has_default_src,
    has_nonce_or_hash.
    """
    directives: dict[str, str] = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split(None, 1)
        directive_name = tokens[0].lower()
        directive_value = tokens[1] if len(tokens) > 1 else ""
        directives[directive_name] = directive_value

    has_unsafe_inline = "'unsafe-inline'" in value.lower()
    has_unsafe_eval = "'unsafe-eval'" in value.lower()
    has_wildcard = False
    for _name, dval in directives.items():
        # Check for bare wildcard * as a source (not in a URL like *.example.com)
        sources = dval.split()
        for src in sources:
            if src == "*":
                has_wildcard = True
                break
    has_default_src = "default-src" in directives
    has_nonce_or_hash = bool(
        re.search(r"'nonce-[A-Za-z0-9+/=]+'", value)
        or re.search(r"'sha(256|384|512)-[A-Za-z0-9+/=]+'", value)
    )

    score = 20  # base points for having CSP at all
    if has_unsafe_inline:
        score -= 5
    if has_unsafe_eval:
        score -= 5
    if has_wildcard:
        score -= 5
    if not has_default_src:
        score -= 5
    if has_nonce_or_hash:
        score += 5
    score = max(0, min(25, score))

    return {
        "score": score,
        "directives": directives,
        "has_unsafe_inline": has_unsafe_inline,
        "has_unsafe_eval": has_unsafe_eval,
        "has_wildcard": has_wildcard,
        "has_default_src": has_default_src,
        "has_nonce_or_hash": has_nonce_or_hash,
    }


# ---------------------------------------------------------------------------
# CORS analysis
# ---------------------------------------------------------------------------

def _analyze_cors(headers: dict) -> dict:
    """Analyze CORS-related headers and return findings."""
    lower = {k.lower(): v for k, v in headers.items()}
    result: dict = {}

    acao = lower.get("access-control-allow-origin", "")
    if acao:
        result["allow_origin"] = acao
    acac = lower.get("access-control-allow-credentials", "")
    if acac:
        result["allow_credentials"] = acac
    acam = lower.get("access-control-allow-methods", "")
    if acam:
        result["allow_methods"] = acam
    acah = lower.get("access-control-allow-headers", "")
    if acah:
        result["allow_headers"] = acah

    # Flag dangerous combos
    result["wildcard_origin"] = acao == "*"
    result["wildcard_with_credentials"] = (
        acao == "*" and acac.lower() == "true"
    )

    return result


# ---------------------------------------------------------------------------
# Server fingerprinting
# ---------------------------------------------------------------------------

def _extract_fingerprint(headers: dict) -> dict:
    """Extract server fingerprint information from response headers."""
    lower = {k.lower(): v for k, v in headers.items()}
    info: dict = {}
    for hdr in FINGERPRINT_HEADERS:
        val = lower.get(hdr, "")
        if val:
            info[hdr] = val
    return info


# ---------------------------------------------------------------------------
# Per-header scoring
# ---------------------------------------------------------------------------

def _score_hsts(value: str) -> tuple[int, str]:
    """Score Strict-Transport-Security header. Max 15 points."""
    if not value:
        return 0, "missing"
    value_lower = value.lower()
    match = re.search(r"max-age=(\d+)", value_lower)
    if not match:
        return 5, "present but no max-age"
    max_age = int(match.group(1))
    has_include_sub = "includesubdomains" in value_lower
    if max_age >= 31536000 and has_include_sub:
        return 15, "optimal"
    if max_age >= 31536000:
        return 12, "good max-age, missing includeSubDomains"
    if max_age >= 15768000:
        return 10, "acceptable max-age"
    if max_age >= 2592000:
        return 7, "low max-age"
    return 5, "very low max-age"


def _score_xcto(value: str) -> tuple[int, str]:
    """Score X-Content-Type-Options header. Max 10 points."""
    if not value:
        return 0, "missing"
    if value.lower().strip() == "nosniff":
        return 10, "nosniff"
    return 0, f"unexpected value: {value}"


def _score_xfo(value: str) -> tuple[int, str]:
    """Score X-Frame-Options header. Max 10 points."""
    if not value:
        return 0, "missing"
    val = value.upper().strip()
    if val == "DENY":
        return 10, "DENY"
    if val == "SAMEORIGIN":
        return 10, "SAMEORIGIN"
    if val.startswith("ALLOW-FROM"):
        return 5, "ALLOW-FROM (partial)"
    return 0, f"unexpected value: {value}"


def _score_referrer_policy(value: str) -> tuple[int, str]:
    """Score Referrer-Policy header. Max 10 points."""
    if not value:
        return 0, "missing"
    val = value.lower().strip()
    full_marks = {"strict-origin-when-cross-origin", "no-referrer", "same-origin",
                  "strict-origin", "no-referrer-when-downgrade"}
    if val in full_marks:
        return 10, val
    if val == "origin":
        return 7, "origin (partial)"
    if val == "origin-when-cross-origin":
        return 7, "origin-when-cross-origin (partial)"
    if val == "unsafe-url":
        return 0, "unsafe-url (leaks full URL)"
    return 5, f"non-standard: {val}"


def _score_permissions_policy(value: str) -> tuple[int, str]:
    """Score Permissions-Policy header. Max 10 points."""
    if not value:
        return 0, "missing"
    # Check for actual restrictions (not just empty)
    stripped = value.strip()
    if not stripped:
        return 0, "empty"
    # Count how many features are restricted
    parts = [p.strip() for p in stripped.split(",") if p.strip()]
    if len(parts) >= 5:
        return 10, f"{len(parts)} features restricted"
    if len(parts) >= 2:
        return 7, f"{len(parts)} features restricted"
    return 5, f"{len(parts)} feature(s) restricted"


def _score_xxp(value: str, has_csp: bool) -> tuple[int, str]:
    """Score X-XSS-Protection header. Max 5 points."""
    if not value:
        if has_csp:
            return 0, "absent (acceptable with CSP)"
        return 0, "missing (no CSP either)"
    val = value.strip()
    if val == "0":
        return 5, "correctly disabled (defers to CSP)"
    if val in ("1; mode=block", "1;mode=block"):
        return 3, "legacy mode=block"
    if val == "1":
        return 2, "basic (no mode=block)"
    return 1, f"non-standard: {val}"


def _score_cache_control(value: str) -> tuple[int, str]:
    """Score Cache-Control header. Max 5 points."""
    if not value:
        return 0, "missing"
    val = value.lower()
    if "no-store" in val:
        return 5, "no-store"
    if "private" in val:
        return 4, "private"
    if "no-cache" in val:
        return 3, "no-cache"
    return 2, "public/other"


def _score_cross_origin(headers: dict) -> tuple[int, str]:
    """Score Cross-Origin headers (COOP, COEP, CORP). Max 10 points total."""
    lower = {k.lower(): v for k, v in headers.items()}
    points = 0
    details = []

    coop = lower.get("cross-origin-opener-policy", "")
    if coop:
        points += 4
        details.append(f"COOP={coop}")

    coep = lower.get("cross-origin-embedder-policy", "")
    if coep:
        points += 3
        details.append(f"COEP={coep}")

    corp = lower.get("cross-origin-resource-policy", "")
    if corp:
        points += 3
        details.append(f"CORP={corp}")

    if not details:
        return 0, "none present"
    return min(points, 10), ", ".join(details)


# ---------------------------------------------------------------------------
# Score calculation and grading
# ---------------------------------------------------------------------------

def _calculate_grade(score: int) -> str:
    """Convert a numeric score (0-100) to a letter grade."""
    if score >= 90:
        return "A+"
    if score >= 80:
        return "A"
    if score >= 70:
        return "B"
    if score >= 60:
        return "C"
    if score >= 50:
        return "D"
    return "F"


def _generate_warnings(headers: dict, csp_analysis: dict | None, cors: dict,
                        fingerprint: dict, is_https: bool) -> list[str]:
    """Generate warning messages based on header analysis."""
    lower = {k.lower(): v for k, v in headers.items()}
    warnings: list[str] = []

    # Missing CSP is critical
    if "content-security-policy" not in lower:
        warnings.append("CRITICAL: No Content-Security-Policy header — XSS protection relies solely on browser defaults")

    # CSP issues
    if csp_analysis:
        if csp_analysis.get("has_unsafe_inline"):
            warnings.append("CSP contains 'unsafe-inline' — weakens XSS protection")
        if csp_analysis.get("has_unsafe_eval"):
            warnings.append("CSP contains 'unsafe-eval' — allows dynamic code execution")
        if csp_analysis.get("has_wildcard"):
            warnings.append("CSP contains wildcard (*) source — overly permissive")

    # Missing HSTS on HTTPS
    if is_https and "strict-transport-security" not in lower:
        warnings.append("HTTPS site missing Strict-Transport-Security header — vulnerable to SSL stripping")

    # Server version exposure
    server_val = lower.get("server", "")
    if server_val and _VERSION_RE.search(server_val):
        warnings.append(f"Server header exposes version: {server_val}")

    # X-Powered-By
    if "x-powered-by" in lower:
        warnings.append(f"X-Powered-By header present (information disclosure): {lower['x-powered-by']}")

    # CORS wildcard + credentials
    if cors.get("wildcard_with_credentials"):
        warnings.append("CRITICAL: CORS allows wildcard origin (*) with credentials — any site can make authenticated requests")

    return warnings


def grade_headers(headers: dict, url: str = "") -> HeadersReport:
    """Grade a set of HTTP response headers.

    This is the pure-logic scoring function — no network I/O.
    Useful for testing the grading logic in isolation.

    Args:
        headers: dict of response headers (case-insensitive lookup done internally).
        url: the URL these headers came from (for context in the report).

    Returns:
        HeadersReport with score, grade, findings, and warnings.
    """
    lower = {k.lower(): v for k, v in headers.items()}
    report = HeadersReport(url=url)
    report.raw_headers = dict(headers)

    is_https = url.lower().startswith("https://") if url else False

    # --- Score each security header ---
    total = 0
    present: dict[str, dict] = {}
    missing: list[str] = []

    # 1. HSTS (15 pts)
    hsts_val = lower.get("strict-transport-security", "")
    hsts_score, hsts_detail = _score_hsts(hsts_val)
    total += hsts_score
    if hsts_val:
        present["strict-transport-security"] = {"value": hsts_val, "score": hsts_score, "max": 15, "detail": hsts_detail}
    else:
        missing.append("strict-transport-security")

    # 2. CSP (25 pts)
    csp_val = lower.get("content-security-policy", "")
    csp_analysis = None
    if csp_val:
        csp_analysis = _analyze_csp(csp_val)
        csp_score = csp_analysis["score"]
        total += csp_score
        present["content-security-policy"] = {"value": csp_val, "score": csp_score, "max": 25, "detail": csp_analysis}
    else:
        missing.append("content-security-policy")

    has_csp = bool(csp_val)

    # 3. X-Content-Type-Options (10 pts)
    xcto_val = lower.get("x-content-type-options", "")
    xcto_score, xcto_detail = _score_xcto(xcto_val)
    total += xcto_score
    if xcto_val:
        present["x-content-type-options"] = {"value": xcto_val, "score": xcto_score, "max": 10, "detail": xcto_detail}
    else:
        missing.append("x-content-type-options")

    # 4. X-Frame-Options (10 pts)
    xfo_val = lower.get("x-frame-options", "")
    xfo_score, xfo_detail = _score_xfo(xfo_val)
    total += xfo_score
    if xfo_val:
        present["x-frame-options"] = {"value": xfo_val, "score": xfo_score, "max": 10, "detail": xfo_detail}
    else:
        missing.append("x-frame-options")

    # 5. Referrer-Policy (10 pts)
    rp_val = lower.get("referrer-policy", "")
    rp_score, rp_detail = _score_referrer_policy(rp_val)
    total += rp_score
    if rp_val:
        present["referrer-policy"] = {"value": rp_val, "score": rp_score, "max": 10, "detail": rp_detail}
    else:
        missing.append("referrer-policy")

    # 6. Permissions-Policy (10 pts)
    pp_val = lower.get("permissions-policy", "")
    pp_score, pp_detail = _score_permissions_policy(pp_val)
    total += pp_score
    if pp_val:
        present["permissions-policy"] = {"value": pp_val, "score": pp_score, "max": 10, "detail": pp_detail}
    else:
        missing.append("permissions-policy")

    # 7. X-XSS-Protection (5 pts)
    xxp_val = lower.get("x-xss-protection", "")
    xxp_score, xxp_detail = _score_xxp(xxp_val, has_csp)
    total += xxp_score
    if xxp_val:
        present["x-xss-protection"] = {"value": xxp_val, "score": xxp_score, "max": 5, "detail": xxp_detail}
    else:
        missing.append("x-xss-protection")

    # 8. Cache-Control (5 pts)
    cc_val = lower.get("cache-control", "")
    cc_score, cc_detail = _score_cache_control(cc_val)
    total += cc_score
    if cc_val:
        present["cache-control"] = {"value": cc_val, "score": cc_score, "max": 5, "detail": cc_detail}
    else:
        missing.append("cache-control")

    # 9. Cross-Origin headers (10 pts)
    co_score, co_detail = _score_cross_origin(headers)
    total += co_score
    if co_score > 0:
        present["cross-origin-headers"] = {"value": co_detail, "score": co_score, "max": 10, "detail": co_detail}
    else:
        missing.append("cross-origin-headers (COOP/COEP/CORP)")

    # --- Fingerprint ---
    fingerprint = _extract_fingerprint(headers)
    report.server = fingerprint.get("server", "")
    report.x_powered_by = fingerprint.get("x-powered-by", "")

    # --- CORS ---
    cors = _analyze_cors(headers)
    report.cors = cors

    # --- Warnings ---
    warnings = _generate_warnings(headers, csp_analysis, cors, fingerprint, is_https)

    # --- Assemble report ---
    report.score = max(0, min(100, total))
    report.grade = _calculate_grade(report.score)
    report.headers_present = present
    report.headers_missing = missing
    report.warnings = warnings

    return report


# ---------------------------------------------------------------------------
# Main async function
# ---------------------------------------------------------------------------

async def analyze_headers(url: str) -> HeadersReport:
    """Fetch a URL and analyze its HTTP security headers.

    Makes a GET request with httpx (per-request client, 10s timeout),
    then grades the response headers for security best practices.

    Args:
        url: URL to analyze (should include scheme, e.g. https://example.com).

    Returns:
        HeadersReport with score, grade, findings, warnings, and fingerprint.
    """
    url = url.strip()
    if not url:
        return HeadersReport(url=url, error="URL is required.")

    # Ensure scheme is present
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(url)
    except httpx.TimeoutException:
        return HeadersReport(url=url, error=f"Timeout connecting to {url}")
    except httpx.ConnectError:
        return HeadersReport(url=url, error=f"Connection failed to {url}")
    except httpx.TooManyRedirects:
        return HeadersReport(url=url, error=f"Too many redirects for {url}")
    except Exception as e:
        return HeadersReport(url=url, error=f"Request error: {e}")

    # Convert httpx Headers to a plain dict for grading
    raw = {k: v for k, v in resp.headers.items()}

    # Use the final URL after redirects
    final_url = str(resp.url)

    report = grade_headers(raw, url=final_url)
    return report
