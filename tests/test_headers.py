"""Tests for HTTP security header analysis module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ghostmcp.recon.headers import (
    HeadersReport,
    analyze_headers,
    grade_headers,
    _analyze_csp,
    _analyze_cors,
    _extract_fingerprint,
    _score_hsts,
    _score_xcto,
    _score_xfo,
    _score_referrer_policy,
    _score_permissions_policy,
    _score_xxp,
    _score_cache_control,
    _score_cross_origin,
    _calculate_grade,
    _generate_warnings,
)


# ---------------------------------------------------------------------------
# Sample header sets
# ---------------------------------------------------------------------------

SAMPLE_SECURE_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'nonce-abc123'; style-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "X-XSS-Protection": "0",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Server": "nginx",
}

SAMPLE_INSECURE_HEADERS = {
    "Server": "Apache/2.4.49 (Ubuntu)",
    "X-Powered-By": "PHP/7.4.3",
    "X-AspNet-Version": "4.0.30319",
}


# ---------------------------------------------------------------------------
# Header grading tests (pure logic, no mocking)
# ---------------------------------------------------------------------------

class TestHeaderGrading:

    def test_secure_headers_get_high_grade(self):
        report = grade_headers(SAMPLE_SECURE_HEADERS, url="https://example.com")
        assert report.grade in ("A+", "A")
        assert report.score >= 80

    def test_insecure_headers_get_low_grade(self):
        report = grade_headers(SAMPLE_INSECURE_HEADERS, url="https://example.com")
        assert report.grade == "F"
        assert report.score < 50

    def test_empty_headers_score_zero(self):
        report = grade_headers({}, url="https://example.com")
        assert report.score == 0
        assert report.grade == "F"

    def test_partial_headers_middle_grade(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",
            "Cache-Control": "no-store",
        }
        report = grade_headers(headers, url="https://example.com")
        # 15 + 15 + 10 + 10 + 5 = 55 -> grade D
        assert report.grade in ("C", "D")
        assert 50 <= report.score <= 69

    def test_all_missing_headers_listed(self):
        report = grade_headers({}, url="https://example.com")
        assert "strict-transport-security" in report.headers_missing
        assert "content-security-policy" in report.headers_missing
        assert "x-content-type-options" in report.headers_missing

    def test_present_headers_recorded(self):
        headers = {"X-Content-Type-Options": "nosniff"}
        report = grade_headers(headers, url="https://example.com")
        assert "x-content-type-options" in report.headers_present
        entry = report.headers_present["x-content-type-options"]
        assert entry["score"] == 10
        assert entry["max"] == 10

    def test_raw_headers_preserved(self):
        headers = {"X-Custom": "value123", "Server": "test"}
        report = grade_headers(headers, url="https://example.com")
        assert report.raw_headers["X-Custom"] == "value123"

    def test_grade_boundaries(self):
        assert _calculate_grade(100) == "A+"
        assert _calculate_grade(90) == "A+"
        assert _calculate_grade(89) == "A"
        assert _calculate_grade(80) == "A"
        assert _calculate_grade(79) == "B"
        assert _calculate_grade(70) == "B"
        assert _calculate_grade(69) == "C"
        assert _calculate_grade(60) == "C"
        assert _calculate_grade(59) == "D"
        assert _calculate_grade(50) == "D"
        assert _calculate_grade(49) == "F"
        assert _calculate_grade(0) == "F"


# ---------------------------------------------------------------------------
# HSTS scoring tests
# ---------------------------------------------------------------------------

class TestHSTSScoring:

    def test_optimal_hsts(self):
        score, _ = _score_hsts("max-age=31536000; includeSubDomains")
        assert score == 15

    def test_good_maxage_no_includesub(self):
        score, _ = _score_hsts("max-age=31536000")
        assert score == 12

    def test_acceptable_maxage(self):
        score, _ = _score_hsts("max-age=15768000")
        assert score == 10

    def test_low_maxage(self):
        score, _ = _score_hsts("max-age=2592000")
        assert score == 7

    def test_very_low_maxage(self):
        score, _ = _score_hsts("max-age=86400")
        assert score == 5

    def test_present_no_maxage(self):
        score, _ = _score_hsts("includeSubDomains")
        assert score == 5

    def test_missing(self):
        score, detail = _score_hsts("")
        assert score == 0
        assert detail == "missing"


# ---------------------------------------------------------------------------
# CSP analysis tests
# ---------------------------------------------------------------------------

class TestCSPAnalysis:

    def test_good_csp_full_score(self):
        csp = "default-src 'self'; script-src 'self' 'nonce-abc123'"
        result = _analyze_csp(csp)
        # Base 20 + nonce bonus 5 = 25 (max)
        assert result["score"] == 25
        assert result["has_default_src"] is True
        assert result["has_nonce_or_hash"] is True
        assert result["has_unsafe_inline"] is False
        assert result["has_unsafe_eval"] is False

    def test_unsafe_inline_deduction(self):
        csp = "default-src 'self'; script-src 'self' 'unsafe-inline'"
        result = _analyze_csp(csp)
        assert result["has_unsafe_inline"] is True
        assert result["score"] < 25

    def test_unsafe_eval_deduction(self):
        csp = "default-src 'self'; script-src 'self' 'unsafe-eval'"
        result = _analyze_csp(csp)
        assert result["has_unsafe_eval"] is True
        assert result["score"] < 25

    def test_wildcard_deduction(self):
        csp = "default-src *"
        result = _analyze_csp(csp)
        assert result["has_wildcard"] is True
        assert result["score"] < 20

    def test_no_default_src_deduction(self):
        csp = "script-src 'self'"
        result = _analyze_csp(csp)
        assert result["has_default_src"] is False
        assert result["score"] <= 15

    def test_nonce_detection(self):
        csp = "default-src 'self'; script-src 'nonce-r4nD0m=='"
        result = _analyze_csp(csp)
        assert result["has_nonce_or_hash"] is True

    def test_sha256_hash_detection(self):
        csp = "default-src 'self'; script-src 'sha256-abc123def456=='"
        result = _analyze_csp(csp)
        assert result["has_nonce_or_hash"] is True

    def test_worst_case_csp(self):
        csp = "script-src * 'unsafe-inline' 'unsafe-eval'"
        result = _analyze_csp(csp)
        assert result["score"] == 0

    def test_directive_parsing(self):
        csp = "default-src 'self'; img-src https: data:; font-src 'self'"
        result = _analyze_csp(csp)
        assert "default-src" in result["directives"]
        assert "img-src" in result["directives"]
        assert "font-src" in result["directives"]

    def test_subdomain_wildcard_not_flagged(self):
        csp = "default-src 'self'; img-src *.example.com"
        result = _analyze_csp(csp)
        assert result["has_wildcard"] is False


# ---------------------------------------------------------------------------
# CORS analysis tests
# ---------------------------------------------------------------------------

class TestCORSAnalysis:

    def test_no_cors_headers(self):
        result = _analyze_cors({"Server": "nginx"})
        assert result.get("wildcard_origin") is False
        assert result.get("wildcard_with_credentials") is False

    def test_wildcard_origin(self):
        headers = {"Access-Control-Allow-Origin": "*"}
        result = _analyze_cors(headers)
        assert result["wildcard_origin"] is True
        assert result["allow_origin"] == "*"

    def test_wildcard_with_credentials_critical(self):
        headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
        result = _analyze_cors(headers)
        assert result["wildcard_with_credentials"] is True

    def test_specific_origin_safe(self):
        headers = {
            "Access-Control-Allow-Origin": "https://example.com",
            "Access-Control-Allow-Credentials": "true",
        }
        result = _analyze_cors(headers)
        assert result["wildcard_origin"] is False
        assert result["wildcard_with_credentials"] is False

    def test_methods_and_headers_extracted(self):
        headers = {
            "Access-Control-Allow-Origin": "https://example.com",
            "Access-Control-Allow-Methods": "GET, POST, PUT",
            "Access-Control-Allow-Headers": "Authorization, Content-Type",
        }
        result = _analyze_cors(headers)
        assert result["allow_methods"] == "GET, POST, PUT"
        assert result["allow_headers"] == "Authorization, Content-Type"


# ---------------------------------------------------------------------------
# Server fingerprint tests
# ---------------------------------------------------------------------------

class TestServerFingerprint:

    def test_server_extraction(self):
        headers = {"Server": "nginx/1.18.0"}
        result = _extract_fingerprint(headers)
        assert result["server"] == "nginx/1.18.0"

    def test_powered_by_extraction(self):
        headers = {"X-Powered-By": "Express"}
        result = _extract_fingerprint(headers)
        assert result["x-powered-by"] == "Express"

    def test_aspnet_extraction(self):
        headers = {"X-AspNet-Version": "4.0.30319", "X-AspNetMvc-Version": "5.2"}
        result = _extract_fingerprint(headers)
        assert result["x-aspnet-version"] == "4.0.30319"
        assert result["x-aspnetmvc-version"] == "5.2"

    def test_via_proxy_chain(self):
        headers = {"Via": "1.1 varnish, 1.1 nginx"}
        result = _extract_fingerprint(headers)
        assert result["via"] == "1.1 varnish, 1.1 nginx"

    def test_generator_extraction(self):
        headers = {"X-Generator": "WordPress 5.8"}
        result = _extract_fingerprint(headers)
        assert result["x-generator"] == "WordPress 5.8"

    def test_no_fingerprint_headers(self):
        headers = {"Content-Type": "text/html"}
        result = _extract_fingerprint(headers)
        assert len(result) == 0

    def test_grade_headers_populates_server_field(self):
        headers = {"Server": "Apache/2.4.49", "X-Powered-By": "PHP/8.1"}
        report = grade_headers(headers, url="https://example.com")
        assert report.server == "Apache/2.4.49"
        assert report.x_powered_by == "PHP/8.1"


# ---------------------------------------------------------------------------
# Individual header scoring tests
# ---------------------------------------------------------------------------

class TestIndividualScoring:

    def test_xcto_nosniff(self):
        score, _ = _score_xcto("nosniff")
        assert score == 10

    def test_xcto_wrong_value(self):
        score, _ = _score_xcto("nofollow")
        assert score == 0

    def test_xcto_missing(self):
        score, _ = _score_xcto("")
        assert score == 0

    def test_xfo_deny(self):
        score, _ = _score_xfo("DENY")
        assert score == 10

    def test_xfo_sameorigin(self):
        score, _ = _score_xfo("SAMEORIGIN")
        assert score == 10

    def test_xfo_allowfrom(self):
        score, _ = _score_xfo("ALLOW-FROM https://example.com")
        assert score == 5

    def test_referrer_strict_origin(self):
        score, _ = _score_referrer_policy("strict-origin-when-cross-origin")
        assert score == 10

    def test_referrer_no_referrer(self):
        score, _ = _score_referrer_policy("no-referrer")
        assert score == 10

    def test_referrer_unsafe_url(self):
        score, _ = _score_referrer_policy("unsafe-url")
        assert score == 0

    def test_referrer_origin_partial(self):
        score, _ = _score_referrer_policy("origin")
        assert score == 7

    def test_permissions_policy_many_features(self):
        value = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        score, _ = _score_permissions_policy(value)
        assert score == 10

    def test_permissions_policy_few_features(self):
        value = "camera=(), microphone=()"
        score, _ = _score_permissions_policy(value)
        assert score == 7

    def test_permissions_policy_single(self):
        value = "camera=()"
        score, _ = _score_permissions_policy(value)
        assert score == 5

    def test_xxp_disabled_correctly(self):
        score, _ = _score_xxp("0", has_csp=True)
        assert score == 5

    def test_xxp_mode_block_legacy(self):
        score, _ = _score_xxp("1; mode=block", has_csp=False)
        assert score == 3

    def test_xxp_missing_with_csp(self):
        score, _ = _score_xxp("", has_csp=True)
        assert score == 0

    def test_xxp_missing_without_csp(self):
        score, _ = _score_xxp("", has_csp=False)
        assert score == 0

    def test_cache_control_no_store(self):
        score, _ = _score_cache_control("no-store")
        assert score == 5

    def test_cache_control_private(self):
        score, _ = _score_cache_control("private, max-age=3600")
        assert score == 4

    def test_cache_control_no_cache(self):
        score, _ = _score_cache_control("no-cache")
        assert score == 3

    def test_cache_control_public(self):
        score, _ = _score_cache_control("public, max-age=86400")
        assert score == 2

    def test_cross_origin_all_present(self):
        headers = {
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Resource-Policy": "same-origin",
        }
        score, _ = _score_cross_origin(headers)
        assert score == 10

    def test_cross_origin_partial(self):
        headers = {"Cross-Origin-Opener-Policy": "same-origin"}
        score, _ = _score_cross_origin(headers)
        assert score == 4

    def test_cross_origin_none(self):
        headers = {"Server": "nginx"}
        score, detail = _score_cross_origin(headers)
        assert score == 0
        assert detail == "none present"


# ---------------------------------------------------------------------------
# Warnings generation tests
# ---------------------------------------------------------------------------

class TestWarnings:

    def test_missing_csp_warning(self):
        warnings = _generate_warnings({}, None, {}, {}, is_https=True)
        assert any("Content-Security-Policy" in w for w in warnings)

    def test_missing_hsts_on_https(self):
        warnings = _generate_warnings({}, None, {}, {}, is_https=True)
        assert any("Strict-Transport-Security" in w for w in warnings)

    def test_no_hsts_warning_on_http(self):
        warnings = _generate_warnings({}, None, {}, {}, is_https=False)
        hsts_warnings = [w for w in warnings if "Strict-Transport-Security" in w]
        assert len(hsts_warnings) == 0

    def test_server_version_exposure(self):
        headers = {"server": "Apache/2.4.49"}
        warnings = _generate_warnings(headers, None, {}, {"server": "Apache/2.4.49"}, is_https=False)
        assert any("version" in w.lower() for w in warnings)

    def test_x_powered_by_warning(self):
        headers = {"x-powered-by": "PHP/7.4"}
        warnings = _generate_warnings(headers, None, {}, {}, is_https=False)
        assert any("X-Powered-By" in w for w in warnings)

    def test_cors_wildcard_credentials_warning(self):
        cors = {"wildcard_with_credentials": True}
        warnings = _generate_warnings({}, None, cors, {}, is_https=False)
        assert any("CORS" in w for w in warnings)

    def test_csp_unsafe_inline_warning(self):
        csp_analysis = {"has_unsafe_inline": True, "has_unsafe_eval": False}
        headers = {"content-security-policy": "default-src 'self' 'unsafe-inline'"}
        warnings = _generate_warnings(headers, csp_analysis, {}, {}, is_https=False)
        assert any("unsafe-inline" in w for w in warnings)

    def test_csp_unsafe_eval_warning(self):
        csp_analysis = {"has_unsafe_inline": False, "has_unsafe_eval": True}
        headers = {"content-security-policy": "default-src 'self' 'unsafe-eval'"}
        warnings = _generate_warnings(headers, csp_analysis, {}, {}, is_https=False)
        assert any("unsafe-eval" in w for w in warnings)

    def test_secure_site_no_critical_warnings(self):
        headers = {
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000",
            "server": "nginx",
        }
        csp_analysis = {
            "has_unsafe_inline": False,
            "has_unsafe_eval": False,
            "has_wildcard": False,
        }
        cors = {"wildcard_with_credentials": False}
        warnings = _generate_warnings(headers, csp_analysis, cors, {"server": "nginx"}, is_https=True)
        critical = [w for w in warnings if "CRITICAL" in w]
        assert len(critical) == 0


# ---------------------------------------------------------------------------
# Async analyze_headers tests (mocked httpx)
# ---------------------------------------------------------------------------

class TestAnalyzeHeaders:

    @pytest.mark.asyncio
    async def test_successful_analysis(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = SAMPLE_SECURE_HEADERS
        mock_resp.url = "https://example.com"

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            report = await analyze_headers("https://example.com")

        assert report.error is None
        assert report.grade in ("A+", "A")
        assert report.score >= 80
        assert "x-content-type-options" in report.headers_present
        assert report.server == "nginx"

    @pytest.mark.asyncio
    async def test_insecure_headers(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = SAMPLE_INSECURE_HEADERS
        mock_resp.url = "https://example.com"

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            report = await analyze_headers("https://example.com")

        assert report.error is None
        assert report.grade == "F"
        assert report.score < 50
        assert len(report.headers_missing) > 5
        assert len(report.warnings) > 0
        assert report.server == "Apache/2.4.49 (Ubuntu)"
        assert report.x_powered_by == "PHP/7.4.3"

    @pytest.mark.asyncio
    async def test_timeout_error(self):
        import httpx as _httpx

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=_httpx.TimeoutException("")):
            report = await analyze_headers("https://example.com")

        assert report.error is not None
        assert "Timeout" in report.error

    @pytest.mark.asyncio
    async def test_connection_error(self):
        import httpx as _httpx

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=_httpx.ConnectError("")):
            report = await analyze_headers("https://nonexistent.example.com")

        assert report.error is not None
        assert "Connection failed" in report.error

    @pytest.mark.asyncio
    async def test_redirect_handling(self):
        """The client follows redirects; final URL should be used."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
        }
        mock_resp.url = "https://www.example.com/"  # final URL after redirect

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            report = await analyze_headers("http://example.com")

        assert report.error is None
        # The report URL should reflect the final redirect target
        assert "www.example.com" in report.url

    @pytest.mark.asyncio
    async def test_empty_url_returns_error(self):
        report = await analyze_headers("")
        assert report.error is not None
        assert "required" in report.error.lower()

    @pytest.mark.asyncio
    async def test_url_without_scheme_gets_https(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"X-Content-Type-Options": "nosniff"}
        mock_resp.url = "https://example.com"

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp):
            report = await analyze_headers("example.com")

        assert report.error is None

    @pytest.mark.asyncio
    async def test_too_many_redirects(self):
        import httpx as _httpx

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=_httpx.TooManyRedirects("")):
            report = await analyze_headers("https://loop.example.com")

        assert report.error is not None
        assert "redirect" in report.error.lower()


# ---------------------------------------------------------------------------
# Integration tests (live sites)
# ---------------------------------------------------------------------------

class TestIntegration:

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_google_com(self):
        report = await analyze_headers("https://www.google.com")
        assert report.error is None
        assert report.grade in ("A+", "A", "B", "C", "D", "F")
        assert 0 <= report.score <= 100
        assert isinstance(report.headers_present, dict)
        assert isinstance(report.headers_missing, list)

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_example_com(self):
        report = await analyze_headers("https://example.com")
        assert report.error is None
        assert report.grade in ("A+", "A", "B", "C", "D", "F")
        assert 0 <= report.score <= 100

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_github_com(self):
        report = await analyze_headers("https://github.com")
        assert report.error is None
        # GitHub should have decent headers
        assert report.score >= 20
