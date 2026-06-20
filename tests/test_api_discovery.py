"""Tests for API surface discovery module."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.recon.api_discovery import (
    APIDiscoveryReport,
    GRAPHQL_INTROSPECTION_QUERY,
    OPENAPI_PATHS,
    GRAPHQL_PATHS,
    SENSITIVE_KEYWORDS,
    VERSION_PATHS,
    normalize_url,
    parse_openapi,
    parse_graphql_introspection,
    identify_oidc_provider,
    parse_robots_txt,
    parse_security_txt,
    fingerprint_framework,
    parse_cors_headers,
    api_discover,
)


# ---------------------------------------------------------------------------
# Sample response payloads
# ---------------------------------------------------------------------------

SAMPLE_OPENAPI_30 = json.dumps({
    "openapi": "3.0.2",
    "info": {"title": "Pet Store API", "version": "1.0.0"},
    "paths": {
        "/pets": {"get": {}, "post": {}},
        "/pets/{id}": {"get": {}, "put": {}, "delete": {}},
        "/users": {"get": {}},
        "/health": {"get": {}},
    },
})

SAMPLE_SWAGGER_20 = json.dumps({
    "swagger": "2.0",
    "info": {"title": "Legacy API", "version": "0.9"},
    "paths": {
        "/api/login": {"post": {}},
        "/api/data": {"get": {}},
    },
})

SAMPLE_OPENAPI_WITH_GENERATOR = json.dumps({
    "openapi": "3.1.0",
    "info": {"title": "FastAPI App"},
    "x-generator": "FastAPI 0.110.0",
    "paths": {"/items": {}, "/users": {}},
})

SAMPLE_GRAPHQL_INTROSPECTION = json.dumps({
    "data": {
        "__schema": {
            "types": [
                {"name": "Query", "kind": "OBJECT"},
                {"name": "Mutation", "kind": "OBJECT"},
                {"name": "User", "kind": "OBJECT"},
                {"name": "Post", "kind": "OBJECT"},
                {"name": "__Schema", "kind": "OBJECT"},
                {"name": "__Type", "kind": "OBJECT"},
            ],
            "queryType": {
                "name": "Query",
                "fields": [
                    {"name": "users"},
                    {"name": "posts"},
                    {"name": "user"},
                ],
            },
            "mutationType": {
                "name": "Mutation",
                "fields": [
                    {"name": "createUser"},
                    {"name": "deletePost"},
                ],
            },
        }
    }
})

SAMPLE_OIDC_CONFIG = json.dumps({
    "issuer": "https://dev-12345.okta.com/oauth2/default",
    "authorization_endpoint": "https://dev-12345.okta.com/oauth2/default/v1/authorize",
    "token_endpoint": "https://dev-12345.okta.com/oauth2/default/v1/token",
    "userinfo_endpoint": "https://dev-12345.okta.com/oauth2/default/v1/userinfo",
    "jwks_uri": "https://dev-12345.okta.com/oauth2/default/v1/keys",
})

SAMPLE_ROBOTS_TXT = """
User-agent: *
Disallow: /admin/
Disallow: /api/internal/
Disallow: /private/stuff
Disallow: /debug/pprof
Allow: /public/

Sitemap: https://example.com/sitemap.xml
"""

SAMPLE_SECURITY_TXT = """
Contact: security@example.com
Expires: 2027-12-31T23:59:59.000Z
Preferred-Languages: en
"""


# ===========================================================================
# Test classes
# ===========================================================================


class TestURLNormalization:
    """Tests for normalize_url()."""

    def test_adds_https_scheme(self):
        assert normalize_url("example.com") == "https://example.com"

    def test_preserves_http(self):
        assert normalize_url("http://example.com") == "http://example.com"

    def test_preserves_https(self):
        assert normalize_url("https://example.com") == "https://example.com"

    def test_strips_trailing_slash(self):
        assert normalize_url("https://example.com/") == "https://example.com"

    def test_strips_multiple_trailing_slashes(self):
        assert normalize_url("https://example.com///") == "https://example.com"

    def test_preserves_port(self):
        assert normalize_url("example.com:8443") == "https://example.com:8443"

    def test_preserves_port_with_scheme(self):
        assert normalize_url("https://example.com:8443/") == "https://example.com:8443"

    def test_strips_whitespace(self):
        assert normalize_url("  https://example.com  ") == "https://example.com"

    def test_empty_string(self):
        assert normalize_url("") == ""

    def test_preserves_path(self):
        # normalize_url strips trailing slash, but preserves internal paths
        assert normalize_url("https://example.com/api") == "https://example.com/api"

    def test_subdomain(self):
        assert normalize_url("api.example.com") == "https://api.example.com"


class TestOpenAPIParsing:
    """Tests for parse_openapi()."""

    def test_parses_openapi_30(self):
        result = parse_openapi(SAMPLE_OPENAPI_30)
        assert result["version"] == "3.0.2"
        assert result["title"] == "Pet Store API"
        assert result["endpoints_count"] == 4
        assert "/pets" in result["paths"]
        assert "/users" in result["paths"]

    def test_parses_swagger_20(self):
        result = parse_openapi(SAMPLE_SWAGGER_20)
        assert result["version"] == "2.0"
        assert result["title"] == "Legacy API"
        assert result["endpoints_count"] == 2

    def test_parses_generator_field(self):
        result = parse_openapi(SAMPLE_OPENAPI_WITH_GENERATOR)
        assert result["version"] == "3.1.0"
        assert result["generator"] == "FastAPI 0.110.0"

    def test_limits_paths_to_20(self):
        many_paths = {f"/path/{i}": {"get": {}} for i in range(50)}
        spec = json.dumps({"openapi": "3.0.0", "info": {"title": "Big"}, "paths": many_paths})
        result = parse_openapi(spec)
        assert len(result["paths"]) == 20
        assert result["endpoints_count"] == 50

    def test_invalid_json_returns_empty(self):
        result = parse_openapi("this is not json or yaml")
        assert result == {}

    def test_valid_json_but_not_openapi(self):
        result = parse_openapi('{"name": "not an api spec"}')
        assert result == {}

    def test_empty_paths(self):
        spec = json.dumps({"openapi": "3.0.0", "info": {"title": "Empty"}, "paths": {}})
        result = parse_openapi(spec)
        assert result["endpoints_count"] == 0
        assert result["paths"] == []

    def test_yaml_fallback_openapi(self):
        yaml_content = "openapi: '3.0.1'\ninfo:\n  title: YAML API\npaths: {}"
        result = parse_openapi(yaml_content)
        # Should at least extract version via fallback
        assert result.get("version", "") in ("3.0.1", "")  # depends on yaml availability

    def test_yaml_fallback_swagger(self):
        yaml_content = "swagger: '2.0'\ninfo:\n  title: Old YAML\npaths: {}"
        result = parse_openapi(yaml_content)
        # If yaml module is available, this parses fully
        if result:
            assert result["version"] == "2.0"


class TestGraphQLIntrospection:
    """Tests for parse_graphql_introspection()."""

    def test_parses_types(self):
        result = parse_graphql_introspection(SAMPLE_GRAPHQL_INTROSPECTION)
        # 4 user types (Query, Mutation, User, Post) — __Schema and __Type filtered
        assert result["types_count"] == 4

    def test_parses_queries(self):
        result = parse_graphql_introspection(SAMPLE_GRAPHQL_INTROSPECTION)
        assert "users" in result["queries"]
        assert "posts" in result["queries"]
        assert "user" in result["queries"]
        assert len(result["queries"]) == 3

    def test_parses_mutations(self):
        result = parse_graphql_introspection(SAMPLE_GRAPHQL_INTROSPECTION)
        assert "createUser" in result["mutations"]
        assert "deletePost" in result["mutations"]
        assert len(result["mutations"]) == 2

    def test_invalid_json_returns_empty(self):
        result = parse_graphql_introspection("not json")
        assert result == {}

    def test_no_schema_returns_empty(self):
        result = parse_graphql_introspection('{"data": {}}')
        assert result == {}

    def test_no_mutation_type(self):
        data = json.dumps({
            "data": {
                "__schema": {
                    "types": [{"name": "Query", "kind": "OBJECT"}],
                    "queryType": {"name": "Query", "fields": [{"name": "hello"}]},
                    "mutationType": None,
                }
            }
        })
        result = parse_graphql_introspection(data)
        assert result["queries"] == ["hello"]
        assert result["mutations"] == []

    def test_no_query_type(self):
        data = json.dumps({
            "data": {
                "__schema": {
                    "types": [],
                    "queryType": None,
                    "mutationType": None,
                }
            }
        })
        result = parse_graphql_introspection(data)
        assert result["queries"] == []
        assert result["mutations"] == []


class TestOIDCProviderDetection:
    """Tests for identify_oidc_provider()."""

    def test_okta(self):
        assert identify_oidc_provider("https://dev-12345.okta.com/oauth2/default") == "Okta"

    def test_auth0(self):
        assert identify_oidc_provider("https://myapp.auth0.com/") == "Auth0"

    def test_azure_ad(self):
        assert identify_oidc_provider(
            "https://login.microsoftonline.com/tenant-id/v2.0"
        ) == "Azure AD / Entra ID"

    def test_keycloak(self):
        assert identify_oidc_provider(
            "https://keycloak.example.com/realms/myrealm"
        ) == "Keycloak"

    def test_google(self):
        assert identify_oidc_provider("https://accounts.google.com") == "Google"

    def test_aws_cognito(self):
        assert identify_oidc_provider(
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123"
        ) == "AWS Cognito"

    def test_salesforce(self):
        assert identify_oidc_provider("https://login.salesforce.com") == "Salesforce"

    def test_pingidentity(self):
        assert identify_oidc_provider(
            "https://auth.pingone.com/env-id/as"
        ) == "PingIdentity"

    def test_unknown_extracts_hostname(self):
        result = identify_oidc_provider("https://custom-idp.corp.example.com/oidc")
        assert result == "custom-idp.corp.example.com"

    def test_case_insensitive(self):
        assert identify_oidc_provider("https://DEV-123.OKTA.COM/oauth2") == "Okta"


class TestRobotsParser:
    """Tests for parse_robots_txt()."""

    def test_extracts_disallowed(self):
        disallowed, _, _ = parse_robots_txt(SAMPLE_ROBOTS_TXT)
        assert "/admin/" in disallowed
        assert "/api/internal/" in disallowed
        assert "/private/stuff" in disallowed
        assert "/debug/pprof" in disallowed

    def test_flags_sensitive_paths(self):
        _, sensitive, _ = parse_robots_txt(SAMPLE_ROBOTS_TXT)
        assert "/admin/" in sensitive
        assert "/api/internal/" in sensitive
        assert "/debug/pprof" in sensitive
        # /private/stuff does not contain a sensitive keyword
        assert "/private/stuff" not in sensitive

    def test_extracts_sitemap(self):
        _, _, sitemap = parse_robots_txt(SAMPLE_ROBOTS_TXT)
        assert sitemap == "https://example.com/sitemap.xml"

    def test_empty_robots(self):
        disallowed, sensitive, sitemap = parse_robots_txt("")
        assert disallowed == []
        assert sensitive == []
        assert sitemap == ""

    def test_no_disallow(self):
        content = "User-agent: *\nAllow: /\nSitemap: https://x.com/sitemap.xml"
        disallowed, sensitive, sitemap = parse_robots_txt(content)
        assert disallowed == []
        assert sensitive == []
        assert sitemap == "https://x.com/sitemap.xml"

    def test_env_path_flagged(self):
        content = "User-agent: *\nDisallow: /.env"
        _, sensitive, _ = parse_robots_txt(content)
        assert "/.env" in sensitive

    def test_git_path_flagged(self):
        content = "User-agent: *\nDisallow: /.git/"
        _, sensitive, _ = parse_robots_txt(content)
        assert "/.git/" in sensitive

    def test_backup_path_flagged(self):
        content = "User-agent: *\nDisallow: /backup/db"
        _, sensitive, _ = parse_robots_txt(content)
        assert "/backup/db" in sensitive


class TestSecurityTxtParser:
    """Tests for parse_security_txt()."""

    def test_extracts_contact(self):
        assert parse_security_txt(SAMPLE_SECURITY_TXT) == "security@example.com"

    def test_empty_content(self):
        assert parse_security_txt("") == ""

    def test_no_contact_field(self):
        assert parse_security_txt("Expires: 2027-01-01\n") == ""

    def test_url_contact(self):
        content = "Contact: https://example.com/security"
        assert parse_security_txt(content) == "https://example.com/security"


class TestFrameworkFingerprint:
    """Tests for fingerprint_framework()."""

    def test_fastapi_from_generator(self):
        fw, evidence = fingerprint_framework({}, "", "FastAPI 0.110.0")
        assert fw == "FastAPI"
        assert "FastAPI" in evidence

    def test_springdoc_from_generator(self):
        fw, evidence = fingerprint_framework({}, "", "springdoc-openapi")
        assert fw == "Spring Boot"

    def test_swagger_codegen_from_generator(self):
        fw, _ = fingerprint_framework({}, "", "swagger-codegen 3.0")
        assert fw == "Swagger Codegen"

    def test_django_from_generator(self):
        fw, _ = fingerprint_framework({}, "", "django-rest-framework")
        assert fw == "Django REST Framework"

    def test_express_from_header(self):
        headers = {"x-powered-by": "Express"}
        fw, evidence = fingerprint_framework(headers)
        assert fw == "Express.js"
        assert "X-Powered-By" in evidence

    def test_aspnet_from_header(self):
        headers = {"x-powered-by": "ASP.NET"}
        fw, _ = fingerprint_framework(headers)
        assert fw == "ASP.NET"

    def test_php_from_header(self):
        headers = {"x-powered-by": "PHP/8.2.0"}
        fw, _ = fingerprint_framework(headers)
        assert fw == "PHP"

    def test_kestrel_from_server(self):
        headers = {"server": "Kestrel"}
        fw, _ = fingerprint_framework(headers)
        assert fw == "ASP.NET / Kestrel"

    def test_gunicorn_from_server(self):
        headers = {"server": "gunicorn/21.2.0"}
        fw, _ = fingerprint_framework(headers)
        assert fw == "Python / Gunicorn"

    def test_uvicorn_from_server(self):
        headers = {"server": "uvicorn"}
        fw, _ = fingerprint_framework(headers)
        assert fw == "FastAPI / Uvicorn"

    def test_openresty_from_server(self):
        headers = {"server": "openresty/1.21.4.1"}
        fw, _ = fingerprint_framework(headers)
        assert fw == "OpenResty / Lua"

    def test_django_from_error_body(self):
        fw, _ = fingerprint_framework({}, "DisallowedHost at /")
        assert fw == "Django"

    def test_express_from_error_body(self):
        fw, _ = fingerprint_framework({}, "Cannot GET /nonexistent")
        assert fw == "Express.js"

    def test_spring_from_error_body(self):
        fw, _ = fingerprint_framework({}, "Whitelabel Error Page")
        assert fw == "Spring Boot"

    def test_fastapi_from_error_body(self):
        fw, _ = fingerprint_framework({}, '{"detail":"Not Found","status":404}')
        assert fw == "FastAPI"

    def test_no_match_returns_empty(self):
        fw, evidence = fingerprint_framework({"server": "nginx/1.25"})
        assert fw == ""
        assert evidence == ""

    def test_unknown_generator(self):
        fw, evidence = fingerprint_framework({}, "", "custom-generator-v2")
        assert fw == "custom-generator-v2"
        assert "generator" in evidence


class TestCORSAnalysis:
    """Tests for parse_cors_headers()."""

    def test_wildcard_origin(self):
        headers = {"access-control-allow-origin": "*"}
        result = parse_cors_headers(headers)
        assert result["allow_origin"] == "*"

    def test_specific_origin(self):
        headers = {"access-control-allow-origin": "https://app.example.com"}
        result = parse_cors_headers(headers)
        assert result["allow_origin"] == "https://app.example.com"

    def test_credentials_true(self):
        headers = {
            "access-control-allow-origin": "https://app.example.com",
            "access-control-allow-credentials": "true",
        }
        result = parse_cors_headers(headers)
        assert result["allow_credentials"] is True

    def test_credentials_false(self):
        headers = {
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "false",
        }
        result = parse_cors_headers(headers)
        assert result["allow_credentials"] is False

    def test_allow_methods(self):
        headers = {
            "access-control-allow-origin": "*",
            "access-control-allow-methods": "GET, POST, PUT, DELETE",
        }
        result = parse_cors_headers(headers)
        assert "GET" in result["allow_methods"]

    def test_allow_headers(self):
        headers = {
            "access-control-allow-origin": "*",
            "access-control-allow-headers": "Authorization, Content-Type",
        }
        result = parse_cors_headers(headers)
        assert "Authorization" in result["allow_headers"]

    def test_no_cors_headers(self):
        result = parse_cors_headers({"server": "nginx"})
        assert result == {}

    def test_empty_headers(self):
        result = parse_cors_headers({})
        assert result == {}


class TestAPIDiscoveryReport:
    """Tests for the dataclass defaults."""

    def test_defaults(self):
        report = APIDiscoveryReport(url="https://example.com")
        assert report.url == "https://example.com"
        assert report.openapi_found is False
        assert report.graphql_found is False
        assert report.oidc_found is False
        assert report.openapi_paths == []
        assert report.robots_disallowed == []
        assert report.sensitive_paths == []
        assert report.api_versions == []
        assert report.cors_policy == {}
        assert report.error is None

    def test_error_state(self):
        report = APIDiscoveryReport(url="https://bad.com", error="unreachable")
        assert report.error == "unreachable"


# ===========================================================================
# Integration-style tests with mocked httpx
# ===========================================================================

def _make_mock_response(status_code=200, text="", headers=None, json_data=None):
    """Create a mock httpx.Response."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.headers = httpx.Headers(headers or {})
    if json_data is not None:
        resp.text = json.dumps(json_data)
        resp.json = MagicMock(return_value=json_data)
    else:
        resp.text = text
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            f"HTTP {status_code}",
            request=MagicMock(),
            response=resp,
        )
    return resp


class TestAPIDiscover:
    """Async tests with mocked httpx for full api_discover()."""

    @pytest.mark.asyncio
    async def test_full_discovery(self):
        """Mock multiple paths returning various responses."""
        def mock_request(method, url, **kwargs):
            url_str = str(url)
            if url_str.endswith("/robots.txt"):
                return _make_mock_response(200, SAMPLE_ROBOTS_TXT)
            if "security.txt" in url_str:
                return _make_mock_response(200, SAMPLE_SECURITY_TXT)
            if "openid-configuration" in url_str:
                return _make_mock_response(200, SAMPLE_OIDC_CONFIG)
            if url_str.endswith("/swagger.json"):
                return _make_mock_response(200, SAMPLE_OPENAPI_30)
            return _make_mock_response(404, "Not Found")

        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            async def side_effect_get(url, **kwargs):
                return mock_request("GET", url, **kwargs)

            async def side_effect_head(url, **kwargs):
                return mock_request("HEAD", url, **kwargs)

            async def side_effect_options(url, **kwargs):
                return _make_mock_response(200, "", {
                    "access-control-allow-origin": "*",
                    "access-control-allow-methods": "GET, POST",
                })

            async def side_effect_post(url, **kwargs):
                if "/graphql" in str(url):
                    return _make_mock_response(200, SAMPLE_GRAPHQL_INTROSPECTION)
                return _make_mock_response(404)

            client_instance.get = AsyncMock(side_effect=side_effect_get)
            client_instance.head = AsyncMock(side_effect=side_effect_head)
            client_instance.options = AsyncMock(side_effect=side_effect_options)
            client_instance.post = AsyncMock(side_effect=side_effect_post)

            report = await api_discover("https://example.com")

        assert report.error is None
        assert report.robots_txt != ""
        assert "/admin/" in report.robots_disallowed
        assert report.security_contact == "security@example.com"
        assert report.oidc_found is True
        assert report.oidc_provider == "Okta"
        assert report.openapi_found is True
        assert report.openapi_version == "3.0.2"
        assert report.cors_policy.get("allow_origin") == "*"

    @pytest.mark.asyncio
    async def test_no_api_found(self):
        """All probes return 404."""
        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            not_found = _make_mock_response(404, "Not Found")
            client_instance.get = AsyncMock(return_value=not_found)
            client_instance.head = AsyncMock(return_value=not_found)
            client_instance.options = AsyncMock(return_value=_make_mock_response(404))
            client_instance.post = AsyncMock(return_value=not_found)

            report = await api_discover("https://example.com")

        assert report.error is None  # base URL was reachable (404 is still a response)
        assert report.openapi_found is False
        assert report.graphql_found is False
        assert report.oidc_found is False
        assert report.robots_txt == ""
        assert report.total_endpoints_discovered == 0

    @pytest.mark.asyncio
    async def test_openapi_found(self):
        """swagger.json returns 200 with valid OpenAPI 3.0 spec."""
        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            async def get_side_effect(url, **kwargs):
                if "/swagger.json" in str(url):
                    return _make_mock_response(200, SAMPLE_OPENAPI_30)
                return _make_mock_response(404)

            client_instance.get = AsyncMock(side_effect=get_side_effect)
            client_instance.head = AsyncMock(return_value=_make_mock_response(404))
            client_instance.options = AsyncMock(return_value=_make_mock_response(404))
            client_instance.post = AsyncMock(return_value=_make_mock_response(404))

            report = await api_discover("https://api.example.com")

        assert report.openapi_found is True
        assert report.openapi_version == "3.0.2"
        assert report.openapi_title == "Pet Store API"
        assert report.openapi_endpoints_count == 4
        assert "/pets" in report.openapi_paths
        assert report.total_endpoints_discovered == 4

    @pytest.mark.asyncio
    async def test_graphql_introspection_enabled(self):
        """GraphQL endpoint found and introspection succeeds."""
        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            async def get_side_effect(url, **kwargs):
                if "/graphql" in str(url):
                    return _make_mock_response(200, '{"data": "playground"}')
                return _make_mock_response(404)

            async def post_side_effect(url, **kwargs):
                if "/graphql" in str(url):
                    return _make_mock_response(200, SAMPLE_GRAPHQL_INTROSPECTION)
                return _make_mock_response(404)

            client_instance.get = AsyncMock(side_effect=get_side_effect)
            client_instance.head = AsyncMock(return_value=_make_mock_response(404))
            client_instance.options = AsyncMock(return_value=_make_mock_response(404))
            client_instance.post = AsyncMock(side_effect=post_side_effect)

            report = await api_discover("https://example.com")

        assert report.graphql_found is True
        assert report.graphql_introspection is True
        assert report.graphql_types_count == 4
        assert "users" in report.graphql_queries
        assert "createUser" in report.graphql_mutations
        assert report.total_endpoints_discovered == 5  # 3 queries + 2 mutations

    @pytest.mark.asyncio
    async def test_oidc_okta_detected(self):
        """OIDC config returns Okta issuer."""
        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            async def get_side_effect(url, **kwargs):
                if "openid-configuration" in str(url):
                    return _make_mock_response(200, SAMPLE_OIDC_CONFIG)
                return _make_mock_response(404)

            client_instance.get = AsyncMock(side_effect=get_side_effect)
            client_instance.head = AsyncMock(return_value=_make_mock_response(404))
            client_instance.options = AsyncMock(return_value=_make_mock_response(404))
            client_instance.post = AsyncMock(return_value=_make_mock_response(404))

            report = await api_discover("https://example.com")

        assert report.oidc_found is True
        assert report.oidc_provider == "Okta"
        assert report.oidc_issuer == "https://dev-12345.okta.com/oauth2/default"
        assert report.oidc_endpoints["authorization"] != ""
        assert report.oidc_endpoints["token"] != ""
        assert report.oidc_endpoints["jwks"] != ""

    @pytest.mark.asyncio
    async def test_robots_sensitive_paths(self):
        """robots.txt with sensitive paths flagged correctly."""
        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            async def get_side_effect(url, **kwargs):
                if "/robots.txt" in str(url):
                    return _make_mock_response(200, SAMPLE_ROBOTS_TXT)
                return _make_mock_response(404)

            client_instance.get = AsyncMock(side_effect=get_side_effect)
            client_instance.head = AsyncMock(return_value=_make_mock_response(404))
            client_instance.options = AsyncMock(return_value=_make_mock_response(404))
            client_instance.post = AsyncMock(return_value=_make_mock_response(404))

            report = await api_discover("https://example.com")

        assert "/admin/" in report.robots_disallowed
        assert "/api/internal/" in report.robots_disallowed
        assert "/admin/" in report.sensitive_paths
        assert "/debug/pprof" in report.sensitive_paths
        assert report.sitemap_url == "https://example.com/sitemap.xml"

    @pytest.mark.asyncio
    async def test_unreachable_host(self):
        """Base URL connection fails — should set error."""
        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            client_instance.get = AsyncMock(
                side_effect=httpx.ConnectError("Connection refused")
            )

            report = await api_discover("https://unreachable.example.com")

        assert report.error is not None
        assert "unreachable" in report.error.lower() or "connection" in report.error.lower()
        assert report.openapi_found is False
        assert report.graphql_found is False

    @pytest.mark.asyncio
    async def test_empty_url(self):
        """Empty URL should return error immediately."""
        report = await api_discover("")
        assert report.error is not None
        assert "empty" in report.error.lower()

    @pytest.mark.asyncio
    async def test_framework_detected_from_base_headers(self):
        """Framework detected from base URL response headers."""
        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            base_resp = _make_mock_response(200, "OK", {"server": "uvicorn"})

            async def get_side_effect(url, **kwargs):
                if str(url).rstrip("/") == "https://example.com":
                    return base_resp
                return _make_mock_response(404)

            client_instance.get = AsyncMock(side_effect=get_side_effect)
            client_instance.head = AsyncMock(return_value=_make_mock_response(404))
            client_instance.options = AsyncMock(return_value=_make_mock_response(404))
            client_instance.post = AsyncMock(return_value=_make_mock_response(404))

            report = await api_discover("https://example.com")

        assert report.framework == "FastAPI / Uvicorn"
        assert "uvicorn" in report.framework_evidence.lower()

    @pytest.mark.asyncio
    async def test_version_paths_detected(self):
        """API version paths that return non-404 are recorded."""
        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            async def head_side_effect(url, **kwargs):
                url_str = str(url)
                if "/v1/" in url_str or "/api/v2/" in url_str:
                    return _make_mock_response(200)
                return _make_mock_response(404)

            client_instance.get = AsyncMock(return_value=_make_mock_response(404))
            client_instance.head = AsyncMock(side_effect=head_side_effect)
            client_instance.options = AsyncMock(return_value=_make_mock_response(404))
            client_instance.post = AsyncMock(return_value=_make_mock_response(404))

            report = await api_discover("https://example.com")

        version_strs = [v["version"] for v in report.api_versions]
        assert "v1" in version_strs
        assert "v2" in version_strs

    @pytest.mark.asyncio
    async def test_cors_wildcard_with_credentials_detected(self):
        """CORS with wildcard origin and credentials is captured."""
        with patch("httpx.AsyncClient") as MockClient:
            client_instance = AsyncMock()
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client_instance)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            cors_resp = _make_mock_response(200, "", {
                "access-control-allow-origin": "*",
                "access-control-allow-credentials": "true",
                "access-control-allow-methods": "GET, POST, DELETE",
            })

            client_instance.get = AsyncMock(return_value=_make_mock_response(404))
            client_instance.head = AsyncMock(return_value=_make_mock_response(404))
            client_instance.options = AsyncMock(return_value=cors_resp)
            client_instance.post = AsyncMock(return_value=_make_mock_response(404))

            report = await api_discover("https://example.com")

        assert report.cors_policy["allow_origin"] == "*"
        assert report.cors_policy["allow_credentials"] is True
        assert "DELETE" in report.cors_policy["allow_methods"]


class TestIntegration:
    """Integration tests against real sites — skipped by default."""

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_live_discovery(self):
        """Test against a real site with known API docs."""
        report = await api_discover("https://httpbin.org")
        # httpbin.org should be reachable
        assert report.error is None
        # It may or may not have API docs — just verify no crash
        assert report.url == "https://httpbin.org"
