"""API surface discovery module — passive Tier 1 reconnaissance.

Probes well-known paths to discover published API documentation,
GraphQL endpoints, OIDC/OAuth configurations, and standard discovery
files (robots.txt, security.txt). Completely passive — only checks
paths that legitimate clients would access.
"""

from __future__ import annotations

import asyncio
import json as json_module
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

# ---------------------------------------------------------------------------
# Probe path lists
# ---------------------------------------------------------------------------

OPENAPI_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/openapi.json", "/openapi.yaml", "/openapi/v1/openapi.json",
    "/api-docs", "/api/docs", "/api/swagger.json",
    "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
    "/docs/api", "/api/v1/docs", "/api/v2/docs",
    "/redoc", "/api/redoc",
]

GRAPHQL_PATHS = ["/graphql", "/gql", "/api/graphql", "/graphql/v1"]

WELL_KNOWN_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/security.txt",
    "/security.txt",
    "/.well-known/change-password",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
]

VERSION_PATHS = ["/v1/", "/v2/", "/v3/", "/api/v1/", "/api/v2/", "/api/v3/"]

WSDL_PATHS = ["/?wsdl", "/services?wsdl", "/ws?wsdl"]

# Paths whose presence is noteworthy from a security standpoint
SENSITIVE_KEYWORDS = [
    "admin", "internal", "debug", "config", "env", "test",
    "staging", "graphiql", "playground", ".git", "backup",
]

# GraphQL introspection query — compact
GRAPHQL_INTROSPECTION_QUERY = (
    '{"query": "{__schema{types{name kind}'
    'queryType{name fields{name}}'
    'mutationType{name fields{name}}}}"}'
)

TIMEOUT = 10.0
SEMAPHORE_LIMIT = 5


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass
class APIDiscoveryReport:
    """Results of API surface discovery for a target URL."""

    url: str

    # OpenAPI / Swagger
    openapi_found: bool = False
    openapi_url: str = ""
    openapi_version: str = ""      # "2.0", "3.0", "3.1"
    openapi_title: str = ""
    openapi_endpoints_count: int = 0
    openapi_paths: list[str] = field(default_factory=list)  # first 20

    # GraphQL
    graphql_found: bool = False
    graphql_url: str = ""
    graphql_introspection: bool = False
    graphql_types_count: int = 0
    graphql_queries: list[str] = field(default_factory=list)
    graphql_mutations: list[str] = field(default_factory=list)

    # Standard discovery files
    robots_txt: str = ""
    robots_disallowed: list[str] = field(default_factory=list)
    sitemap_url: str = ""
    security_txt: str = ""
    security_contact: str = ""

    # OIDC / Auth discovery
    oidc_found: bool = False
    oidc_issuer: str = ""
    oidc_provider: str = ""         # "Okta", "Auth0", "Azure AD", etc.
    oidc_endpoints: dict = field(default_factory=dict)

    # API versioning
    api_versions: list[dict] = field(default_factory=list)

    # Framework fingerprint
    framework: str = ""
    framework_evidence: str = ""

    # CORS
    cors_policy: dict = field(default_factory=dict)

    # Summary
    total_endpoints_discovered: int = 0
    sensitive_paths: list[str] = field(default_factory=list)

    error: str | None = None


# ---------------------------------------------------------------------------
# URL normalisation
# ---------------------------------------------------------------------------

def normalize_url(url: str) -> str:
    """Ensure *url* has a scheme and no trailing slash.

    >>> normalize_url("example.com")
    'https://example.com'
    >>> normalize_url("http://example.com/")
    'http://example.com'
    >>> normalize_url("https://example.com:8443/")
    'https://example.com:8443'
    """
    url = url.strip()
    if not url:
        return url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_openapi(body: str) -> dict:
    """Parse an OpenAPI/Swagger spec and extract key fields.

    Returns a dict with keys: version, title, paths, endpoints_count.
    Returns an empty dict if parsing fails.
    """
    try:
        spec = json_module.loads(body)
    except (json_module.JSONDecodeError, ValueError):
        # Attempt YAML (best-effort: look for openapi:/swagger: lines)
        spec = _parse_yaml_fallback(body)
        if spec is None:
            return {}

    result: dict = {}

    # OpenAPI 3.x
    if "openapi" in spec:
        result["version"] = str(spec["openapi"])
    # Swagger 2.0
    elif "swagger" in spec:
        result["version"] = str(spec["swagger"])
    else:
        return {}

    info = spec.get("info", {})
    result["title"] = info.get("title", "")

    paths = spec.get("paths", {})
    path_names = sorted(paths.keys())
    result["endpoints_count"] = len(path_names)
    result["paths"] = path_names[:20]

    # Framework hints from x-generator / info.description
    generator = spec.get("x-generator", "") or info.get("x-generator", "")
    if generator:
        result["generator"] = generator

    return result


def _parse_yaml_fallback(body: str) -> dict | None:
    """Minimal YAML-like extraction for openapi/swagger specs.

    Only handles the trivial case where the spec is valid JSON-ish YAML
    (no anchors, no multi-doc). Returns None if nothing useful found.
    """
    try:
        import yaml  # type: ignore
        return yaml.safe_load(body)
    except Exception:
        pass

    # Ultra-minimal: just look for key fields in a line-based fashion
    lines = body.splitlines()
    version = ""
    title = ""
    for line in lines[:30]:
        stripped = line.strip()
        if stripped.startswith("openapi:"):
            version = stripped.split(":", 1)[1].strip().strip("'\"")
        elif stripped.startswith("swagger:"):
            version = stripped.split(":", 1)[1].strip().strip("'\"")
        elif stripped.startswith("title:"):
            title = stripped.split(":", 1)[1].strip().strip("'\"")
    if version:
        return {"openapi": version, "info": {"title": title}, "paths": {}}
    return None


def parse_graphql_introspection(body: str) -> dict:
    """Parse a GraphQL introspection response.

    Returns dict with keys: types_count, queries, mutations.
    Returns empty dict on failure.
    """
    try:
        data = json_module.loads(body)
    except (json_module.JSONDecodeError, ValueError):
        return {}

    schema = data.get("data", {}).get("__schema", {})
    if not schema:
        return {}

    result: dict = {}

    # Types (filter out builtins starting with __)
    all_types = schema.get("types", [])
    user_types = [t for t in all_types if not t.get("name", "").startswith("__")]
    result["types_count"] = len(user_types)

    # Queries
    query_type = schema.get("queryType", {})
    if query_type:
        fields = query_type.get("fields", []) or []
        result["queries"] = [f.get("name", "") for f in fields if f.get("name")]
    else:
        result["queries"] = []

    # Mutations
    mutation_type = schema.get("mutationType", {})
    if mutation_type:
        fields = mutation_type.get("fields", []) or []
        result["mutations"] = [f.get("name", "") for f in fields if f.get("name")]
    else:
        result["mutations"] = []

    return result


def identify_oidc_provider(issuer: str) -> str:
    """Identify the OIDC provider from the issuer URL.

    >>> identify_oidc_provider("https://dev-123.okta.com/oauth2/default")
    'Okta'
    >>> identify_oidc_provider("https://login.microsoftonline.com/tenant-id/v2.0")
    'Azure AD / Entra ID'
    """
    issuer_lower = issuer.lower()
    if "okta.com" in issuer_lower:
        return "Okta"
    if "auth0.com" in issuer_lower:
        return "Auth0"
    if "login.microsoftonline.com" in issuer_lower:
        return "Azure AD / Entra ID"
    if "/realms/" in issuer_lower:
        return "Keycloak"
    if "accounts.google.com" in issuer_lower:
        return "Google"
    if "cognito-idp" in issuer_lower:
        return "AWS Cognito"
    if "login.salesforce.com" in issuer_lower:
        return "Salesforce"
    if "pingidentity" in issuer_lower or "pingone" in issuer_lower:
        return "PingIdentity"
    # Fallback — extract hostname
    try:
        parsed = urlparse(issuer)
        return parsed.hostname or issuer
    except Exception:
        return issuer


def parse_robots_txt(body: str) -> tuple[list[str], list[str], str]:
    """Parse robots.txt content.

    Returns (disallowed, sensitive, sitemap_url).
    """
    disallowed: list[str] = []
    sensitive: list[str] = []
    sitemap_url = ""

    for line in body.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                disallowed.append(path)
                path_lower = path.lower()
                if any(kw in path_lower for kw in SENSITIVE_KEYWORDS):
                    sensitive.append(path)
        elif line.lower().startswith("sitemap:"):
            sitemap_url = line.split(":", 1)[1].strip()
            # Re-join if the URL was split on the colon in https://
            if sitemap_url and not sitemap_url.startswith("http"):
                # e.g. "Sitemap: https://..." was split at the first ':'
                rest = line.split(":", 2)
                if len(rest) >= 3:
                    sitemap_url = rest[1].strip() + ":" + rest[2].strip()

    return disallowed, sensitive, sitemap_url


def parse_security_txt(body: str) -> str:
    """Extract the Contact field from security.txt."""
    for line in body.splitlines():
        line = line.strip()
        if line.lower().startswith("contact:"):
            return line.split(":", 1)[1].strip()
    return ""


def fingerprint_framework(
    headers: dict[str, str],
    body: str = "",
    openapi_generator: str = "",
) -> tuple[str, str]:
    """Detect API framework from response headers, body, or OpenAPI generator.

    Returns (framework_name, evidence_string).
    """
    # Check OpenAPI generator hint first
    if openapi_generator:
        gen_lower = openapi_generator.lower()
        if "fastapi" in gen_lower:
            return "FastAPI", f"OpenAPI generator: {openapi_generator}"
        if "swagger-codegen" in gen_lower:
            return "Swagger Codegen", f"OpenAPI generator: {openapi_generator}"
        if "springdoc" in gen_lower or "springfox" in gen_lower:
            return "Spring Boot", f"OpenAPI generator: {openapi_generator}"
        if "django" in gen_lower:
            return "Django REST Framework", f"OpenAPI generator: {openapi_generator}"
        return openapi_generator, f"OpenAPI generator: {openapi_generator}"

    # Response headers
    powered_by = headers.get("x-powered-by", "").lower()
    server = headers.get("server", "").lower()

    if "express" in powered_by:
        return "Express.js", f"X-Powered-By: {headers.get('x-powered-by', '')}"
    if "asp.net" in powered_by:
        return "ASP.NET", f"X-Powered-By: {headers.get('x-powered-by', '')}"
    if "php" in powered_by:
        return "PHP", f"X-Powered-By: {headers.get('x-powered-by', '')}"
    if "kestrel" in server:
        return "ASP.NET / Kestrel", f"Server: {headers.get('server', '')}"
    if "gunicorn" in server:
        return "Python / Gunicorn", f"Server: {headers.get('server', '')}"
    if "uvicorn" in server:
        return "FastAPI / Uvicorn", f"Server: {headers.get('server', '')}"
    if "nginx" in server:
        # nginx is a proxy, not a framework — note it but don't claim a framework
        pass
    if "openresty" in server:
        return "OpenResty / Lua", f"Server: {headers.get('server', '')}"

    # Error page format heuristics
    body_lower = body.lower() if body else ""
    if "disallowedhost" in body_lower:
        return "Django", "Error page: DisallowedHost"
    if "cannot get" in body_lower or "cannot post" in body_lower:
        return "Express.js", "Error page: Cannot GET/POST"
    if "whitelabel error" in body_lower:
        return "Spring Boot", "Error page: Whitelabel Error"
    if '"detail":' in body_lower and '"status":' in body_lower:
        return "FastAPI", "Error response format: detail+status"

    return "", ""


def parse_cors_headers(headers: dict[str, str]) -> dict:
    """Extract CORS policy from response headers.

    Returns dict with allow_origin, allow_credentials, allow_methods, allow_headers.
    """
    result: dict = {}
    origin = headers.get("access-control-allow-origin", "")
    if origin:
        result["allow_origin"] = origin
    creds = headers.get("access-control-allow-credentials", "")
    if creds:
        result["allow_credentials"] = creds.lower() == "true"
    methods = headers.get("access-control-allow-methods", "")
    if methods:
        result["allow_methods"] = methods
    allow_headers = headers.get("access-control-allow-headers", "")
    if allow_headers:
        result["allow_headers"] = allow_headers
    return result


# ---------------------------------------------------------------------------
# Probe helpers
# ---------------------------------------------------------------------------

async def _probe_path(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
    semaphore: asyncio.Semaphore,
    method: str = "GET",
) -> tuple[str, int, dict[str, str], str]:
    """Probe a single path and return (full_url, status, headers, body).

    Returns status 0 on connection/timeout errors.
    """
    full_url = base_url + path
    async with semaphore:
        try:
            if method == "HEAD":
                resp = await client.head(full_url)
                return full_url, resp.status_code, dict(resp.headers), ""
            elif method == "OPTIONS":
                resp = await client.options(
                    full_url,
                    headers={"Origin": "https://evil.com"},
                )
                return full_url, resp.status_code, dict(resp.headers), ""
            else:
                resp = await client.get(full_url)
                body = resp.text[:100_000]  # cap body size
                return full_url, resp.status_code, dict(resp.headers), body
        except (httpx.RequestError, httpx.TimeoutException):
            return full_url, 0, {}, ""


async def _probe_graphql(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
    semaphore: asyncio.Semaphore,
) -> tuple[str, bool, str]:
    """Probe a GraphQL endpoint — GET first, then POST introspection.

    Returns (full_url, endpoint_found, introspection_body).
    """
    full_url = base_url + path
    async with semaphore:
        try:
            # GET — many GraphQL endpoints return 200 or 400 to a bare GET
            resp = await client.get(full_url)
            if resp.status_code not in (200, 400):
                return full_url, False, ""

            # Endpoint exists — try introspection via POST
            introspection_body = ""
            try:
                intro_resp = await client.post(
                    full_url,
                    content=GRAPHQL_INTROSPECTION_QUERY,
                    headers={"Content-Type": "application/json"},
                )
                if intro_resp.status_code == 200:
                    introspection_body = intro_resp.text[:100_000]
            except (httpx.RequestError, httpx.TimeoutException):
                pass

            return full_url, True, introspection_body
        except (httpx.RequestError, httpx.TimeoutException):
            return full_url, False, ""


# ---------------------------------------------------------------------------
# Main discovery function
# ---------------------------------------------------------------------------

async def api_discover(url: str) -> APIDiscoveryReport:
    """Discover published API surfaces for a target URL.

    Probes well-known paths for OpenAPI/Swagger docs, GraphQL endpoints,
    OIDC configuration, robots.txt, security.txt, CORS policy, and
    API versioning. All probes are passive Tier 1 — only accessing
    paths that legitimate clients would request.

    Args:
        url: Base URL of the target (e.g. "https://api.example.com").

    Returns:
        APIDiscoveryReport with all discovered information.
    """
    base_url = normalize_url(url)
    if not base_url:
        return APIDiscoveryReport(url=url, error="Empty URL provided")

    report = APIDiscoveryReport(url=base_url)
    semaphore = asyncio.Semaphore(SEMAPHORE_LIMIT)

    # -------------------------------------------------------------------
    # Check base URL reachability first
    # -------------------------------------------------------------------
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=TIMEOUT,
        ) as client:
            try:
                base_resp = await client.get(base_url)
                base_headers = dict(base_resp.headers)
                base_body = base_resp.text[:100_000]
            except (httpx.RequestError, httpx.TimeoutException) as exc:
                report.error = f"Base URL unreachable: {exc}"
                return report

            # -----------------------------------------------------------
            # Batch 1 — robots.txt, security.txt, OIDC, CORS (parallel)
            # -----------------------------------------------------------
            batch1_tasks = [
                _probe_path(client, base_url, "/robots.txt", semaphore),
                _probe_path(client, base_url, "/.well-known/security.txt", semaphore),
                _probe_path(client, base_url, "/security.txt", semaphore),
                _probe_path(client, base_url, "/.well-known/openid-configuration", semaphore),
                _probe_path(client, base_url, "", semaphore, method="OPTIONS"),
            ]
            batch1_results = await asyncio.gather(*batch1_tasks)

            # robots.txt
            _url, status, _hdrs, body = batch1_results[0]
            if status == 200 and body.strip():
                report.robots_txt = body
                disallowed, sensitive, sitemap = parse_robots_txt(body)
                report.robots_disallowed = disallowed
                report.sensitive_paths.extend(sensitive)
                if sitemap:
                    report.sitemap_url = sitemap

            # security.txt (.well-known first, then root fallback)
            for idx in (1, 2):
                _url, status, _hdrs, body = batch1_results[idx]
                if status == 200 and body.strip():
                    report.security_txt = body
                    report.security_contact = parse_security_txt(body)
                    break

            # OIDC
            _url, status, _hdrs, body = batch1_results[3]
            if status == 200 and body.strip():
                try:
                    oidc_data = json_module.loads(body)
                    report.oidc_found = True
                    report.oidc_issuer = oidc_data.get("issuer", "")
                    report.oidc_provider = identify_oidc_provider(report.oidc_issuer)
                    report.oidc_endpoints = {
                        "authorization": oidc_data.get("authorization_endpoint", ""),
                        "token": oidc_data.get("token_endpoint", ""),
                        "userinfo": oidc_data.get("userinfo_endpoint", ""),
                        "jwks": oidc_data.get("jwks_uri", ""),
                    }
                except (json_module.JSONDecodeError, ValueError):
                    pass

            # CORS (from OPTIONS preflight)
            _url, status, hdrs, _body = batch1_results[4]
            if status and hdrs:
                cors = parse_cors_headers(hdrs)
                if cors:
                    report.cors_policy = cors

            # -----------------------------------------------------------
            # Batch 2 — OpenAPI, GraphQL, version paths (parallel)
            # -----------------------------------------------------------
            openapi_tasks = [
                _probe_path(client, base_url, p, semaphore)
                for p in OPENAPI_PATHS
            ]
            graphql_tasks = [
                _probe_graphql(client, base_url, p, semaphore)
                for p in GRAPHQL_PATHS
            ]
            version_tasks = [
                _probe_path(client, base_url, p, semaphore, method="HEAD")
                for p in VERSION_PATHS
            ]

            all_batch2 = await asyncio.gather(
                asyncio.gather(*openapi_tasks),
                asyncio.gather(*graphql_tasks),
                asyncio.gather(*version_tasks),
            )

            openapi_results = all_batch2[0]
            graphql_results = all_batch2[1]
            version_results = all_batch2[2]

            # --- Process OpenAPI results (first 200 wins) ---
            openapi_generator = ""
            for probe_url, status, hdrs, body in openapi_results:
                if status == 200 and body.strip():
                    parsed = parse_openapi(body)
                    if parsed:
                        report.openapi_found = True
                        report.openapi_url = probe_url
                        report.openapi_version = parsed.get("version", "")
                        report.openapi_title = parsed.get("title", "")
                        report.openapi_endpoints_count = parsed.get("endpoints_count", 0)
                        report.openapi_paths = parsed.get("paths", [])
                        openapi_generator = parsed.get("generator", "")
                        break  # first valid spec wins

            # --- Process GraphQL results ---
            for gql_url, found, intro_body in graphql_results:
                if found:
                    report.graphql_found = True
                    report.graphql_url = gql_url
                    if intro_body:
                        introspection = parse_graphql_introspection(intro_body)
                        if introspection:
                            report.graphql_introspection = True
                            report.graphql_types_count = introspection.get("types_count", 0)
                            report.graphql_queries = introspection.get("queries", [])
                            report.graphql_mutations = introspection.get("mutations", [])
                    break  # first found wins

            # --- Process version paths ---
            for probe_url, status, _hdrs, _body in version_results:
                if status and 200 <= status < 404:
                    # Extract version from path
                    path = urlparse(probe_url).path
                    version_match = re.search(r"v(\d+)", path)
                    if version_match:
                        version_str = f"v{version_match.group(1)}"
                        status_label = "active" if status == 200 else "redirect" if 300 <= status < 400 else "exists"
                        report.api_versions.append({
                            "version": version_str,
                            "path": path,
                            "status": status_label,
                        })

            # -----------------------------------------------------------
            # Framework fingerprinting
            # -----------------------------------------------------------
            fw, evidence = fingerprint_framework(
                base_headers, base_body, openapi_generator
            )
            if fw:
                report.framework = fw
                report.framework_evidence = evidence

            # -----------------------------------------------------------
            # Collect sensitive paths — paths returning 200 with sensitive keywords
            # -----------------------------------------------------------
            for probe_url, status, _hdrs, _body in openapi_results:
                if status == 200:
                    path = urlparse(probe_url).path.lower()
                    if any(kw in path for kw in SENSITIVE_KEYWORDS):
                        if path not in report.sensitive_paths:
                            report.sensitive_paths.append(path)

            # GraphQL playground / graphiql detection
            if report.graphql_found:
                gql_path = urlparse(report.graphql_url).path.lower()
                if any(kw in gql_path for kw in SENSITIVE_KEYWORDS):
                    if gql_path not in report.sensitive_paths:
                        report.sensitive_paths.append(gql_path)

            # -----------------------------------------------------------
            # Summary
            # -----------------------------------------------------------
            total = 0
            if report.openapi_endpoints_count:
                total += report.openapi_endpoints_count
            if report.graphql_queries:
                total += len(report.graphql_queries)
            if report.graphql_mutations:
                total += len(report.graphql_mutations)
            report.total_endpoints_discovered = total

    except Exception as exc:
        report.error = f"Discovery failed: {exc}"

    return report
