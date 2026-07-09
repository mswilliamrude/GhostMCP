"""Vulnerability intelligence module — CVE lookup, package vuln checks, EPSS + KEV."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import httpx

TIMEOUT = 10.0

# NVD API (rate-limited: 5 req/30s without key, 50 req/30s with key)
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# EPSS — Exploit Prediction Scoring System
EPSS_URL = "https://api.first.org/data/v1/epss"

# CISA Known Exploited Vulnerabilities
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# OSV.dev — open-source vulnerability database
OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# Severity mapping from CVSS v3.x baseScore
_SEVERITY_THRESHOLDS = [
    (9.0, "CRITICAL"),
    (7.0, "HIGH"),
    (4.0, "MEDIUM"),
    (0.1, "LOW"),
]


def _cvss_to_severity(score: float | None) -> str:
    """Map a CVSS score to a severity label."""
    if score is None:
        return "UNKNOWN"
    for threshold, label in _SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "UNKNOWN"


@dataclass
class CVEResult:
    cve_id: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    cvss_score: float | None
    published: str
    references: list[str]
    epss_score: float | None  # Exploit Prediction Scoring
    epss_percentile: float | None
    in_kev: bool  # CISA Known Exploited Vulnerabilities
    affected_products: list[str]
    source: str  # "nvd", "osv", "ghsa"


@dataclass
class PackageVulnResult:
    package: str
    ecosystem: str  # PyPI, npm, Go, crates.io
    vulnerabilities: list[CVEResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# EPSS
# ---------------------------------------------------------------------------

async def get_epss(cve_id: str) -> tuple[float | None, float | None]:
    """Get EPSS score + percentile for a CVE.

    Returns (score, percentile) or (None, None) on failure.
    """
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.get(EPSS_URL, params={"cve": cve_id})
            if resp.status_code == 200:
                data = resp.json()
                entries = data.get("data", [])
                if entries:
                    entry = entries[0]
                    score = float(entry.get("epss", 0))
                    percentile = float(entry.get("percentile", 0))
                    return score, percentile
        except (httpx.TimeoutException, httpx.ConnectError, ValueError, KeyError):
            pass
    return None, None


# ---------------------------------------------------------------------------
# CISA KEV
# ---------------------------------------------------------------------------

# Module-level cache for the KEV catalog
_kev_cache: list[dict] | None = None
_kev_cve_set: set[str] | None = None


async def get_kev_list() -> list[dict]:
    """Fetch CISA Known Exploited Vulnerabilities catalog.

    Returns the list of vulnerability entries. Results are cached
    in-process after first fetch.
    """
    global _kev_cache, _kev_cve_set

    if _kev_cache is not None:
        return _kev_cache

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.get(KEV_URL)
            if resp.status_code == 200:
                data = resp.json()
                _kev_cache = data.get("vulnerabilities", [])
                _kev_cve_set = {
                    v.get("cveID", "") for v in _kev_cache
                }
                return _kev_cache
        except (httpx.TimeoutException, httpx.ConnectError, ValueError):
            pass

    return []


async def _is_in_kev(cve_id: str) -> bool:
    """Check whether a CVE is in the CISA KEV catalog."""
    global _kev_cve_set

    if _kev_cve_set is None:
        await get_kev_list()

    if _kev_cve_set is not None:
        return cve_id.upper() in _kev_cve_set
    return False


# ---------------------------------------------------------------------------
# NVD CVE parsing helpers
# ---------------------------------------------------------------------------

def _parse_nvd_item(item: dict) -> CVEResult:
    """Parse a single NVD CVE item into a CVEResult (without EPSS/KEV)."""
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")

    # Description — prefer English
    descriptions = cve.get("descriptions", [])
    description = ""
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break
    if not description and descriptions:
        description = descriptions[0].get("value", "")

    # CVSS score — try v3.1, then v3.0, then v2
    cvss_score: float | None = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            if cvss_score is not None:
                cvss_score = float(cvss_score)
                break

    severity = _cvss_to_severity(cvss_score)

    # Published date
    published = cve.get("published", "")

    # References
    refs_list = cve.get("references", [])
    references = [r.get("url", "") for r in refs_list if r.get("url")]

    # Affected products (CPE match strings)
    affected: list[str] = []
    configurations = cve.get("configurations", [])
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                if criteria:
                    affected.append(criteria)

    return CVEResult(
        cve_id=cve_id,
        description=description,
        severity=severity,
        cvss_score=cvss_score,
        published=published,
        references=references,
        epss_score=None,
        epss_percentile=None,
        in_kev=False,
        affected_products=affected,
        source="nvd",
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def lookup_cve(cve_id: str) -> CVEResult | None:
    """Query NVD for a specific CVE. Also checks EPSS + KEV.

    Returns None if the CVE is not found.
    """
    cve_id = cve_id.strip().upper()

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.get(NVD_CVE_URL, params={"cveId": cve_id})
            if resp.status_code != 200:
                return None
            data = resp.json()
        except (httpx.TimeoutException, httpx.ConnectError):
            return None

    items = data.get("vulnerabilities", [])
    if not items:
        return None

    result = _parse_nvd_item(items[0])

    # Enrich with EPSS and KEV in parallel
    epss_task = get_epss(cve_id)
    kev_task = _is_in_kev(cve_id)
    (epss_score, epss_percentile), in_kev = await asyncio.gather(epss_task, kev_task)

    result.epss_score = epss_score
    result.epss_percentile = epss_percentile
    result.in_kev = in_kev

    return result


async def search_cves(keyword: str, max_results: int = 10) -> list[CVEResult]:
    """Search NVD by keyword.

    Returns up to max_results CVEs matching the keyword.
    """
    max_results = min(max(1, max_results), 50)

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.get(
                NVD_CVE_URL,
                params={
                    "keywordSearch": keyword,
                    "resultsPerPage": max_results,
                },
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
        except (httpx.TimeoutException, httpx.ConnectError):
            return []

    items = data.get("vulnerabilities", [])
    results: list[CVEResult] = []
    for item in items[:max_results]:
        results.append(_parse_nvd_item(item))

    return results


async def check_package(package: str, ecosystem: str = "PyPI") -> PackageVulnResult:
    """Check a package for known vulns via OSV.dev.

    Queries the OSV API and returns all known vulnerabilities for the
    given package in the specified ecosystem.
    """
    result = PackageVulnResult(package=package, ecosystem=ecosystem)

    payload = {
        "package": {
            "name": package,
            "ecosystem": ecosystem,
        },
    }

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        try:
            resp = await client.post(OSV_QUERY_URL, json=payload)
            if resp.status_code != 200:
                return result
            data = resp.json()
        except (httpx.TimeoutException, httpx.ConnectError):
            return result

    vulns = data.get("vulns", [])
    for vuln in vulns:
        vuln_id = vuln.get("id", "")
        summary = vuln.get("summary", vuln.get("details", ""))

        # Severity from OSV
        severity_list = vuln.get("severity", [])
        cvss_score: float | None = None
        for sev in severity_list:
            score_str = sev.get("score")
            if score_str:
                try:
                    cvss_score = float(score_str)
                except (ValueError, TypeError):
                    pass

        # References
        refs = [r.get("url", "") for r in vuln.get("references", []) if r.get("url")]

        # Affected packages
        affected_products: list[str] = []
        for affected in vuln.get("affected", []):
            pkg = affected.get("package", {})
            name = pkg.get("name", "")
            eco = pkg.get("ecosystem", "")
            if name:
                affected_products.append(f"{eco}/{name}")

        # Published / modified
        published = vuln.get("published", vuln.get("modified", ""))

        # Determine source from ID prefix
        source = "osv"
        if vuln_id.startswith("GHSA-"):
            source = "ghsa"
        elif vuln_id.startswith("CVE-"):
            source = "nvd"

        cve_result = CVEResult(
            cve_id=vuln_id,
            description=summary,
            severity=_cvss_to_severity(cvss_score),
            cvss_score=cvss_score,
            published=published,
            references=refs,
            epss_score=None,
            epss_percentile=None,
            in_kev=False,
            affected_products=affected_products,
            source=source,
        )
        result.vulnerabilities.append(cve_result)

    return result
