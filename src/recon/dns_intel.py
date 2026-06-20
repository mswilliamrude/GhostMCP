"""DNS intelligence module — comprehensive DNS recon via DNS-over-HTTPS (DoH).

Performs full DNS record enumeration, email security analysis (SPF/DMARC/DKIM),
dangling CNAME detection, and SaaS service discovery. Uses Cloudflare DoH as
primary with Google DoH fallback. Zero new dependencies — httpx only.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field

import httpx

# ---------------------------------------------------------------------------
# DoH endpoints and constants
# ---------------------------------------------------------------------------

DOH_CLOUDFLARE = "https://cloudflare-dns.com/dns-query"
DOH_GOOGLE = "https://dns.google/resolve"
TIMEOUT = 10.0

# DNS record type codes (RFC 1035 + extensions)
DNS_TYPES = {
    "A": 1,
    "AAAA": 28,
    "MX": 15,
    "NS": 2,
    "CNAME": 5,
    "TXT": 16,
    "SRV": 33,
    "CAA": 257,
    "SOA": 6,
}

# Patterns for dangling CNAME detection — services known to be claimable
VULNERABLE_CNAME_PATTERNS = [
    r"\.herokuapp\.com$",
    r"\.azurewebsites\.net$",
    r"\.github\.io$",
    r"\.s3\.amazonaws\.com$",
    r"\.cloudfront\.net$",
    r"\.fastly\.net$",
    r"\.ghost\.io$",
    r"\.surge\.sh$",
    r"\.bitbucket\.io$",
    r"\.pantheon\.io$",
    r"\.shopify\.com$",
    r"\.fly\.dev$",
    r"\.netlify\.app$",
]

# Common DKIM selectors to probe
DKIM_SELECTORS = [
    "google", "selector1", "selector2", "default",
    "k1", "s1", "s2", "mail", "dkim",
]

# SaaS verification token patterns in TXT records
SAAS_TXT_PATTERNS = {
    "google-site-verification": "Google Workspace / Search Console",
    "facebook-domain-verification": "Facebook / Meta",
    "MS=": "Microsoft 365",
    "atlassian-domain-verification": "Atlassian (Jira/Confluence)",
    "stripe-verification": "Stripe",
    "hubspot": "HubSpot",
    "_github-challenge": "GitHub Pages",
    "docusign": "DocuSign",
    "adobe-idp-site-verification": "Adobe",
}

# SRV service prefixes to check
SRV_SERVICE_PREFIXES = [
    "_sip._tcp",
    "_sip._udp",
    "_sipfederationtls._tcp",
    "_ldap._tcp",
    "_kerberos._tcp",
    "_kerberos._udp",
    "_autodiscover._tcp",
    "_xmpp-server._tcp",
    "_xmpp-client._tcp",
]

# Domain validation regex
DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass
class DNSReport:
    """Result of a comprehensive DNS reconnaissance lookup."""

    domain: str

    # Core records
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    mx_records: list[dict] = field(default_factory=list)      # [{priority, host}]
    ns_records: list[str] = field(default_factory=list)
    cname_records: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    srv_records: list[dict] = field(default_factory=list)      # [{service, protocol, priority, weight, port, target}]
    caa_records: list[str] = field(default_factory=list)
    soa_record: str = ""

    # Email security
    spf: dict = field(default_factory=dict)     # {record, valid, issues[], mechanism_count, includes[]}
    dmarc: dict = field(default_factory=dict)   # {record, policy, pct, rua, ruf, issues[]}
    dkim: dict = field(default_factory=dict)    # {found, selector, record, issues[]}

    # Analysis
    dangling_cnames: list[dict] = field(default_factory=list)   # [{cname, target, status, risk}]
    service_discovery: list[dict] = field(default_factory=list) # [{service, from_record_type, value}]
    email_security_grade: str = ""  # A through F

    error: str | None = None


# ---------------------------------------------------------------------------
# Domain validation
# ---------------------------------------------------------------------------

def _validate_domain(domain: str) -> str | None:
    """Validate and clean a domain input.

    Returns the cleaned domain string, or None if invalid.
    Strips whitespace, removes protocol prefixes, removes trailing slashes/paths.
    """
    if not domain:
        return None

    domain = domain.strip()

    # Remove protocol prefix
    for prefix in ("https://", "http://", "ftp://"):
        if domain.lower().startswith(prefix):
            domain = domain[len(prefix):]

    # Remove path, query string, fragment
    domain = domain.split("/")[0]
    domain = domain.split("?")[0]
    domain = domain.split("#")[0]

    # Remove port
    if ":" in domain:
        domain = domain.split(":")[0]

    domain = domain.strip().lower()

    if not domain:
        return None

    if not DOMAIN_RE.match(domain):
        return None

    return domain


# ---------------------------------------------------------------------------
# DoH query engine
# ---------------------------------------------------------------------------

async def _doh_query(
    domain: str, record_type: str, client: httpx.AsyncClient
) -> list[dict] | None:
    """Query DNS-over-HTTPS using Cloudflare JSON API, fallback to Google.

    Returns a list of Answer dicts on success, empty list on NOERROR with no
    answers, or None if both providers fail entirely.
    """
    params = {"name": domain, "type": record_type}
    headers = {"Accept": "application/dns-json"}

    # Try Cloudflare first
    try:
        resp = await client.get(DOH_CLOUDFLARE, params=params, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("Status") == 0:  # NOERROR
                return data.get("Answer", [])
            return []
    except Exception:
        pass

    # Fallback to Google
    try:
        resp = await client.get(DOH_GOOGLE, params=params)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("Status") == 0:
                return data.get("Answer", [])
            return []
    except Exception:
        pass

    return None


# ---------------------------------------------------------------------------
# Record parsers
# ---------------------------------------------------------------------------

def _parse_mx(answers: list[dict]) -> list[dict]:
    """Parse MX answers into [{priority, host}]."""
    results = []
    for ans in answers:
        data = ans.get("data", "")
        parts = data.split(None, 1)
        if len(parts) == 2:
            try:
                priority = int(parts[0])
            except ValueError:
                priority = 0
            host = parts[1].rstrip(".")
            results.append({"priority": priority, "host": host})
        elif data:
            results.append({"priority": 0, "host": data.rstrip(".")})
    results.sort(key=lambda x: x["priority"])
    return results


def _parse_srv(answers: list[dict]) -> list[dict]:
    """Parse SRV answers into [{service, protocol, priority, weight, port, target}]."""
    results = []
    for ans in answers:
        name = ans.get("name", "")
        data = ans.get("data", "")

        # Parse service and protocol from the query name
        # Format: _service._protocol.domain
        name_parts = name.split(".")
        service = name_parts[0] if len(name_parts) > 0 else ""
        protocol = name_parts[1] if len(name_parts) > 1 else ""

        # Parse data: priority weight port target
        data_parts = data.split()
        if len(data_parts) >= 4:
            try:
                results.append({
                    "service": service,
                    "protocol": protocol,
                    "priority": int(data_parts[0]),
                    "weight": int(data_parts[1]),
                    "port": int(data_parts[2]),
                    "target": data_parts[3].rstrip("."),
                })
            except (ValueError, IndexError):
                pass
    return results


def _strip_txt_quotes(data: str) -> str:
    """Strip surrounding quotes from TXT record data."""
    data = data.strip()
    if data.startswith('"') and data.endswith('"'):
        data = data[1:-1]
    return data


# ---------------------------------------------------------------------------
# Email security analysis
# ---------------------------------------------------------------------------

def _analyze_spf(txt_records: list[str]) -> dict:
    """Analyze SPF record from TXT records.

    Returns dict with: record, valid, issues, mechanism_count, includes.
    """
    spf_record = ""
    for txt in txt_records:
        if txt.lower().startswith("v=spf1"):
            spf_record = txt
            break

    if not spf_record:
        return {}

    issues: list[str] = []
    includes: list[str] = []

    # Count DNS-querying mechanisms (each include, a, mx, ptr, exists counts as a lookup)
    dns_mechanisms = re.findall(
        r"\b(?:include|a|mx|ptr|exists|redirect)[:=]\S+", spf_record, re.IGNORECASE
    )
    mechanism_count = len(dns_mechanisms)

    # Extract includes
    for m in re.finditer(r"include:(\S+)", spf_record, re.IGNORECASE):
        includes.append(m.group(1))

    # Check for critical issues
    if "+all" in spf_record.lower():
        issues.append("CRITICAL: +all allows any sender — SPF is effectively disabled")
    elif "~all" in spf_record.lower():
        issues.append("Soft-fail (~all) — emails from unauthorized senders are accepted but marked")
    elif "-all" not in spf_record.lower() and "?all" not in spf_record.lower():
        if "all" not in spf_record.lower():
            issues.append("No 'all' mechanism — missing default policy")

    if mechanism_count > 10:
        issues.append(f"Too many DNS lookups ({mechanism_count}) — RFC 7208 allows max 10")

    valid = not any("CRITICAL" in i for i in issues)

    return {
        "record": spf_record,
        "valid": valid,
        "issues": issues,
        "mechanism_count": mechanism_count,
        "includes": includes,
    }


def _analyze_dmarc(dmarc_txt: list[str]) -> dict:
    """Analyze DMARC record.

    Returns dict with: record, policy, pct, rua, ruf, issues.
    """
    dmarc_record = ""
    for txt in dmarc_txt:
        if txt.lower().startswith("v=dmarc1"):
            dmarc_record = txt
            break

    if not dmarc_record:
        return {}

    issues: list[str] = []

    # Extract policy
    policy_match = re.search(r"\bp=(\w+)", dmarc_record, re.IGNORECASE)
    policy = policy_match.group(1).lower() if policy_match else "none"

    # Extract pct
    pct_match = re.search(r"\bpct=(\d+)", dmarc_record, re.IGNORECASE)
    pct = int(pct_match.group(1)) if pct_match else 100

    # Extract rua (aggregate report URI)
    rua_match = re.search(r"\brua=([^;\s]+)", dmarc_record, re.IGNORECASE)
    rua = rua_match.group(1) if rua_match else ""

    # Extract ruf (forensic report URI)
    ruf_match = re.search(r"\bruf=([^;\s]+)", dmarc_record, re.IGNORECASE)
    ruf = ruf_match.group(1) if ruf_match else ""

    # Flag issues
    if policy == "none":
        issues.append("Policy is 'none' — monitoring only, no enforcement")
    if not rua:
        issues.append("No rua (aggregate report) URI — no visibility into failures")
    if pct < 100:
        issues.append(f"pct={pct} — only {pct}% of messages subject to DMARC policy")

    return {
        "record": dmarc_record,
        "policy": policy,
        "pct": pct,
        "rua": rua,
        "ruf": ruf,
        "issues": issues,
    }


async def _check_dkim(
    domain: str, client: httpx.AsyncClient
) -> dict:
    """Probe common DKIM selectors for the domain.

    Returns dict with: found, selector, record, issues.
    """
    for selector in DKIM_SELECTORS:
        dkim_domain = f"{selector}._domainkey.{domain}"
        answers = await _doh_query(dkim_domain, "TXT", client)
        if answers:
            for ans in answers:
                data = _strip_txt_quotes(ans.get("data", ""))
                if "v=dkim1" in data.lower() or "k=rsa" in data.lower() or "p=" in data:
                    return {
                        "found": True,
                        "selector": selector,
                        "record": data,
                        "issues": [],
                    }

    return {
        "found": False,
        "selector": "",
        "record": "",
        "issues": ["No DKIM record found for common selectors"],
    }


def _grade_email_security(
    spf: dict, dmarc: dict, dkim: dict
) -> str:
    """Grade email security from A (best) to F (worst).

    A: DMARC p=reject + valid SPF with -all + DKIM found
    B: DMARC p=quarantine + valid SPF
    C: DMARC p=none + valid SPF
    D: SPF present but no DMARC
    F: No SPF and no DMARC
    """
    has_spf = bool(spf.get("record"))
    spf_valid = spf.get("valid", False)
    spf_hard_fail = "-all" in spf.get("record", "").lower() if has_spf else False
    has_dmarc = bool(dmarc.get("record"))
    dmarc_policy = dmarc.get("policy", "none")
    has_dkim = dkim.get("found", False)

    if has_dmarc and dmarc_policy == "reject" and has_spf and spf_valid and spf_hard_fail and has_dkim:
        return "A"
    if has_dmarc and dmarc_policy == "quarantine" and has_spf and spf_valid:
        return "B"
    if has_dmarc and dmarc_policy == "none" and has_spf and spf_valid:
        return "C"
    if has_spf and not has_dmarc:
        return "D"
    return "F"


# ---------------------------------------------------------------------------
# Dangling CNAME detection
# ---------------------------------------------------------------------------

async def _check_dangling_cnames(
    cname_records: list[str], client: httpx.AsyncClient
) -> list[dict]:
    """Check CNAME targets for potential subdomain takeover vulnerabilities."""
    results = []

    for target in cname_records:
        target_clean = target.rstrip(".")
        status = "resolved"
        risk = "none"

        # Try to resolve the CNAME target
        a_answers = await _doh_query(target_clean, "A", client)

        if a_answers is None or a_answers == []:
            # Check if it's an NXDOMAIN (no answers at all)
            status = "nxdomain"
            risk = "high"
        else:
            status = "resolved"

        # Check against known vulnerable patterns regardless of resolution
        for pattern in VULNERABLE_CNAME_PATTERNS:
            if re.search(pattern, target_clean, re.IGNORECASE):
                if status == "nxdomain":
                    risk = "critical"
                else:
                    risk = "medium"
                break

        if risk != "none":
            results.append({
                "cname": target_clean,
                "target": target_clean,
                "status": status,
                "risk": risk,
            })

    return results


# ---------------------------------------------------------------------------
# Service discovery
# ---------------------------------------------------------------------------

def _discover_services_from_txt(txt_records: list[str]) -> list[dict]:
    """Discover SaaS services from TXT verification tokens."""
    services = []

    for txt in txt_records:
        txt_lower = txt.lower()
        for pattern, service_name in SAAS_TXT_PATTERNS.items():
            if pattern.lower() in txt_lower:
                services.append({
                    "service": service_name,
                    "from_record_type": "TXT",
                    "value": txt,
                })
                break  # One match per TXT record

    return services


def _discover_services_from_srv(srv_records: list[dict]) -> list[dict]:
    """Discover internal services from SRV records."""
    service_map = {
        "_sip": "SIP (VoIP)",
        "_sipfederationtls": "SIP Federation TLS (Microsoft Teams/Skype)",
        "_ldap": "LDAP (Active Directory)",
        "_kerberos": "Kerberos (Active Directory)",
        "_autodiscover": "Autodiscover (Exchange/Outlook)",
        "_xmpp-server": "XMPP Server (Jabber/Chat)",
        "_xmpp-client": "XMPP Client (Jabber/Chat)",
    }

    services = []
    for srv in srv_records:
        svc_name = srv.get("service", "")
        for prefix, description in service_map.items():
            if svc_name.startswith(prefix):
                services.append({
                    "service": description,
                    "from_record_type": "SRV",
                    "value": f"{srv.get('target', '')}:{srv.get('port', '')}",
                })
                break

    return services


# ---------------------------------------------------------------------------
# Main lookup function
# ---------------------------------------------------------------------------

async def dns_lookup(domain: str) -> DNSReport:
    """Perform comprehensive DNS reconnaissance on a domain.

    Uses DNS-over-HTTPS (Cloudflare primary, Google fallback) to query all
    major record types. Analyzes email security posture (SPF/DMARC/DKIM),
    detects dangling CNAMEs for subdomain takeover, and discovers SaaS
    services via TXT and SRV records.

    Args:
        domain: Domain name to investigate. Protocol prefixes are stripped.

    Returns:
        DNSReport with all records, analysis, and security grading.
    """
    cleaned = _validate_domain(domain)
    if cleaned is None:
        return DNSReport(
            domain=domain.strip() if domain else "",
            error=f"Invalid domain: {domain}",
        )

    domain = cleaned
    report = DNSReport(domain=domain)

    # Use a single shared client for all queries (connection reuse)
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:

        # -----------------------------------------------------------------
        # Phase 1: Parallel core record queries
        # -----------------------------------------------------------------
        query_tasks = {
            rtype: _doh_query(domain, rtype, client)
            for rtype in DNS_TYPES
        }

        results = await asyncio.gather(*query_tasks.values(), return_exceptions=True)
        answers = {}
        all_failed = True
        for rtype, result in zip(query_tasks.keys(), results):
            if isinstance(result, Exception):
                answers[rtype] = None
            else:
                answers[rtype] = result
                if result is not None:
                    all_failed = False

        if all_failed:
            report.error = "All DoH queries failed — both Cloudflare and Google unreachable"
            return report

        # -----------------------------------------------------------------
        # Phase 2: Parse core records
        # -----------------------------------------------------------------

        # A records
        if answers.get("A"):
            report.a_records = [
                ans["data"] for ans in answers["A"]
                if ans.get("type") == DNS_TYPES["A"] and ans.get("data")
            ]

        # AAAA records
        if answers.get("AAAA"):
            report.aaaa_records = [
                ans["data"] for ans in answers["AAAA"]
                if ans.get("type") == DNS_TYPES["AAAA"] and ans.get("data")
            ]

        # MX records
        if answers.get("MX"):
            report.mx_records = _parse_mx(answers["MX"])

        # NS records
        if answers.get("NS"):
            report.ns_records = [
                ans["data"].rstrip(".") for ans in answers["NS"]
                if ans.get("type") == DNS_TYPES["NS"] and ans.get("data")
            ]

        # CNAME records
        if answers.get("CNAME"):
            report.cname_records = [
                ans["data"].rstrip(".") for ans in answers["CNAME"]
                if ans.get("type") == DNS_TYPES["CNAME"] and ans.get("data")
            ]

        # TXT records
        if answers.get("TXT"):
            report.txt_records = [
                _strip_txt_quotes(ans["data"]) for ans in answers["TXT"]
                if ans.get("type") == DNS_TYPES["TXT"] and ans.get("data")
            ]

        # SRV records — query specific service prefixes
        srv_tasks = [
            _doh_query(f"{prefix}.{domain}", "SRV", client)
            for prefix in SRV_SERVICE_PREFIXES
        ]
        srv_results = await asyncio.gather(*srv_tasks, return_exceptions=True)
        all_srv_answers: list[dict] = []
        for result in srv_results:
            if isinstance(result, list):
                all_srv_answers.extend(result)
        if all_srv_answers:
            report.srv_records = _parse_srv(all_srv_answers)

        # CAA records
        if answers.get("CAA"):
            report.caa_records = [
                ans["data"] for ans in answers["CAA"]
                if ans.get("type") == DNS_TYPES["CAA"] and ans.get("data")
            ]

        # SOA record
        if answers.get("SOA"):
            soa_answers = [
                ans for ans in answers["SOA"]
                if ans.get("type") == DNS_TYPES["SOA"] and ans.get("data")
            ]
            if soa_answers:
                report.soa_record = soa_answers[0]["data"]

        # -----------------------------------------------------------------
        # Phase 3: Email security analysis
        # -----------------------------------------------------------------

        # SPF
        report.spf = _analyze_spf(report.txt_records)

        # DMARC — query _dmarc.{domain}
        dmarc_answers = await _doh_query(f"_dmarc.{domain}", "TXT", client)
        dmarc_txts = []
        if dmarc_answers:
            dmarc_txts = [
                _strip_txt_quotes(ans.get("data", ""))
                for ans in dmarc_answers
                if ans.get("data")
            ]
        report.dmarc = _analyze_dmarc(dmarc_txts)

        # DKIM
        report.dkim = await _check_dkim(domain, client)

        # Email security grade
        report.email_security_grade = _grade_email_security(
            report.spf, report.dmarc, report.dkim
        )

        # -----------------------------------------------------------------
        # Phase 4: Dangling CNAME detection
        # -----------------------------------------------------------------
        if report.cname_records:
            report.dangling_cnames = await _check_dangling_cnames(
                report.cname_records, client
            )

        # -----------------------------------------------------------------
        # Phase 5: Service discovery
        # -----------------------------------------------------------------
        report.service_discovery = _discover_services_from_txt(report.txt_records)
        report.service_discovery.extend(
            _discover_services_from_srv(report.srv_records)
        )

    return report
