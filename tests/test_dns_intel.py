"""Tests for DNS intelligence module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.recon.dns_intel import (
    DNSReport,
    dns_lookup,
    _validate_domain,
    _analyze_spf,
    _analyze_dmarc,
    _grade_email_security,
    _discover_services_from_txt,
    _check_dangling_cnames,
    _parse_mx,
    _parse_srv,
    _strip_txt_quotes,
)


# ---------------------------------------------------------------------------
# Sample DoH responses
# ---------------------------------------------------------------------------

SAMPLE_DOH_RESPONSE_A = {
    "Status": 0,
    "Answer": [
        {"name": "example.com.", "type": 1, "TTL": 300, "data": "93.184.216.34"}
    ],
}

SAMPLE_DOH_RESPONSE_AAAA = {
    "Status": 0,
    "Answer": [
        {"name": "example.com.", "type": 28, "TTL": 300, "data": "2606:2800:220:1:248:1893:25c8:1946"}
    ],
}

SAMPLE_DOH_RESPONSE_MX = {
    "Status": 0,
    "Answer": [
        {"name": "example.com.", "type": 15, "TTL": 300, "data": "10 mail.example.com."},
        {"name": "example.com.", "type": 15, "TTL": 300, "data": "20 mail2.example.com."},
    ],
}

SAMPLE_DOH_RESPONSE_NS = {
    "Status": 0,
    "Answer": [
        {"name": "example.com.", "type": 2, "TTL": 300, "data": "ns1.example.com."},
        {"name": "example.com.", "type": 2, "TTL": 300, "data": "ns2.example.com."},
    ],
}

SAMPLE_DOH_RESPONSE_CNAME = {
    "Status": 0,
    "Answer": [
        {"name": "www.example.com.", "type": 5, "TTL": 300, "data": "example.com."},
    ],
}

SAMPLE_DOH_RESPONSE_TXT = {
    "Status": 0,
    "Answer": [
        {"name": "example.com.", "type": 16, "TTL": 300, "data": '"v=spf1 include:_spf.google.com -all"'},
        {"name": "example.com.", "type": 16, "TTL": 300, "data": '"google-site-verification=abc123"'},
    ],
}

SAMPLE_DOH_RESPONSE_SOA = {
    "Status": 0,
    "Answer": [
        {"name": "example.com.", "type": 6, "TTL": 300, "data": "ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400"},
    ],
}

SAMPLE_DOH_RESPONSE_CAA = {
    "Status": 0,
    "Answer": [
        {"name": "example.com.", "type": 257, "TTL": 300, "data": '0 issue "letsencrypt.org"'},
    ],
}

SAMPLE_DOH_RESPONSE_SRV = {
    "Status": 0,
    "Answer": [
        {"name": "_sip._tcp.example.com.", "type": 33, "TTL": 300, "data": "10 5 5060 sip.example.com."},
    ],
}

SAMPLE_DOH_RESPONSE_DMARC = {
    "Status": 0,
    "Answer": [
        {"name": "_dmarc.example.com.", "type": 16, "TTL": 300, "data": '"v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100"'},
    ],
}

SAMPLE_DOH_RESPONSE_DKIM = {
    "Status": 0,
    "Answer": [
        {"name": "google._domainkey.example.com.", "type": 16, "TTL": 300, "data": '"v=DKIM1; k=rsa; p=MIGfMA0GCS..."'},
    ],
}

SAMPLE_DOH_RESPONSE_EMPTY = {"Status": 0, "Answer": []}
SAMPLE_DOH_RESPONSE_NXDOMAIN = {"Status": 3}


# ---------------------------------------------------------------------------
# Domain validation tests
# ---------------------------------------------------------------------------

class TestDomainValidation:

    def test_valid_domain(self):
        assert _validate_domain("example.com") == "example.com"

    def test_valid_domain_subdomain(self):
        assert _validate_domain("sub.example.com") == "sub.example.com"

    def test_strip_whitespace(self):
        assert _validate_domain("  example.com  ") == "example.com"

    def test_remove_https_prefix(self):
        assert _validate_domain("https://example.com") == "example.com"

    def test_remove_http_prefix(self):
        assert _validate_domain("http://example.com") == "example.com"

    def test_remove_https_with_path(self):
        assert _validate_domain("https://example.com/path/to/page") == "example.com"

    def test_remove_port(self):
        assert _validate_domain("example.com:8080") == "example.com"

    def test_remove_query_string(self):
        assert _validate_domain("example.com?foo=bar") == "example.com"

    def test_reject_empty(self):
        assert _validate_domain("") is None

    def test_reject_none_like(self):
        assert _validate_domain("   ") is None

    def test_reject_invalid_chars(self):
        assert _validate_domain("exam ple.com") is None

    def test_reject_ip_address(self):
        assert _validate_domain("8.8.8.8") is None

    def test_reject_single_label(self):
        assert _validate_domain("localhost") is None

    def test_lowercase(self):
        assert _validate_domain("EXAMPLE.COM") == "example.com"


# ---------------------------------------------------------------------------
# SPF parsing tests
# ---------------------------------------------------------------------------

class TestSPFParsing:

    def test_valid_spf_hard_fail(self):
        txt_records = ["v=spf1 include:_spf.google.com -all"]
        result = _analyze_spf(txt_records)
        assert result["valid"] is True
        assert result["record"] == "v=spf1 include:_spf.google.com -all"
        assert "includes" in result
        assert "_spf.google.com" in result["includes"]
        assert result["mechanism_count"] >= 1

    def test_spf_soft_fail(self):
        txt_records = ["v=spf1 include:_spf.google.com ~all"]
        result = _analyze_spf(txt_records)
        assert result["valid"] is True
        assert any("Soft-fail" in i for i in result["issues"])

    def test_spf_plus_all_critical(self):
        txt_records = ["v=spf1 +all"]
        result = _analyze_spf(txt_records)
        assert result["valid"] is False
        assert any("CRITICAL" in i for i in result["issues"])

    def test_spf_too_many_mechanisms(self):
        mechanisms = " ".join(f"include:spf{i}.example.com" for i in range(12))
        txt_records = [f"v=spf1 {mechanisms} -all"]
        result = _analyze_spf(txt_records)
        assert result["mechanism_count"] > 10
        assert any("Too many" in i for i in result["issues"])

    def test_no_spf_returns_empty(self):
        txt_records = ["some-other-record"]
        result = _analyze_spf(txt_records)
        assert result == {}

    def test_empty_txt_records(self):
        result = _analyze_spf([])
        assert result == {}

    def test_spf_no_all_mechanism(self):
        txt_records = ["v=spf1 include:_spf.google.com"]
        result = _analyze_spf(txt_records)
        assert any("No 'all' mechanism" in i for i in result["issues"])


# ---------------------------------------------------------------------------
# DMARC parsing tests
# ---------------------------------------------------------------------------

class TestDMARCParsing:

    def test_dmarc_reject_full(self):
        txt = ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com; pct=100"]
        result = _analyze_dmarc(txt)
        assert result["policy"] == "reject"
        assert result["pct"] == 100
        assert result["rua"] == "mailto:dmarc@example.com"
        assert result["ruf"] == "mailto:forensic@example.com"
        assert len(result["issues"]) == 0

    def test_dmarc_none_monitoring(self):
        txt = ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"]
        result = _analyze_dmarc(txt)
        assert result["policy"] == "none"
        assert any("monitoring only" in i for i in result["issues"])

    def test_dmarc_missing_rua(self):
        txt = ["v=DMARC1; p=reject"]
        result = _analyze_dmarc(txt)
        assert result["policy"] == "reject"
        assert any("No rua" in i for i in result["issues"])

    def test_dmarc_low_pct(self):
        txt = ["v=DMARC1; p=quarantine; pct=50; rua=mailto:dmarc@example.com"]
        result = _analyze_dmarc(txt)
        assert result["pct"] == 50
        assert any("pct=50" in i for i in result["issues"])

    def test_no_dmarc_returns_empty(self):
        result = _analyze_dmarc([])
        assert result == {}

    def test_non_dmarc_txt_ignored(self):
        result = _analyze_dmarc(["some random txt record"])
        assert result == {}

    def test_dmarc_quarantine(self):
        txt = ["v=DMARC1; p=quarantine; rua=mailto:d@example.com; pct=100"]
        result = _analyze_dmarc(txt)
        assert result["policy"] == "quarantine"


# ---------------------------------------------------------------------------
# Dangling CNAME detection tests
# ---------------------------------------------------------------------------

class TestDanglingCNAME:

    @pytest.mark.asyncio
    async def test_resolved_non_vulnerable_target(self):
        """CNAME resolves normally, not a vulnerable pattern — no risk."""
        mock_client = AsyncMock()

        async def fake_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {
                "Status": 0,
                "Answer": [{"name": "target.example.com.", "type": 1, "TTL": 300, "data": "1.2.3.4"}],
            }
            return resp

        mock_client.get = fake_get
        results = await _check_dangling_cnames(["target.example.com"], mock_client)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_nxdomain_non_vulnerable(self):
        """CNAME target doesn't resolve (NXDOMAIN), generic domain — high risk."""
        mock_client = AsyncMock()

        async def fake_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"Status": 0, "Answer": []}
            return resp

        mock_client.get = fake_get
        results = await _check_dangling_cnames(["dead.otherdomain.com"], mock_client)
        assert len(results) == 1
        assert results[0]["risk"] == "high"
        assert results[0]["status"] == "nxdomain"

    @pytest.mark.asyncio
    async def test_nxdomain_vulnerable_pattern(self):
        """CNAME target doesn't resolve AND matches a vulnerable pattern — critical."""
        mock_client = AsyncMock()

        async def fake_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"Status": 0, "Answer": []}
            return resp

        mock_client.get = fake_get
        results = await _check_dangling_cnames(["myapp.herokuapp.com"], mock_client)
        assert len(results) == 1
        assert results[0]["risk"] == "critical"

    @pytest.mark.asyncio
    async def test_resolved_vulnerable_pattern(self):
        """CNAME resolves but matches a vulnerable pattern — medium risk."""
        mock_client = AsyncMock()

        async def fake_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {
                "Status": 0,
                "Answer": [{"name": "mysite.netlify.app.", "type": 1, "TTL": 300, "data": "1.2.3.4"}],
            }
            return resp

        mock_client.get = fake_get
        results = await _check_dangling_cnames(["mysite.netlify.app"], mock_client)
        assert len(results) == 1
        assert results[0]["risk"] == "medium"

    @pytest.mark.asyncio
    async def test_multiple_patterns(self):
        """Check various vulnerable patterns are recognized."""
        mock_client = AsyncMock()

        async def fake_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {"Status": 0, "Answer": []}
            return resp

        mock_client.get = fake_get

        targets = [
            "app.azurewebsites.net",
            "page.github.io",
            "bucket.s3.amazonaws.com",
            "cdn.cloudfront.net",
            "site.fly.dev",
        ]
        results = await _check_dangling_cnames(targets, mock_client)
        assert len(results) == 5
        for r in results:
            assert r["risk"] == "critical"


# ---------------------------------------------------------------------------
# Service discovery tests
# ---------------------------------------------------------------------------

class TestServiceDiscovery:

    def test_google_verification(self):
        txt = ["google-site-verification=abcdef123456"]
        services = _discover_services_from_txt(txt)
        assert len(services) == 1
        assert services[0]["service"] == "Google Workspace / Search Console"
        assert services[0]["from_record_type"] == "TXT"

    def test_microsoft_verification(self):
        txt = ["MS=ms12345678"]
        services = _discover_services_from_txt(txt)
        assert len(services) == 1
        assert services[0]["service"] == "Microsoft 365"

    def test_facebook_verification(self):
        txt = ["facebook-domain-verification=abc123"]
        services = _discover_services_from_txt(txt)
        assert len(services) == 1
        assert services[0]["service"] == "Facebook / Meta"

    def test_multiple_services(self):
        txt = [
            "google-site-verification=abc",
            "facebook-domain-verification=def",
            "stripe-verification=ghi",
        ]
        services = _discover_services_from_txt(txt)
        assert len(services) == 3
        names = [s["service"] for s in services]
        assert "Google Workspace / Search Console" in names
        assert "Facebook / Meta" in names
        assert "Stripe" in names

    def test_no_matches(self):
        txt = ["v=spf1 -all", "some random record"]
        services = _discover_services_from_txt(txt)
        assert len(services) == 0

    def test_atlassian_verification(self):
        txt = ["atlassian-domain-verification=xyz789"]
        services = _discover_services_from_txt(txt)
        assert len(services) == 1
        assert services[0]["service"] == "Atlassian (Jira/Confluence)"

    def test_github_challenge(self):
        txt = ["_github-challenge-myorg=abc"]
        services = _discover_services_from_txt(txt)
        assert len(services) == 1
        assert services[0]["service"] == "GitHub Pages"

    def test_docusign(self):
        txt = ["docusign=abc123"]
        services = _discover_services_from_txt(txt)
        assert len(services) == 1
        assert services[0]["service"] == "DocuSign"


# ---------------------------------------------------------------------------
# Email security grading tests
# ---------------------------------------------------------------------------

class TestEmailGrading:

    def test_grade_a_full_security(self):
        spf = {"record": "v=spf1 include:_spf.google.com -all", "valid": True}
        dmarc = {"record": "v=DMARC1; p=reject", "policy": "reject"}
        dkim = {"found": True, "selector": "google", "record": "v=DKIM1; ..."}
        assert _grade_email_security(spf, dmarc, dkim) == "A"

    def test_grade_b_quarantine(self):
        spf = {"record": "v=spf1 -all", "valid": True}
        dmarc = {"record": "v=DMARC1; p=quarantine", "policy": "quarantine"}
        dkim = {"found": False}
        assert _grade_email_security(spf, dmarc, dkim) == "B"

    def test_grade_c_dmarc_none(self):
        spf = {"record": "v=spf1 -all", "valid": True}
        dmarc = {"record": "v=DMARC1; p=none", "policy": "none"}
        dkim = {"found": False}
        assert _grade_email_security(spf, dmarc, dkim) == "C"

    def test_grade_d_spf_only(self):
        spf = {"record": "v=spf1 -all", "valid": True}
        dmarc = {}
        dkim = {"found": False}
        assert _grade_email_security(spf, dmarc, dkim) == "D"

    def test_grade_f_nothing(self):
        spf = {}
        dmarc = {}
        dkim = {"found": False}
        assert _grade_email_security(spf, dmarc, dkim) == "F"

    def test_grade_a_requires_hard_fail(self):
        """A grade requires -all, not ~all."""
        spf = {"record": "v=spf1 include:_spf.google.com ~all", "valid": True}
        dmarc = {"record": "v=DMARC1; p=reject", "policy": "reject"}
        dkim = {"found": True, "selector": "google", "record": "v=DKIM1; ..."}
        # ~all instead of -all should not get A grade
        assert _grade_email_security(spf, dmarc, dkim) != "A"

    def test_grade_a_requires_dkim(self):
        """A grade requires DKIM."""
        spf = {"record": "v=spf1 -all", "valid": True}
        dmarc = {"record": "v=DMARC1; p=reject", "policy": "reject"}
        dkim = {"found": False}
        assert _grade_email_security(spf, dmarc, dkim) != "A"

    def test_grade_d_spf_invalid_no_dmarc(self):
        """SPF present but invalid + no DMARC = D (SPF present, just no DMARC)."""
        spf = {"record": "v=spf1 +all", "valid": False}
        dmarc = {}
        dkim = {}
        assert _grade_email_security(spf, dmarc, dkim) == "D"

    def test_grade_f_no_spf_no_dmarc(self):
        """Completely unprotected domain."""
        assert _grade_email_security({}, {}, {}) == "F"


# ---------------------------------------------------------------------------
# DNS lookup tests (with mocked DoH)
# ---------------------------------------------------------------------------

def _make_doh_side_effect(responses: dict):
    """Create a side effect function for httpx.AsyncClient.get that returns
    different responses based on the URL parameters (record type and domain)."""

    async def side_effect(url, **kwargs):
        params = kwargs.get("params", {})
        record_type = params.get("type", "")
        name = params.get("name", "")
        resp = MagicMock()
        resp.status_code = 200

        # Check for specific domain+type combos
        key = f"{name}:{record_type}"
        if key in responses:
            resp.json.return_value = responses[key]
            return resp

        # Check for just record type
        if record_type in responses:
            resp.json.return_value = responses[record_type]
            return resp

        # Default empty
        resp.json.return_value = {"Status": 0, "Answer": []}
        return resp

    return side_effect


class TestDNSLookup:

    @pytest.mark.asyncio
    async def test_successful_lookup(self):
        """Full mock with all record types returning data."""
        responses = {
            "A": SAMPLE_DOH_RESPONSE_A,
            "AAAA": SAMPLE_DOH_RESPONSE_AAAA,
            "MX": SAMPLE_DOH_RESPONSE_MX,
            "NS": SAMPLE_DOH_RESPONSE_NS,
            "CNAME": SAMPLE_DOH_RESPONSE_CNAME,
            "TXT": SAMPLE_DOH_RESPONSE_TXT,
            "SRV": SAMPLE_DOH_RESPONSE_SRV,
            "CAA": SAMPLE_DOH_RESPONSE_CAA,
            "SOA": SAMPLE_DOH_RESPONSE_SOA,
            # DMARC query
            "_dmarc.example.com:TXT": SAMPLE_DOH_RESPONSE_DMARC,
            # DKIM query
            "google._domainkey.example.com:TXT": SAMPLE_DOH_RESPONSE_DKIM,
        }

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock,
                    side_effect=_make_doh_side_effect(responses)):
            report = await dns_lookup("example.com")

        assert report.error is None
        assert report.domain == "example.com"
        assert "93.184.216.34" in report.a_records
        assert len(report.aaaa_records) >= 1
        assert len(report.mx_records) >= 1
        assert report.mx_records[0]["host"] == "mail.example.com"
        assert len(report.ns_records) >= 1
        assert "ns1.example.com" in report.ns_records
        assert len(report.txt_records) >= 1
        assert report.soa_record != ""
        assert report.spf.get("valid") is True
        assert report.email_security_grade != ""

    @pytest.mark.asyncio
    async def test_partial_failure(self):
        """Some record types fail (return None), others succeed."""
        call_count = 0

        async def partial_fail(url, **kwargs):
            nonlocal call_count
            call_count += 1
            params = kwargs.get("params", {})
            record_type = params.get("type", "")

            resp = MagicMock()

            # Let A and NS succeed, everything else fail
            if record_type == "A":
                resp.status_code = 200
                resp.json.return_value = SAMPLE_DOH_RESPONSE_A
                return resp
            elif record_type == "NS":
                resp.status_code = 200
                resp.json.return_value = SAMPLE_DOH_RESPONSE_NS
                return resp
            else:
                # Fail for both Cloudflare and Google
                raise ConnectionError("DNS provider unavailable")

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock,
                    side_effect=partial_fail):
            report = await dns_lookup("example.com")

        # Should still succeed overall
        assert report.error is None
        assert "93.184.216.34" in report.a_records
        assert "ns1.example.com" in report.ns_records
        # Other fields should be empty (not error)
        assert report.mx_records == []
        assert report.txt_records == []

    @pytest.mark.asyncio
    async def test_both_doh_providers_fail(self):
        """Both Cloudflare and Google DoH fail completely."""
        async def all_fail(url, **kwargs):
            raise ConnectionError("Network unreachable")

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock,
                    side_effect=all_fail):
            report = await dns_lookup("example.com")

        assert report.error is not None
        assert "unreachable" in report.error.lower()

    @pytest.mark.asyncio
    async def test_domain_with_protocol_prefix(self):
        """Should strip https:// prefix and work normally."""
        responses = {"A": SAMPLE_DOH_RESPONSE_A}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock,
                    side_effect=_make_doh_side_effect(responses)):
            report = await dns_lookup("https://example.com")

        assert report.error is None
        assert report.domain == "example.com"
        assert "93.184.216.34" in report.a_records

    @pytest.mark.asyncio
    async def test_empty_domain(self):
        """Empty domain should return error without making any queries."""
        report = await dns_lookup("")
        assert report.error is not None
        assert "Invalid" in report.error

    @pytest.mark.asyncio
    async def test_invalid_domain(self):
        """Invalid domain string should return error."""
        report = await dns_lookup("not a domain!")
        assert report.error is not None

    @pytest.mark.asyncio
    async def test_domain_with_path(self):
        """Domain with path should have path stripped."""
        responses = {"A": SAMPLE_DOH_RESPONSE_A}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock,
                    side_effect=_make_doh_side_effect(responses)):
            report = await dns_lookup("https://example.com/some/path?q=1")

        assert report.error is None
        assert report.domain == "example.com"

    @pytest.mark.asyncio
    async def test_email_security_grade_populated(self):
        """Email security grade should be calculated."""
        responses = {
            "TXT": {
                "Status": 0,
                "Answer": [
                    {"name": "example.com.", "type": 16, "TTL": 300,
                     "data": '"v=spf1 include:_spf.google.com -all"'},
                ],
            },
            "_dmarc.example.com:TXT": SAMPLE_DOH_RESPONSE_DMARC,
            "google._domainkey.example.com:TXT": SAMPLE_DOH_RESPONSE_DKIM,
        }

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock,
                    side_effect=_make_doh_side_effect(responses)):
            report = await dns_lookup("example.com")

        assert report.email_security_grade == "A"

    @pytest.mark.asyncio
    async def test_service_discovery_from_txt(self):
        """Should detect SaaS services from TXT records."""
        responses = {
            "TXT": {
                "Status": 0,
                "Answer": [
                    {"name": "example.com.", "type": 16, "TTL": 300,
                     "data": '"google-site-verification=abc123"'},
                    {"name": "example.com.", "type": 16, "TTL": 300,
                     "data": '"facebook-domain-verification=def456"'},
                ],
            },
        }

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock,
                    side_effect=_make_doh_side_effect(responses)):
            report = await dns_lookup("example.com")

        service_names = [s["service"] for s in report.service_discovery]
        assert "Google Workspace / Search Console" in service_names
        assert "Facebook / Meta" in service_names


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------

class TestHelpers:

    def test_parse_mx_sorted(self):
        answers = [
            {"data": "20 mail2.example.com."},
            {"data": "10 mail.example.com."},
        ]
        result = _parse_mx(answers)
        assert len(result) == 2
        assert result[0]["priority"] == 10
        assert result[0]["host"] == "mail.example.com"
        assert result[1]["priority"] == 20

    def test_parse_mx_single_field(self):
        answers = [{"data": "mail.example.com."}]
        result = _parse_mx(answers)
        assert len(result) == 1
        assert result[0]["host"] == "mail.example.com"

    def test_parse_srv(self):
        answers = [
            {"name": "_sip._tcp.example.com.", "data": "10 5 5060 sip.example.com."},
        ]
        result = _parse_srv(answers)
        assert len(result) == 1
        assert result[0]["service"] == "_sip"
        assert result[0]["protocol"] == "_tcp"
        assert result[0]["port"] == 5060
        assert result[0]["target"] == "sip.example.com"

    def test_strip_txt_quotes(self):
        assert _strip_txt_quotes('"hello world"') == "hello world"
        assert _strip_txt_quotes("hello world") == "hello world"
        assert _strip_txt_quotes('  "quoted"  ') == "quoted"


# ---------------------------------------------------------------------------
# Integration tests (live DNS — skipped by default)
# ---------------------------------------------------------------------------

class TestIntegration:

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_google_com_live(self):
        """Integration test against google.com — requires internet."""
        report = await dns_lookup("google.com")
        assert report.error is None
        assert report.domain == "google.com"
        assert len(report.a_records) > 0
        assert len(report.ns_records) > 0
        assert len(report.mx_records) > 0
        assert len(report.txt_records) > 0
        assert report.email_security_grade != ""

    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_example_com_live(self):
        """Integration test against example.com — requires internet."""
        report = await dns_lookup("example.com")
        assert report.error is None
        assert report.domain == "example.com"
        assert len(report.a_records) > 0
        assert len(report.ns_records) > 0
