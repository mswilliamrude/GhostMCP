"""Tests for composite background report generator — section rendering, confidence, cross-referencing."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace

import pytest

from ghostmcp.recon.report import (
    BackgroundReport,
    LEGAL_DISCLAIMER,
    CONFIDENCE_GOVERNMENT,
    CONFIDENCE_MULTI_SOURCE,
    CONFIDENCE_PAID_API,
    CONFIDENCE_FREE_API,
    CONFIDENCE_BREACH_ONLY,
    CONFIDENCE_URL_ONLY,
    generate_report,
    _section_subject_identity,
    _section_contact_info,
    _section_online_presence,
    _section_professional,
    _section_vehicle,
    _section_court,
    _section_breach,
    _section_search_urls,
    _section_confidence,
    _collect_data_sources,
    _generate_warnings,
)
from ghostmcp.recon.phone import PhoneReport
from ghostmcp.recon.breach import BreachRecord, BreachSearchResult


# ---------------------------------------------------------------------------
# Helpers for mock result objects
# ---------------------------------------------------------------------------


def _make_phone_result(**kwargs) -> PhoneReport:
    """Create a PhoneReport with sensible test defaults."""
    defaults = dict(
        number="+12145551234",
        formatted={
            "e164": "+12145551234",
            "national": "(214) 555-1234",
            "international": "+1 214-555-1234",
        },
        valid=True,
        carrier_name="T-Mobile",
        carrier_type="mobile",
        region="Dallas, TX",
        cnam_name=None,
        veriphone=None,
        search_urls={"reverse_phone": [{"name": "Spokeo", "url": "http://spokeo.com/test"}]},
    )
    defaults.update(kwargs)
    return PhoneReport(**defaults)


def _make_email_result(**kwargs) -> SimpleNamespace:
    """Create a mock email intelligence result."""
    defaults = dict(
        email="test@example.com",
        reputation="high",
        deliverable=True,
        details=None,
        organization="",
        title="",
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def _make_breach_result(**kwargs) -> BreachSearchResult:
    """Create a BreachSearchResult with test data."""
    defaults = dict(
        query="test@example.com",
        query_type="email",
        mode="metadata_only",
        total_breaches=0,
        records=[],
        providers_checked=["HIBP"],
        providers_failed={},
        search_urls={},
    )
    defaults.update(kwargs)
    return BreachSearchResult(**defaults)


def _make_breach_record(**kwargs) -> BreachRecord:
    """Create a BreachRecord with test data."""
    defaults = dict(
        source="hibp",
        breach_name="TestBreach",
        date="2023-01-15",
        data_classes=["Emails", "Passwords"],
        record_count=1000000,
        details=None,
        severity="high",
    )
    defaults.update(kwargs)
    return BreachRecord(**defaults)


def _make_vehicle_result(**kwargs) -> SimpleNamespace:
    """Create a mock vehicle result."""
    defaults = dict(
        vin="1HGCG5655WA014428",
        year="2003",
        make="HONDA",
        model="Accord",
        trim="EX",
        body_class="Sedan",
        plant_city="",
        recalls=[],
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def _make_court_result(**kwargs) -> SimpleNamespace:
    """Create a mock court result."""
    defaults = dict(
        cases=[],
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def _make_username_result(**kwargs) -> SimpleNamespace:
    """Create a mock username enumeration result."""
    defaults = dict(
        sites=[],
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


# ---------------------------------------------------------------------------
# Subject Identity section tests
# ---------------------------------------------------------------------------


class TestSectionSubjectIdentity:
    """Tests for _section_subject_identity()."""

    def test_with_name(self):
        text = _section_subject_identity({"name": "John Doe"})
        assert "John Doe" in text
        assert "Subject Identity" in text

    def test_with_dob(self):
        text = _section_subject_identity({"name": "Jane", "dob": "1990-01-01"})
        assert "1990-01-01" in text

    def test_with_aliases(self):
        text = _section_subject_identity({"name": "John", "aliases": ["JD", "Johnny"]})
        assert "JD" in text
        assert "Johnny" in text

    def test_empty_subject(self):
        text = _section_subject_identity({})
        assert "No identity information available" in text


# ---------------------------------------------------------------------------
# Report with no data (all None)
# ---------------------------------------------------------------------------


class TestGenerateReportNoData:
    """Tests for generate_report() with no OSINT results."""

    def test_no_data_returns_report(self):
        report = generate_report(subject={"name": "Test Subject"})
        assert isinstance(report, BackgroundReport)

    def test_no_data_has_generated_at(self):
        report = generate_report(subject={"name": "Test"})
        assert report.generated_at != ""

    def test_no_data_has_sections(self):
        report = generate_report(subject={"name": "Test"})
        assert "subject_identity" in report.sections
        assert "contact_information" in report.sections
        assert "legal_disclaimer" in report.sections

    def test_no_data_empty_confidence(self):
        report = generate_report(subject={"name": "Test"})
        assert report.confidence_ratings == {}

    def test_no_data_no_warnings(self):
        report = generate_report(subject={"name": "Test"})
        assert report.warnings == []

    def test_no_data_report_text_has_title(self):
        report = generate_report(subject={"name": "Test Subject"})
        assert "# Background Report: Test Subject" in report.report_text

    def test_no_data_report_text_has_disclaimer(self):
        report = generate_report(subject={"name": "Test"})
        assert LEGAL_DISCLAIMER in report.report_text


# ---------------------------------------------------------------------------
# Report with phone result only
# ---------------------------------------------------------------------------


class TestGenerateReportPhoneOnly:
    """Tests for generate_report() with phone data only."""

    def test_phone_in_contact_section(self):
        phone = _make_phone_result()
        report = generate_report(
            subject={"name": "Test", "phone": "+12145551234"},
            phone_result=phone,
        )
        assert "+1 214-555-1234" in report.sections["contact_information"]

    def test_phone_carrier_in_report(self):
        phone = _make_phone_result(carrier_name="T-Mobile", carrier_type="mobile")
        report = generate_report(
            subject={"name": "Test"},
            phone_result=phone,
        )
        assert "T-Mobile" in report.sections["contact_information"]

    def test_phone_confidence_free_api(self):
        phone = _make_phone_result()
        report = generate_report(subject={"name": "T"}, phone_result=phone)
        assert "phone" in report.confidence_ratings
        assert report.confidence_ratings["phone"] == CONFIDENCE_FREE_API

    def test_phone_confidence_paid_api(self):
        phone = _make_phone_result(veriphone={"phone_valid": True})
        report = generate_report(subject={"name": "T"}, phone_result=phone)
        assert report.confidence_ratings["phone"] == CONFIDENCE_PAID_API

    def test_phone_cnam_in_report(self):
        phone = _make_phone_result(cnam_name="JOHN DOE")
        report = generate_report(subject={"name": "T"}, phone_result=phone)
        assert "JOHN DOE" in report.sections["contact_information"]

    def test_phone_data_sources(self):
        phone = _make_phone_result()
        report = generate_report(subject={"name": "T"}, phone_result=phone)
        assert "phonenumbers (offline)" in report.data_sources


# ---------------------------------------------------------------------------
# Report with email result only
# ---------------------------------------------------------------------------


class TestGenerateReportEmailOnly:
    """Tests for generate_report() with email data only."""

    def test_email_in_contact_section(self):
        email = _make_email_result()
        report = generate_report(
            subject={"name": "Test", "email": "test@example.com"},
            email_result=email,
        )
        assert "test@example.com" in report.sections["contact_information"]

    def test_email_reputation_shown(self):
        email = _make_email_result(reputation="high")
        report = generate_report(
            subject={"name": "Test"},
            email_result=email,
        )
        assert "high" in report.sections["contact_information"]

    def test_email_deliverable_shown(self):
        email = _make_email_result(deliverable=True)
        report = generate_report(
            subject={"name": "Test"},
            email_result=email,
        )
        assert "Yes" in report.sections["contact_information"]

    def test_email_confidence(self):
        email = _make_email_result()
        report = generate_report(subject={"name": "T"}, email_result=email)
        assert "email" in report.confidence_ratings
        assert report.confidence_ratings["email"] == CONFIDENCE_FREE_API

    def test_email_confidence_with_details(self):
        email = _make_email_result(details={"organization": "Acme"})
        report = generate_report(subject={"name": "T"}, email_result=email)
        assert report.confidence_ratings["email"] == CONFIDENCE_PAID_API


# ---------------------------------------------------------------------------
# Report with breach data
# ---------------------------------------------------------------------------


class TestGenerateReportBreach:
    """Tests for generate_report() with breach data."""

    def test_breach_section_populated(self):
        rec = _make_breach_record()
        breach = _make_breach_result(
            total_breaches=1,
            records=[rec],
        )
        report = generate_report(subject={"name": "T"}, breach_result=breach)
        assert "TestBreach" in report.sections["breach_exposure"]
        assert "Total breaches found" in report.sections["breach_exposure"]

    def test_breach_severity_breakdown(self):
        rec = _make_breach_record(severity="high")
        breach = _make_breach_result(total_breaches=1, records=[rec])
        report = generate_report(subject={"name": "T"}, breach_result=breach)
        assert "HIGH" in report.sections["breach_exposure"]

    def test_breach_data_classes_shown(self):
        rec = _make_breach_record(data_classes=["Emails", "Passwords"])
        breach = _make_breach_result(total_breaches=1, records=[rec])
        report = generate_report(subject={"name": "T"}, breach_result=breach)
        assert "Emails" in report.sections["breach_exposure"]
        assert "Passwords" in report.sections["breach_exposure"]

    def test_breach_confidence_metadata_mode(self):
        rec = _make_breach_record()
        breach = _make_breach_result(
            mode="metadata_only", total_breaches=1, records=[rec],
        )
        report = generate_report(subject={"name": "T"}, breach_result=breach)
        assert report.confidence_ratings["breach_exposure"] == CONFIDENCE_FREE_API

    def test_breach_confidence_full_mode(self):
        rec = _make_breach_record()
        breach = _make_breach_result(
            mode="full", total_breaches=1, records=[rec],
        )
        report = generate_report(subject={"name": "T"}, breach_result=breach)
        assert report.confidence_ratings["breach_exposure"] == CONFIDENCE_PAID_API

    def test_breach_warning_stale_data(self):
        rec = _make_breach_record()
        breach = _make_breach_result(total_breaches=1, records=[rec])
        report = generate_report(subject={"name": "T"}, breach_result=breach)
        stale_warnings = [w for w in report.warnings if "outdated" in w.lower()]
        assert len(stale_warnings) >= 1

    def test_breach_warning_full_mode_pii(self):
        rec = _make_breach_record()
        breach = _make_breach_result(
            mode="full", total_breaches=1, records=[rec],
        )
        report = generate_report(subject={"name": "T"}, breach_result=breach)
        pii_warnings = [w for w in report.warnings if "PII" in w]
        assert len(pii_warnings) >= 1

    def test_no_breach_records(self):
        breach = _make_breach_result(total_breaches=0, records=[])
        report = generate_report(subject={"name": "T"}, breach_result=breach)
        assert "No breaches found" in report.sections["breach_exposure"]


# ---------------------------------------------------------------------------
# Report with all results populated
# ---------------------------------------------------------------------------


class TestGenerateReportFull:
    """Tests for generate_report() with all result types."""

    def test_all_sections_present(self):
        phone = _make_phone_result(cnam_name="JOHN DOE")
        email = _make_email_result(
            organization="Acme Corp",
            details={"organization": "Acme Corp"},
        )
        rec = _make_breach_record(
            details={"employer": "Acme Corp"},
        )
        breach = _make_breach_result(total_breaches=1, records=[rec])
        vehicle = _make_vehicle_result()
        court = _make_court_result(cases=[
            {"caseName": "State v. Doe", "court": "TX District", "dateFiled": "2020-01-01"},
        ])
        username = _make_username_result(sites=[
            {"name": "GitHub", "url": "https://github.com/testuser"},
        ])

        report = generate_report(
            subject={"name": "John Doe", "email": "test@example.com",
                     "phone": "+12145551234"},
            phone_result=phone,
            email_result=email,
            breach_result=breach,
            vehicle_result=vehicle,
            court_result=court,
            username_result=username,
        )

        assert "subject_identity" in report.sections
        assert "contact_information" in report.sections
        assert "online_presence" in report.sections
        assert "professional_information" in report.sections
        assert "vehicle_information" in report.sections
        assert "court_records" in report.sections
        assert "breach_exposure" in report.sections
        assert "legal_disclaimer" in report.sections
        assert "data_sources_confidence" in report.sections

    def test_report_text_generated(self):
        phone = _make_phone_result()
        report = generate_report(
            subject={"name": "John Doe"},
            phone_result=phone,
        )
        assert len(report.report_text) > 100
        assert "# Background Report" in report.report_text

    def test_data_sources_populated(self):
        phone = _make_phone_result(veriphone={"phone_valid": True}, cnam_name="DOE")
        email = _make_email_result(details={"organization": "Acme"})
        report = generate_report(
            subject={"name": "Test"},
            phone_result=phone,
            email_result=email,
        )
        assert "phonenumbers (offline)" in report.data_sources
        assert "Veriphone API" in report.data_sources
        assert "CNAM lookup" in report.data_sources
        assert "Hunter.io / email verification API" in report.data_sources


# ---------------------------------------------------------------------------
# Confidence rating tests
# ---------------------------------------------------------------------------


class TestConfidenceRatings:
    """Tests for confidence rating assignment."""

    def test_government_confidence(self):
        vehicle = _make_vehicle_result()
        report = generate_report(
            subject={"name": "T"},
            vehicle_result=vehicle,
        )
        assert report.confidence_ratings.get("vehicle") == CONFIDENCE_GOVERNMENT

    def test_court_confidence(self):
        court = _make_court_result(cases=[
            {"caseName": "Test", "court": "Test Court"},
        ])
        report = generate_report(
            subject={"name": "T"},
            court_result=court,
        )
        assert report.confidence_ratings.get("court_records") == CONFIDENCE_GOVERNMENT

    def test_url_only_confidence(self):
        """Address with no verification gets URL_ONLY confidence."""
        report = generate_report(
            subject={"name": "T", "address": "123 Main St"},
        )
        assert report.confidence_ratings.get("address") == CONFIDENCE_URL_ONLY

    def test_confidence_section_rendered(self):
        phone = _make_phone_result()
        report = generate_report(
            subject={"name": "T"},
            phone_result=phone,
        )
        conf_section = report.sections.get("data_sources_confidence", "")
        assert "Confidence" in conf_section
        assert "phone" in conf_section


# ---------------------------------------------------------------------------
# Legal disclaimer tests
# ---------------------------------------------------------------------------


class TestLegalDisclaimer:
    """Tests for legal disclaimer presence."""

    def test_disclaimer_in_sections(self):
        report = generate_report(subject={"name": "T"})
        assert "legal_disclaimer" in report.sections
        assert LEGAL_DISCLAIMER in report.sections["legal_disclaimer"]

    def test_disclaimer_in_report_text(self):
        report = generate_report(subject={"name": "T"})
        assert LEGAL_DISCLAIMER in report.report_text

    def test_disclaimer_content(self):
        assert "FCRA" in LEGAL_DISCLAIMER
        assert "employment screening" in LEGAL_DISCLAIMER
        assert "OSINT" in LEGAL_DISCLAIMER


# ---------------------------------------------------------------------------
# Cross-referencing tests
# ---------------------------------------------------------------------------


class TestCrossReferencing:
    """Tests for cross-referencing between modules."""

    def test_employer_from_email_and_breach_multi_source(self):
        """Employer found in both email and breach gets MULTI_SOURCE confidence."""
        email = _make_email_result(
            organization="Acme Corp",
            details={"organization": "Acme Corp"},
        )
        rec = _make_breach_record(details={"employer": "Acme Corp"})
        breach = _make_breach_result(total_breaches=1, records=[rec])

        report = generate_report(
            subject={"name": "T"},
            email_result=email,
            breach_result=breach,
        )
        assert "Acme Corp" in report.sections["professional_information"]
        assert report.confidence_ratings.get("employer") == CONFIDENCE_MULTI_SOURCE

    def test_employer_from_email_only(self):
        email = _make_email_result(
            organization="Solo Corp",
            details={"organization": "Solo Corp"},
        )
        report = generate_report(
            subject={"name": "T"},
            email_result=email,
        )
        assert "Solo Corp" in report.sections["professional_information"]
        assert report.confidence_ratings.get("employer") == CONFIDENCE_PAID_API

    def test_employer_from_breach_only(self):
        rec = _make_breach_record(details={"employer": "Breach Inc"})
        breach = _make_breach_result(total_breaches=1, records=[rec])
        report = generate_report(
            subject={"name": "T"},
            breach_result=breach,
        )
        assert "Breach Inc" in report.sections["professional_information"]
        assert report.confidence_ratings.get("employer") == CONFIDENCE_BREACH_ONLY


# ---------------------------------------------------------------------------
# Warning generation tests
# ---------------------------------------------------------------------------


class TestWarningGeneration:
    """Tests for _generate_warnings()."""

    def test_stale_data_warning(self):
        rec = _make_breach_record()
        breach = _make_breach_result(total_breaches=1, records=[rec])
        warnings = _generate_warnings(breach, None, {})
        stale = [w for w in warnings if "outdated" in w.lower()]
        assert len(stale) >= 1

    def test_full_mode_pii_warning(self):
        rec = _make_breach_record()
        breach = _make_breach_result(mode="full", total_breaches=1, records=[rec])
        warnings = _generate_warnings(breach, None, {})
        pii = [w for w in warnings if "PII" in w]
        assert len(pii) >= 1

    def test_failed_providers_warning(self):
        breach = _make_breach_result(
            providers_failed={"snusbase": "API key invalid"},
        )
        warnings = _generate_warnings(breach, None, {})
        failed = [w for w in warnings if "failed" in w.lower()]
        assert len(failed) >= 1
        assert "snusbase" in failed[0]

    def test_court_records_caveat(self):
        court = _make_court_result(cases=[{"caseName": "Test"}])
        warnings = _generate_warnings(None, court, {})
        sealed = [w for w in warnings if "sealed" in w.lower()]
        assert len(sealed) >= 1

    def test_low_confidence_warning(self):
        confidences = {"address": CONFIDENCE_URL_ONLY, "phone": CONFIDENCE_PAID_API}
        warnings = _generate_warnings(None, None, confidences)
        low = [w for w in warnings if "low-confidence" in w.lower()]
        assert len(low) >= 1
        assert "address" in low[0].lower()

    def test_no_warnings_with_no_data(self):
        warnings = _generate_warnings(None, None, {})
        assert warnings == []


# ---------------------------------------------------------------------------
# BackgroundReport dataclass tests
# ---------------------------------------------------------------------------


class TestBackgroundReport:
    """Tests for the BackgroundReport dataclass defaults."""

    def test_defaults(self):
        report = BackgroundReport()
        assert report.subject == {}
        assert report.sections == {}
        assert report.data_sources == []
        assert report.confidence_ratings == {}
        assert report.generated_at == ""
        assert report.warnings == []
        assert report.report_text == ""
