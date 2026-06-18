"""Composite background report generator — assembles OSINT results into a structured report.

This module does NOT make API calls.  It takes dataclass results from
other recon modules (phone, breach, etc.) and compiles them into a
cross-referenced, confidence-rated markdown report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

LEGAL_DISCLAIMER = (
    "This report is generated from publicly available information and breach "
    "databases for OSINT research purposes only. It is NOT a consumer report "
    "under FCRA and must NOT be used for employment screening, tenant "
    "screening, credit decisions, or any purpose requiring FCRA compliance. "
    "Data accuracy varies by source and may be outdated. The operator assumes "
    "all legal responsibility for the use of this information."
)


# ── Confidence tiers ─────────────────────────────────────────────────────

CONFIDENCE_GOVERNMENT = 1.0    # NHTSA, CourtListener, gov databases
CONFIDENCE_MULTI_SOURCE = 0.9  # multiple independent sources agree
CONFIDENCE_PAID_API = 0.7      # single paid API (Hunter.io, Snusbase)
CONFIDENCE_FREE_API = 0.5      # single free API (EmailRep)
CONFIDENCE_BREACH_ONLY = 0.3   # breach data only (may be stale)
CONFIDENCE_URL_ONLY = 0.1      # URL generator only (unverified)


@dataclass
class BackgroundReport:
    """Compiled background report from multiple OSINT sources."""

    subject: dict = field(default_factory=dict)
    sections: dict[str, str] = field(default_factory=dict)
    data_sources: list[str] = field(default_factory=list)
    confidence_ratings: dict[str, float] = field(default_factory=dict)
    generated_at: str = ""
    warnings: list[str] = field(default_factory=list)
    report_text: str = ""


# ── Section extractors ───────────────────────────────────────────────────


def _section_subject_identity(subject: dict) -> str:
    """Build the Subject Identity section."""
    lines: list[str] = ["## Subject Identity", ""]

    name = subject.get("name", "")
    if name:
        lines.append(f"- **Name:** {name}")
    dob = subject.get("dob", "")
    if dob:
        lines.append(f"- **Date of Birth:** {dob}")

    aliases = subject.get("aliases", [])
    if aliases:
        lines.append(f"- **Known Aliases:** {', '.join(aliases)}")

    if len(lines) <= 2:
        lines.append("- *No identity information available*")

    return "\n".join(lines)


def _section_contact_info(
    subject: dict,
    phone_result: object | None,
    email_result: object | None,
) -> tuple[str, dict[str, float]]:
    """Build Contact Information section with confidence ratings."""
    lines: list[str] = ["## Contact Information", ""]
    confidences: dict[str, float] = {}

    # Phone
    phone = subject.get("phone", "")
    if phone_result is not None:
        formatted = getattr(phone_result, "formatted", {})
        intl = formatted.get("international", "") if isinstance(formatted, dict) else ""
        carrier = getattr(phone_result, "carrier_name", "")
        carrier_type = getattr(phone_result, "carrier_type", "")
        region = getattr(phone_result, "region", "")
        cnam = getattr(phone_result, "cnam_name", None)
        display = intl or phone or getattr(phone_result, "number", "")

        lines.append(f"- **Phone:** {display}")
        if carrier:
            lines.append(f"  - Carrier: {carrier} ({carrier_type})")
        if region:
            lines.append(f"  - Region: {region}")
        if cnam:
            lines.append(f"  - CNAM: {cnam}")

        # Confidence: veriphone data = paid API, offline-only = free
        if getattr(phone_result, "veriphone", None):
            confidences["phone"] = CONFIDENCE_PAID_API
        else:
            confidences["phone"] = CONFIDENCE_FREE_API
    elif phone:
        lines.append(f"- **Phone:** {phone}")
        confidences["phone"] = CONFIDENCE_URL_ONLY

    # Email
    email = subject.get("email", "")
    if email_result is not None:
        addr = getattr(email_result, "email", email) or email
        lines.append(f"- **Email:** {addr}")

        reputation = getattr(email_result, "reputation", None)
        if reputation:
            lines.append(f"  - Reputation: {reputation}")

        deliverable = getattr(email_result, "deliverable", None)
        if deliverable is not None:
            lines.append(f"  - Deliverable: {'Yes' if deliverable else 'No'}")

        # Confidence depends on source depth
        if getattr(email_result, "details", None):
            confidences["email"] = CONFIDENCE_PAID_API
        else:
            confidences["email"] = CONFIDENCE_FREE_API
    elif email:
        lines.append(f"- **Email:** {email}")
        confidences["email"] = CONFIDENCE_URL_ONLY

    # Address
    address = subject.get("address", "")
    if address:
        lines.append(f"- **Address:** {address}")
        confidences["address"] = CONFIDENCE_URL_ONLY

    if len(lines) <= 2:
        lines.append("- *No contact information available*")

    return "\n".join(lines), confidences


def _section_online_presence(
    username_result: object | None,
) -> tuple[str, dict[str, float]]:
    """Build Online Presence section."""
    lines: list[str] = ["## Online Presence", ""]
    confidences: dict[str, float] = {}

    if username_result is None:
        lines.append("- *No username enumeration data available*")
        return "\n".join(lines), confidences

    # Generic extraction — works with any dataclass that has sites/profiles/results
    sites = (
        getattr(username_result, "sites", None)
        or getattr(username_result, "profiles", None)
        or getattr(username_result, "results", None)
        or []
    )

    if isinstance(sites, dict):
        for platform, info in sites.items():
            url = info.get("url", "") if isinstance(info, dict) else str(info)
            lines.append(f"- **{platform}:** {url}")
            confidences[f"username_{platform}"] = CONFIDENCE_FREE_API
    elif isinstance(sites, list):
        for site in sites:
            if isinstance(site, dict):
                name = site.get("name", site.get("site", "Unknown"))
                url = site.get("url", site.get("profile_url", ""))
                lines.append(f"- **{name}:** {url}")
                confidences[f"username_{name}"] = CONFIDENCE_FREE_API
            else:
                lines.append(f"- {site}")

    if len(lines) <= 2:
        lines.append("- *No social media profiles found*")

    return "\n".join(lines), confidences


def _section_professional(
    email_result: object | None,
    breach_result: object | None,
) -> tuple[str, dict[str, float]]:
    """Build Professional Information section from email/breach cross-reference."""
    lines: list[str] = ["## Professional Information", ""]
    confidences: dict[str, float] = {}

    employer_sources: list[str] = []
    employer = ""
    title = ""

    # Extract from email result (e.g. Hunter.io data)
    if email_result is not None:
        org = getattr(email_result, "organization", "") or ""
        if not org:
            details = getattr(email_result, "details", None)
            if isinstance(details, dict):
                org = details.get("organization", "")
        if org:
            employer = org
            employer_sources.append("email_lookup")

        t = getattr(email_result, "title", "") or ""
        if not t:
            details = getattr(email_result, "details", None)
            if isinstance(details, dict):
                t = details.get("title", details.get("position", ""))
        if t:
            title = t

    # Cross-reference: check breach data for employer names
    if breach_result is not None:
        records = getattr(breach_result, "records", [])
        for rec in records:
            details = getattr(rec, "details", None)
            if isinstance(details, dict):
                breach_employer = details.get("employer", details.get("company", ""))
                if breach_employer:
                    if not employer:
                        employer = breach_employer
                        employer_sources.append("breach_data")
                    elif breach_employer.lower() == employer.lower():
                        employer_sources.append("breach_data")

    if employer:
        lines.append(f"- **Employer:** {employer}")
        # Multi-source confirmation boosts confidence
        if len(employer_sources) > 1:
            confidences["employer"] = CONFIDENCE_MULTI_SOURCE
        elif "email_lookup" in employer_sources:
            confidences["employer"] = CONFIDENCE_PAID_API
        else:
            confidences["employer"] = CONFIDENCE_BREACH_ONLY

    if title:
        lines.append(f"- **Title:** {title}")
        confidences["title"] = CONFIDENCE_PAID_API

    if len(lines) <= 2:
        lines.append("- *No professional information found*")

    return "\n".join(lines), confidences


def _section_vehicle(vehicle_result: object | None) -> tuple[str, dict[str, float]]:
    """Build Vehicle Information section."""
    lines: list[str] = ["## Vehicle Information", ""]
    confidences: dict[str, float] = {}

    if vehicle_result is None:
        lines.append("- *No vehicle data provided*")
        return "\n".join(lines), confidences

    vin = getattr(vehicle_result, "vin", "")
    if vin:
        lines.append(f"- **VIN:** {vin}")

    for attr_name, label in [
        ("year", "Year"),
        ("make", "Make"),
        ("model", "Model"),
        ("trim", "Trim"),
        ("body_class", "Body Class"),
        ("plant_city", "Assembly Plant"),
    ]:
        val = getattr(vehicle_result, attr_name, "") or ""
        if val:
            lines.append(f"- **{label}:** {val}")

    recalls = getattr(vehicle_result, "recalls", [])
    if recalls:
        lines.append(f"- **Recalls:** {len(recalls)} found")
        for recall in recalls[:5]:
            if isinstance(recall, dict):
                comp = recall.get("Component", "Unknown")
                summary = recall.get("Summary", "")[:120]
                lines.append(f"  - {comp}: {summary}")

    # NHTSA is a government source
    if vin:
        confidences["vehicle"] = CONFIDENCE_GOVERNMENT

    if len(lines) <= 2:
        lines.append("- *No vehicle details decoded*")

    return "\n".join(lines), confidences


def _section_court(court_result: object | None) -> tuple[str, dict[str, float]]:
    """Build Court Records section."""
    lines: list[str] = ["## Court Records", ""]
    confidences: dict[str, float] = {}

    if court_result is None:
        lines.append("- *No court records data provided*")
        return "\n".join(lines), confidences

    cases = getattr(court_result, "cases", getattr(court_result, "results", []))
    if not cases:
        lines.append("- *No court records found*")
        return "\n".join(lines), confidences

    lines.append(f"**{len(cases)} case(s) found:**")
    lines.append("")

    for case in cases[:10]:
        if isinstance(case, dict):
            case_name = case.get("caseName", case.get("name", "Unknown"))
            court = case.get("court", "")
            date_filed = case.get("dateFiled", case.get("date", ""))
            lines.append(f"- **{case_name}**")
            if court:
                lines.append(f"  - Court: {court}")
            if date_filed:
                lines.append(f"  - Filed: {date_filed}")
        elif hasattr(case, "case_name"):
            lines.append(f"- **{case.case_name}**")
            if hasattr(case, "court"):
                lines.append(f"  - Court: {case.court}")
            if hasattr(case, "date_filed"):
                lines.append(f"  - Filed: {case.date_filed}")

    # CourtListener = government/authoritative
    confidences["court_records"] = CONFIDENCE_GOVERNMENT

    return "\n".join(lines), confidences


def _section_breach(breach_result: object | None) -> tuple[str, dict[str, float]]:
    """Build Breach Exposure section."""
    lines: list[str] = ["## Breach Exposure", ""]
    confidences: dict[str, float] = {}

    if breach_result is None:
        lines.append("- *No breach data provided*")
        return "\n".join(lines), confidences

    records = getattr(breach_result, "records", [])
    total = getattr(breach_result, "total_breaches", len(records))
    mode = getattr(breach_result, "mode", "metadata_only")

    if not records:
        lines.append("- *No breaches found*")
        return "\n".join(lines), confidences

    # Severity summary
    severity_counts: dict[str, int] = {}
    all_data_classes: set[str] = set()
    for rec in records:
        sev = getattr(rec, "severity", "low")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        for dc in getattr(rec, "data_classes", []):
            all_data_classes.add(dc)

    lines.append(f"**Total breaches found:** {total}")
    lines.append(f"**Search mode:** {mode}")
    lines.append("")

    # Severity breakdown
    lines.append("**Severity breakdown:**")
    for sev in ("critical", "high", "medium", "low"):
        count = severity_counts.get(sev, 0)
        if count:
            lines.append(f"- {sev.upper()}: {count}")
    lines.append("")

    # Data types exposed
    if all_data_classes:
        lines.append("**Data types exposed across all breaches:**")
        for dc in sorted(all_data_classes):
            lines.append(f"- {dc}")
        lines.append("")

    # Individual breaches (capped at 20)
    lines.append("**Breach details:**")
    lines.append("")
    for rec in records[:20]:
        name = getattr(rec, "breach_name", "Unknown")
        date = getattr(rec, "date", "")
        source = getattr(rec, "source", "")
        sev = getattr(rec, "severity", "low")
        count = getattr(rec, "record_count", None)

        header = f"- **{name}**"
        if date:
            header += f" ({date})"
        header += f" — {sev.upper()}"
        if source:
            header += f" [via {source}]"
        lines.append(header)

        if count is not None:
            lines.append(f"  - Records: {count:,}")

        rec_classes = getattr(rec, "data_classes", [])
        if rec_classes:
            lines.append(f"  - Exposed: {', '.join(rec_classes)}")

    if len(records) > 20:
        lines.append(f"- *... and {len(records) - 20} more breaches*")

    # Confidence: HIBP = free API, full-mode providers = paid
    if mode == "full":
        confidences["breach_exposure"] = CONFIDENCE_PAID_API
    else:
        confidences["breach_exposure"] = CONFIDENCE_FREE_API

    return "\n".join(lines), confidences


def _section_search_urls(
    subject: dict,
    phone_result: object | None,
    breach_result: object | None,
    people_urls: dict | None,
) -> str:
    """Build Search URLs section for manual follow-up."""
    lines: list[str] = ["## Search URLs for Manual Follow-Up", ""]

    # From people_urls argument
    if people_urls:
        for category, urls in people_urls.items():
            lines.append(f"**{category}:**")
            if isinstance(urls, list):
                for entry in urls:
                    if isinstance(entry, dict):
                        name = entry.get("name", "Link")
                        url = entry.get("url", "")
                        lines.append(f"- [{name}]({url})")
                    else:
                        lines.append(f"- {entry}")
            elif isinstance(urls, dict):
                for name, url in urls.items():
                    lines.append(f"- [{name}]({url})")
            lines.append("")

    # Phone search URLs
    if phone_result is not None:
        phone_urls = getattr(phone_result, "search_urls", {})
        if phone_urls:
            for category, url_list in phone_urls.items():
                lines.append(f"**{category}:**")
                if isinstance(url_list, list):
                    for entry in url_list:
                        if isinstance(entry, dict):
                            lines.append(f"- [{entry.get('name', 'Link')}]({entry.get('url', '')})")
                        else:
                            lines.append(f"- {entry}")
                lines.append("")

    # Breach search URLs
    if breach_result is not None:
        breach_urls = getattr(breach_result, "search_urls", {})
        if breach_urls:
            lines.append("**Breach databases:**")
            for name, url in breach_urls.items():
                lines.append(f"- [{name}]({url})")
            lines.append("")

    if len(lines) <= 2:
        lines.append("- *No search URLs generated*")

    return "\n".join(lines)


def _section_confidence(confidences: dict[str, float]) -> str:
    """Build Data Sources & Confidence section."""
    lines: list[str] = ["## Data Sources & Confidence", ""]

    if not confidences:
        lines.append("- *No confidence ratings available*")
        return "\n".join(lines)

    lines.append("| Data Point | Confidence | Basis |")
    lines.append("|---|---|---|")

    basis_map = {
        CONFIDENCE_GOVERNMENT: "Government/authoritative source",
        CONFIDENCE_MULTI_SOURCE: "Multiple sources agree",
        CONFIDENCE_PAID_API: "Single paid API",
        CONFIDENCE_FREE_API: "Single free API",
        CONFIDENCE_BREACH_ONLY: "Breach data only (may be stale)",
        CONFIDENCE_URL_ONLY: "URL generator only (unverified)",
    }

    for point, score in sorted(confidences.items(), key=lambda x: -x[1]):
        # Find nearest basis label
        basis = "Unknown"
        min_diff = float("inf")
        for threshold, label in basis_map.items():
            diff = abs(score - threshold)
            if diff < min_diff:
                min_diff = diff
                basis = label
        lines.append(f"| {point} | {score:.1f} | {basis} |")

    return "\n".join(lines)


# ── Data source tracking ────────────────────────────────────────────────


def _collect_data_sources(
    phone_result: object | None,
    email_result: object | None,
    username_result: object | None,
    vehicle_result: object | None,
    court_result: object | None,
    breach_result: object | None,
    people_urls: dict | None,
) -> list[str]:
    """Enumerate which APIs/tools contributed data."""
    sources: list[str] = []

    if phone_result is not None:
        sources.append("phonenumbers (offline)")
        if getattr(phone_result, "veriphone", None):
            sources.append("Veriphone API")
        if getattr(phone_result, "cnam_name", None):
            sources.append("CNAM lookup")

    if email_result is not None:
        sources.append("Email intelligence")
        if getattr(email_result, "details", None):
            sources.append("Hunter.io / email verification API")

    if username_result is not None:
        sources.append("Username enumeration")

    if vehicle_result is not None:
        sources.append("NHTSA VIN decoder")

    if court_result is not None:
        sources.append("CourtListener / PACER")

    if breach_result is not None:
        providers = getattr(breach_result, "providers_checked", [])
        for p in providers:
            sources.append(f"Breach DB: {p}")

    if people_urls is not None:
        sources.append("People search URL generators")

    return sources


# ── Warning generation ───────────────────────────────────────────────────


def _generate_warnings(
    breach_result: object | None,
    court_result: object | None,
    confidences: dict[str, float],
) -> list[str]:
    """Generate data freshness and legal caveats."""
    warnings: list[str] = []

    # Breach data staleness
    if breach_result is not None:
        records = getattr(breach_result, "records", [])
        if records:
            warnings.append(
                "Breach data may be outdated — records reflect the state at "
                "time of breach, not current information."
            )
        mode = getattr(breach_result, "mode", "metadata_only")
        if mode == "full":
            warnings.append(
                "Full breach mode was used — results contain PII from breach "
                "databases.  Handle in accordance with your jurisdiction's "
                "data protection laws."
            )
        failed = getattr(breach_result, "providers_failed", {})
        if failed:
            providers = ", ".join(failed.keys())
            warnings.append(
                f"Some breach providers failed: {providers}.  "
                "Results may be incomplete."
            )

    # Court records caveat
    if court_result is not None:
        cases = getattr(court_result, "cases", getattr(court_result, "results", []))
        if cases:
            warnings.append(
                "Court records shown are from public dockets.  Sealed, "
                "expunged, or juvenile records are not included."
            )

    # Low confidence warnings
    low_conf = [k for k, v in confidences.items() if v <= CONFIDENCE_BREACH_ONLY]
    if low_conf:
        warnings.append(
            f"Low-confidence data points ({', '.join(low_conf)}) are based "
            "on limited sources and should be independently verified."
        )

    return warnings


# ── Main entry point ─────────────────────────────────────────────────────


def generate_report(
    subject: dict,
    phone_result: object | None = None,
    email_result: object | None = None,
    username_result: object | None = None,
    vehicle_result: object | None = None,
    court_result: object | None = None,
    breach_result: object | None = None,
    people_urls: dict | None = None,
) -> BackgroundReport:
    """Compile a background report from multiple OSINT module results.

    This is pure data transformation — no API calls, no I/O.  Each
    parameter accepts the dataclass result from its respective recon
    module (or None if that module was not run).

    Args:
        subject: Dict with known subject identifiers — name, email,
                 phone, username, dob, aliases, address, etc.
        phone_result: Result from phone.phone_lookup().
        email_result: Result from an email intelligence module.
        username_result: Result from a username enumeration module.
        vehicle_result: Result from a VIN/vehicle lookup module.
        court_result: Result from a court records search module.
        breach_result: Result from breach.breach_search().
        people_urls: Dict of category -> URL list for people search sites.

    Returns:
        BackgroundReport with compiled sections, confidence ratings,
        warnings, and formatted markdown.
    """
    report = BackgroundReport(
        subject=subject,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )

    all_confidences: dict[str, float] = {}
    sections: dict[str, str] = {}

    # ── Build each section ───────────────────────────────────────────

    sections["subject_identity"] = _section_subject_identity(subject)

    contact_text, contact_conf = _section_contact_info(subject, phone_result, email_result)
    sections["contact_information"] = contact_text
    all_confidences.update(contact_conf)

    online_text, online_conf = _section_online_presence(username_result)
    sections["online_presence"] = online_text
    all_confidences.update(online_conf)

    prof_text, prof_conf = _section_professional(email_result, breach_result)
    sections["professional_information"] = prof_text
    all_confidences.update(prof_conf)

    vehicle_text, vehicle_conf = _section_vehicle(vehicle_result)
    sections["vehicle_information"] = vehicle_text
    all_confidences.update(vehicle_conf)

    court_text, court_conf = _section_court(court_result)
    sections["court_records"] = court_text
    all_confidences.update(court_conf)

    breach_text, breach_conf = _section_breach(breach_result)
    sections["breach_exposure"] = breach_text
    all_confidences.update(breach_conf)

    sections["search_urls"] = _section_search_urls(
        subject, phone_result, breach_result, people_urls,
    )

    sections["data_sources_confidence"] = _section_confidence(all_confidences)

    sections["legal_disclaimer"] = f"## Legal Disclaimer\n\n{LEGAL_DISCLAIMER}"

    # ── Assemble ─────────────────────────────────────────────────────

    report.sections = sections
    report.confidence_ratings = all_confidences

    report.data_sources = _collect_data_sources(
        phone_result, email_result, username_result,
        vehicle_result, court_result, breach_result, people_urls,
    )

    report.warnings = _generate_warnings(breach_result, court_result, all_confidences)

    # ── Render full markdown ─────────────────────────────────────────

    subject_name = subject.get("name", subject.get("email", "Unknown Subject"))
    md_parts: list[str] = [
        f"# Background Report: {subject_name}",
        "",
        f"*Generated: {report.generated_at}*",
        "",
    ]

    # Warnings block
    if report.warnings:
        md_parts.append("> **Warnings:**")
        for w in report.warnings:
            md_parts.append(f"> - {w}")
        md_parts.append("")

    md_parts.append("---")
    md_parts.append("")

    # Sections in display order
    section_order = [
        "subject_identity",
        "contact_information",
        "online_presence",
        "professional_information",
        "vehicle_information",
        "court_records",
        "breach_exposure",
        "search_urls",
        "data_sources_confidence",
        "legal_disclaimer",
    ]

    for key in section_order:
        text = sections.get(key, "")
        if text:
            md_parts.append(text)
            md_parts.append("")
            md_parts.append("---")
            md_parts.append("")

    report.report_text = "\n".join(md_parts)

    return report
