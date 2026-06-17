"""Tests for TLS certificate inspection module."""

from __future__ import annotations

import hashlib
import socket
import ssl
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

import pytest

from src.recon.certs import (
    CertReport,
    inspect_cert,
    _extract_cn,
    _format_rdn,
    _extract_sans,
    _parse_cert_date,
    _detect_key_type_from_der,
    _connect_and_inspect,
)


# ---------------------------------------------------------------------------
# CertReport dataclass tests
# ---------------------------------------------------------------------------

class TestCertReport:
    """Tests for CertReport dataclass creation."""

    def test_basic_creation(self):
        report = CertReport(
            host="example.com",
            port=443,
            subject="CN=example.com",
            issuer="CN=Let's Encrypt R3",
            not_before="Jan  1 00:00:00 2026 GMT",
            not_after="Apr  1 00:00:00 2027 GMT",
            days_until_expiry=365,
            sans=["example.com", "www.example.com"],
            serial="0A1B2C3D",
            fingerprint_sha256="abcd" * 16,
            protocol="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            key_type="RSA 2048",
            is_self_signed=False,
            is_expired=False,
            chain=["example.com", "R3", "ISRG Root X1"],
        )
        assert report.host == "example.com"
        assert report.port == 443
        assert report.error is None
        assert len(report.sans) == 2
        assert len(report.chain) == 3

    def test_error_field_default_none(self):
        report = CertReport(
            host="test.com", port=443, subject="", issuer="",
            not_before="", not_after="", days_until_expiry=0,
            sans=[], serial="", fingerprint_sha256="",
            protocol="", cipher="", key_type="",
            is_self_signed=False, is_expired=False, chain=[],
        )
        assert report.error is None

    def test_with_error(self):
        report = CertReport(
            host="bad.com", port=443, subject="", issuer="",
            not_before="", not_after="", days_until_expiry=0,
            sans=[], serial="", fingerprint_sha256="",
            protocol="", cipher="", key_type="",
            is_self_signed=False, is_expired=False, chain=[],
            error="Connection refused",
        )
        assert report.error == "Connection refused"

    def test_self_signed_flag(self):
        report = CertReport(
            host="self.com", port=443,
            subject="CN=self.com", issuer="CN=self.com",
            not_before="", not_after="", days_until_expiry=0,
            sans=[], serial="", fingerprint_sha256="",
            protocol="", cipher="", key_type="",
            is_self_signed=True, is_expired=False, chain=[],
        )
        assert report.is_self_signed is True

    def test_expired_flag(self):
        report = CertReport(
            host="expired.com", port=443,
            subject="", issuer="",
            not_before="", not_after="", days_until_expiry=-30,
            sans=[], serial="", fingerprint_sha256="",
            protocol="", cipher="", key_type="",
            is_self_signed=False, is_expired=True, chain=[],
        )
        assert report.is_expired is True
        assert report.days_until_expiry < 0


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------

class TestExtractCN:
    """Tests for _extract_cn()."""

    def test_extracts_cn(self):
        rdns = ((("commonName", "example.com"),),)
        assert _extract_cn(rdns) == "example.com"

    def test_multiple_rdns(self):
        rdns = (
            (("countryName", "US"),),
            (("organizationName", "Example Inc"),),
            (("commonName", "example.com"),),
        )
        assert _extract_cn(rdns) == "example.com"

    def test_no_cn(self):
        rdns = ((("organizationName", "Example"),),)
        assert _extract_cn(rdns) == ""

    def test_empty_rdns(self):
        assert _extract_cn(()) == ""


class TestFormatRDN:
    """Tests for _format_rdn()."""

    def test_single_rdn(self):
        rdns = ((("commonName", "example.com"),),)
        assert _format_rdn(rdns) == "commonName=example.com"

    def test_multiple_rdns(self):
        rdns = (
            (("countryName", "US"),),
            (("commonName", "example.com"),),
        )
        result = _format_rdn(rdns)
        assert "countryName=US" in result
        assert "commonName=example.com" in result

    def test_empty(self):
        assert _format_rdn(()) == ""


class TestExtractSANs:
    """Tests for _extract_sans()."""

    def test_extracts_dns_sans(self):
        cert_dict = {
            "subjectAltName": (
                ("DNS", "example.com"),
                ("DNS", "www.example.com"),
            ),
        }
        sans = _extract_sans(cert_dict)
        assert sans == ["example.com", "www.example.com"]

    def test_no_sans(self):
        assert _extract_sans({}) == []

    def test_empty_san_tuple(self):
        assert _extract_sans({"subjectAltName": ()}) == []


class TestParseCertDate:
    """Tests for _parse_cert_date()."""

    def test_valid_date(self):
        dt = _parse_cert_date("Jan  5 00:00:00 2026 GMT")
        assert dt.year == 2026
        assert dt.month == 1
        assert dt.day == 5
        assert dt.tzinfo == timezone.utc

    def test_invalid_date_raises(self):
        with pytest.raises(ValueError):
            _parse_cert_date("not-a-date")


class TestDetectKeyTypeFromDER:
    """Tests for _detect_key_type_from_der()."""

    def test_rsa_oid_detected(self):
        # Build a fake DER with RSA OID embedded, large enough for 2048 estimate
        rsa_oid = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"
        fake_der = b"\x00" * 1200 + rsa_oid + b"\x00" * 100
        result = _detect_key_type_from_der(fake_der)
        assert "RSA" in result

    def test_ec_p256_detected(self):
        ec_oid = b"\x06\x07\x2a\x86\x48\xce\x3d\x02\x01"
        p256_oid = b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"
        fake_der = ec_oid + b"\x00" * 50 + p256_oid
        result = _detect_key_type_from_der(fake_der)
        assert result == "EC 256"

    def test_unknown_cert(self):
        fake_der = b"\x00" * 100
        assert _detect_key_type_from_der(fake_der) == "unknown"


# ---------------------------------------------------------------------------
# Self-signed detection tests
# ---------------------------------------------------------------------------

class TestSelfSignedDetection:
    """Tests for self-signed certificate detection logic."""

    def test_self_signed_when_subject_equals_issuer(self):
        """A cert is self-signed when subject == issuer."""
        subject = "commonName=myserver.local"
        issuer = "commonName=myserver.local"
        is_self_signed = (subject == issuer and subject != "")
        assert is_self_signed is True

    def test_not_self_signed_when_different(self):
        subject = "commonName=example.com"
        issuer = "commonName=Let's Encrypt R3"
        is_self_signed = (subject == issuer and subject != "")
        assert is_self_signed is False

    def test_not_self_signed_when_both_empty(self):
        """Empty strings should not count as self-signed."""
        is_self_signed = ("" == "" and "" != "")
        assert is_self_signed is False


# ---------------------------------------------------------------------------
# Expiry calculation tests
# ---------------------------------------------------------------------------

class TestExpiryCalculation:
    """Tests for certificate expiry calculation."""

    def test_future_expiry(self):
        future = datetime.now(timezone.utc) + timedelta(days=90)
        not_after_str = future.strftime("%b %d %H:%M:%S %Y GMT")
        expiry_dt = _parse_cert_date(not_after_str)
        delta = expiry_dt - datetime.now(timezone.utc)
        assert delta.days >= 89  # allow 1 day margin

    def test_past_expiry(self):
        past = datetime.now(timezone.utc) - timedelta(days=30)
        not_after_str = past.strftime("%b %d %H:%M:%S %Y GMT")
        expiry_dt = _parse_cert_date(not_after_str)
        delta = expiry_dt - datetime.now(timezone.utc)
        assert delta.days < 0


# ---------------------------------------------------------------------------
# inspect_cert async tests — mocked socket/ssl
# ---------------------------------------------------------------------------

class TestInspectCert:
    """Tests for inspect_cert() with mocked connections."""

    def _make_mock_ssock(self, cert_dict=None, der_cert=None,
                          cipher_info=None, tls_version=None):
        """Build a mock SSLSocket with configurable returns."""
        ssock = MagicMock()

        if cert_dict is None:
            cert_dict = {
                "subject": ((("commonName", "example.com"),),),
                "issuer": ((("commonName", "Let's Encrypt R3"),),),
                "notBefore": "Jan  1 00:00:00 2026 GMT",
                "notAfter": "Jan  1 00:00:00 2028 GMT",
                "serialNumber": "0A1B2C3D",
                "subjectAltName": (
                    ("DNS", "example.com"),
                    ("DNS", "www.example.com"),
                ),
            }

        if der_cert is None:
            # Fake DER with RSA OID for key detection
            rsa_oid = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"
            der_cert = b"\x00" * 1200 + rsa_oid + b"\x00" * 100

        if cipher_info is None:
            cipher_info = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        if tls_version is None:
            tls_version = "TLSv1.3"

        def getpeercert(binary_form=False):
            if binary_form:
                return der_cert
            return cert_dict

        ssock.getpeercert = getpeercert
        ssock.cipher.return_value = cipher_info
        ssock.version.return_value = tls_version
        ssock.close = MagicMock()

        # No get_verified_chain by default (pre-3.13)
        if hasattr(ssock, "get_verified_chain"):
            delattr(ssock, "get_verified_chain")

        return ssock

    @pytest.mark.asyncio
    async def test_successful_inspection(self):
        mock_ssock = self._make_mock_ssock()
        mock_sock = MagicMock()

        with patch("src.recon.certs.socket.create_connection", return_value=mock_sock):
            with patch("src.recon.certs.ssl.create_default_context") as mock_ctx_cls:
                mock_ctx = MagicMock()
                mock_ctx.wrap_socket.return_value = mock_ssock
                mock_ctx_cls.return_value = mock_ctx

                report = await inspect_cert("example.com")

        assert report.error is None
        assert report.host == "example.com"
        assert report.port == 443
        assert "example.com" in report.subject
        assert report.protocol == "TLSv1.3"
        assert report.cipher == "TLS_AES_256_GCM_SHA384"
        assert len(report.sans) == 2
        assert report.is_self_signed is False

    @pytest.mark.asyncio
    async def test_self_signed_cert(self):
        cert_dict = {
            "subject": ((("commonName", "myserver.local"),),),
            "issuer": ((("commonName", "myserver.local"),),),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Jan  1 00:00:00 2028 GMT",
            "serialNumber": "1234",
            "subjectAltName": (("DNS", "myserver.local"),),
        }
        mock_ssock = self._make_mock_ssock(cert_dict=cert_dict)
        mock_sock = MagicMock()

        with patch("src.recon.certs.socket.create_connection", return_value=mock_sock):
            with patch("src.recon.certs.ssl.create_default_context") as mock_ctx_cls:
                mock_ctx = MagicMock()
                mock_ctx.wrap_socket.return_value = mock_ssock
                mock_ctx_cls.return_value = mock_ctx

                report = await inspect_cert("myserver.local")

        assert report.is_self_signed is True

    @pytest.mark.asyncio
    async def test_connection_refused(self):
        with patch("src.recon.certs.socket.create_connection",
                   side_effect=ConnectionRefusedError("refused")):
            report = await inspect_cert("noserver.example.com", port=8443)

        assert report.error is not None
        assert "Connection refused" in report.error
        assert report.host == "noserver.example.com"
        assert report.port == 8443

    @pytest.mark.asyncio
    async def test_connection_timeout(self):
        with patch("src.recon.certs.socket.create_connection",
                   side_effect=socket.timeout("timed out")):
            report = await inspect_cert("slow.example.com")

        assert report.error is not None
        assert "timed out" in report.error

    @pytest.mark.asyncio
    async def test_os_error(self):
        with patch("src.recon.certs.socket.create_connection",
                   side_effect=OSError("Network unreachable")):
            report = await inspect_cert("unreachable.example.com")

        assert report.error is not None
        assert "Connection error" in report.error

    @pytest.mark.asyncio
    async def test_custom_port(self):
        mock_ssock = self._make_mock_ssock()
        mock_sock = MagicMock()

        with patch("src.recon.certs.socket.create_connection", return_value=mock_sock) as mock_conn:
            with patch("src.recon.certs.ssl.create_default_context") as mock_ctx_cls:
                mock_ctx = MagicMock()
                mock_ctx.wrap_socket.return_value = mock_ssock
                mock_ctx_cls.return_value = mock_ctx

                report = await inspect_cert("example.com", port=8443)

        assert report.port == 8443
        mock_conn.assert_called_once_with(("example.com", 8443), timeout=10)

    @pytest.mark.asyncio
    async def test_fingerprint_computed(self):
        rsa_oid = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"
        der_cert = b"\x00" * 1200 + rsa_oid + b"\x00" * 100
        expected_fp = hashlib.sha256(der_cert).hexdigest()

        mock_ssock = self._make_mock_ssock(der_cert=der_cert)
        mock_sock = MagicMock()

        with patch("src.recon.certs.socket.create_connection", return_value=mock_sock):
            with patch("src.recon.certs.ssl.create_default_context") as mock_ctx_cls:
                mock_ctx = MagicMock()
                mock_ctx.wrap_socket.return_value = mock_ssock
                mock_ctx_cls.return_value = mock_ctx

                report = await inspect_cert("example.com")

        assert report.fingerprint_sha256 == expected_fp

    @pytest.mark.asyncio
    async def test_ssl_error_handling(self):
        mock_sock = MagicMock()

        with patch("src.recon.certs.socket.create_connection", return_value=mock_sock):
            with patch("src.recon.certs.ssl.create_default_context") as mock_ctx_cls:
                mock_ctx = MagicMock()
                mock_ctx.wrap_socket.side_effect = ssl.SSLError("SSL handshake failed")
                mock_ctx_cls.return_value = mock_ctx

                report = await inspect_cert("badsssl.example.com")

        assert report.error is not None
        assert "SSL error" in report.error
