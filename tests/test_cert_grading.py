"""Tests for TLS certificate grading and JARM fingerprinting."""

from __future__ import annotations

import asyncio
import hashlib
import struct
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ghostmcp.recon.certs import (
    CertReport,
    grade_cert,
    jarm_fingerprint,
    _score_protocol,
    _score_key_strength,
    _score_validity,
    _score_cipher,
    _score_chain,
    _score_to_grade,
    _build_client_hello,
    _build_extensions,
    _parse_server_hello,
    _send_jarm_probe,
    _JARM_PROBES,
)


# ---------------------------------------------------------------------------
# Helper to build CertReport fixtures
# ---------------------------------------------------------------------------

def _make_report(
    protocol: str = "TLSv1.3",
    cipher: str = "TLS_AES_256_GCM_SHA384",
    key_type: str = "EC 256",
    is_self_signed: bool = False,
    is_expired: bool = False,
    days_until_expiry: int = 365,
    chain: list[str] | None = None,
) -> CertReport:
    """Build a CertReport with configurable fields for grading tests."""
    if chain is None:
        chain = ["example.com", "R3", "ISRG Root X1"]
    return CertReport(
        host="example.com",
        port=443,
        subject="CN=example.com",
        issuer="CN=Let's Encrypt R3",
        not_before="Jan  1 00:00:00 2026 GMT",
        not_after="Jan  1 00:00:00 2027 GMT",
        days_until_expiry=days_until_expiry,
        sans=["example.com", "www.example.com"],
        serial="0A1B2C3D",
        fingerprint_sha256="abcd" * 16,
        protocol=protocol,
        cipher=cipher,
        key_type=key_type,
        is_self_signed=is_self_signed,
        is_expired=is_expired,
        chain=chain,
    )


# ===========================================================================
# TestCertGrading — grade calculation for various cert configs
# ===========================================================================

class TestCertGrading:
    """Test grade_cert() scoring and grade assignment."""

    def test_perfect_score_a_plus(self):
        """TLS 1.3 + EC key + valid cert + AES-256-GCM + full chain = A+."""
        report = _make_report(
            protocol="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            key_type="EC 256",
            chain=["leaf.com", "intermediate", "root"],
        )
        graded = grade_cert(report)
        assert graded.score == 100
        assert graded.grade == "A+"
        assert graded.grade_details["protocol"] == 30
        assert graded.grade_details["key_strength"] == 20
        assert graded.grade_details["validity"] == 20
        assert graded.grade_details["cipher"] == 15
        assert graded.grade_details["chain"] == 15

    def test_tls12_rsa2048_gets_a(self):
        """TLS 1.2 + RSA 2048 + valid + AES-256-GCM + full chain = 85 (A)."""
        report = _make_report(
            protocol="TLSv1.2",
            cipher="TLS_AES_256_GCM_SHA384",
            key_type="RSA 2048",
            chain=["leaf.com", "intermediate"],
        )
        graded = grade_cert(report)
        # 20 + 15 + 20 + 15 + 15 = 85
        assert graded.score == 85
        assert graded.grade == "A"

    def test_tls12_rsa4096_chacha20_a(self):
        """TLS 1.2 + RSA 4096 + CHACHA20 + full chain = 90 (A)."""
        report = _make_report(
            protocol="TLSv1.2",
            cipher="TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            key_type="RSA 4096",
            chain=["leaf", "inter"],
        )
        graded = grade_cert(report)
        # 20 + 20 + 20 + 15 + 15 = 90
        assert graded.score == 90
        assert graded.grade == "A"

    def test_tls13_ec384_aes128gcm_gets_a(self):
        """TLS 1.3 + EC 384 + AES-128-GCM + full chain = 97 (A+)."""
        report = _make_report(
            protocol="TLSv1.3",
            cipher="TLS_AES_128_GCM_SHA256",
            key_type="EC 384",
            chain=["leaf", "inter", "root"],
        )
        graded = grade_cert(report)
        # 30 + 20 + 20 + 12 + 15 = 97
        assert graded.score == 97
        assert graded.grade == "A+"

    def test_tls10_weak_key_gets_f(self):
        """TLS 1.0 + RSA 1024 + weak cipher = F."""
        report = _make_report(
            protocol="TLSv1.0",
            cipher="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            key_type="RSA 1024",
            chain=["leaf"],
        )
        graded = grade_cert(report)
        # 0 + 5 + 20 + 0 + 10 = 35
        assert graded.score == 35
        assert graded.grade == "F"

    def test_expired_cert_penalty(self):
        """Expired cert zeroes the validity score."""
        report = _make_report(
            protocol="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            key_type="EC 256",
            is_expired=True,
            days_until_expiry=-30,
            chain=["leaf", "inter", "root"],
        )
        graded = grade_cert(report)
        # 30 + 20 + 0 + 15 + 15 = 80
        assert graded.score == 80
        assert graded.grade == "B"
        assert graded.grade_details["validity"] == 0

    def test_self_signed_penalty(self):
        """Self-signed cert zeroes validity score."""
        report = _make_report(
            protocol="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            key_type="EC 256",
            is_self_signed=True,
            chain=["leaf", "inter"],
        )
        graded = grade_cert(report)
        # 30 + 20 + 0 + 15 + 15 = 80
        assert graded.score == 80
        assert graded.grade == "B"

    def test_near_expiry_deduction(self):
        """Cert expiring in <30 days loses 5 points from validity."""
        report = _make_report(
            protocol="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            key_type="EC 256",
            days_until_expiry=15,
            chain=["leaf", "inter", "root"],
        )
        graded = grade_cert(report)
        # 30 + 20 + 15 + 15 + 15 = 95
        assert graded.grade_details["validity"] == 15
        assert graded.score == 95
        assert graded.grade == "A+"

    def test_single_cert_chain(self):
        """Single cert in chain gets 10/15."""
        report = _make_report(
            protocol="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            key_type="EC 256",
            chain=["leaf_only"],
        )
        graded = grade_cert(report)
        assert graded.grade_details["chain"] == 10
        # 30 + 20 + 20 + 15 + 10 = 95
        assert graded.score == 95

    def test_empty_chain(self):
        """Empty chain gets 5/15."""
        report = _make_report(
            protocol="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            key_type="EC 256",
            chain=[],
        )
        graded = grade_cert(report)
        assert graded.grade_details["chain"] == 5
        # 30 + 20 + 20 + 15 + 5 = 90
        assert graded.score == 90

    def test_tls11_gets_d_range(self):
        """TLS 1.1 with moderate config gets D range."""
        report = _make_report(
            protocol="TLSv1.1",
            cipher="TLS_RSA_WITH_AES_128_CBC_SHA",
            key_type="RSA 1024",
            chain=["leaf"],
        )
        graded = grade_cert(report)
        # 5 + 5 + 20 + 10 + 10 = 50
        assert graded.score == 50
        assert graded.grade == "D"

    def test_null_cipher_gives_zero(self):
        """NULL cipher gives 0 points."""
        report = _make_report(
            protocol="TLSv1.2",
            cipher="TLS_RSA_WITH_NULL_SHA256",
            key_type="RSA 2048",
            chain=["leaf", "inter"],
        )
        graded = grade_cert(report)
        assert graded.grade_details["cipher"] == 0

    def test_rc4_cipher_gives_zero(self):
        """RC4 cipher gives 0 points."""
        report = _make_report(
            protocol="TLSv1.2",
            cipher="TLS_RSA_WITH_RC4_128_SHA",
            key_type="RSA 2048",
            chain=["leaf", "inter"],
        )
        graded = grade_cert(report)
        assert graded.grade_details["cipher"] == 0

    def test_grade_preserves_existing_fields(self):
        """Grading doesn't clobber existing CertReport fields."""
        report = _make_report()
        graded = grade_cert(report)
        assert graded.host == "example.com"
        assert graded.port == 443
        assert graded.subject == "CN=example.com"
        assert graded.protocol == "TLSv1.3"
        assert len(graded.sans) == 2


# ===========================================================================
# TestScoreFunctions — individual scoring functions
# ===========================================================================

class TestScoreFunctions:
    """Test individual scoring helper functions."""

    # Protocol scoring
    def test_score_protocol_tls13(self):
        score, warnings = _score_protocol("TLSv1.3")
        assert score == 30
        assert warnings == []

    def test_score_protocol_tls12(self):
        score, warnings = _score_protocol("TLSv1.2")
        assert score == 20
        assert warnings == []

    def test_score_protocol_tls11(self):
        score, warnings = _score_protocol("TLSv1.1")
        assert score == 5
        assert len(warnings) == 1
        assert "deprecated" in warnings[0]

    def test_score_protocol_tls10(self):
        score, warnings = _score_protocol("TLSv1.0")
        assert score == 0
        assert len(warnings) == 1

    def test_score_protocol_unknown(self):
        score, warnings = _score_protocol("unknown")
        assert score == 0

    def test_score_protocol_empty(self):
        score, warnings = _score_protocol("")
        assert score == 0

    # Key strength scoring
    def test_score_key_ec256(self):
        score, warnings = _score_key_strength("EC 256")
        assert score == 20
        assert warnings == []

    def test_score_key_ec384(self):
        score, _ = _score_key_strength("EC 384")
        assert score == 20

    def test_score_key_rsa4096(self):
        score, _ = _score_key_strength("RSA 4096")
        assert score == 20

    def test_score_key_rsa2048(self):
        score, _ = _score_key_strength("RSA 2048")
        assert score == 15

    def test_score_key_rsa1024(self):
        score, warnings = _score_key_strength("RSA 1024")
        assert score == 5
        assert any("Weak" in w for w in warnings)

    def test_score_key_unknown(self):
        score, warnings = _score_key_strength("unknown")
        assert score == 0
        assert any("unknown" in w.lower() for w in warnings)

    # Validity scoring
    def test_score_validity_valid(self):
        report = _make_report(days_until_expiry=365)
        score, warnings = _score_validity(report)
        assert score == 20
        assert warnings == []

    def test_score_validity_expired(self):
        report = _make_report(is_expired=True, days_until_expiry=-10)
        score, warnings = _score_validity(report)
        assert score == 0
        assert any("expired" in w.lower() for w in warnings)

    def test_score_validity_self_signed(self):
        report = _make_report(is_self_signed=True)
        score, warnings = _score_validity(report)
        assert score == 0
        assert any("self-signed" in w.lower() for w in warnings)

    def test_score_validity_near_expiry(self):
        report = _make_report(days_until_expiry=20)
        score, warnings = _score_validity(report)
        assert score == 15  # 20 - 5
        assert any("expires within" in w.lower() for w in warnings)

    # Cipher scoring
    def test_score_cipher_aes256gcm(self):
        score, _ = _score_cipher("TLS_AES_256_GCM_SHA384")
        assert score == 15

    def test_score_cipher_chacha20(self):
        score, _ = _score_cipher("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256")
        assert score == 15

    def test_score_cipher_aes128gcm(self):
        score, _ = _score_cipher("TLS_AES_128_GCM_SHA256")
        assert score == 12

    def test_score_cipher_aes256cbc(self):
        score, _ = _score_cipher("TLS_RSA_WITH_AES_256_CBC_SHA")
        assert score == 10

    def test_score_cipher_3des(self):
        score, warnings = _score_cipher("TLS_RSA_WITH_3DES_EDE_CBC_SHA")
        assert score == 0
        assert any("3DES" in w for w in warnings)

    def test_score_cipher_rc4(self):
        score, warnings = _score_cipher("TLS_RSA_WITH_RC4_128_SHA")
        assert score == 0
        assert any("RC4" in w for w in warnings)

    def test_score_cipher_null(self):
        score, warnings = _score_cipher("TLS_RSA_WITH_NULL_SHA")
        assert score == 0
        assert any("NULL" in w for w in warnings)

    def test_score_cipher_export(self):
        score, warnings = _score_cipher("TLS_RSA_EXPORT_WITH_RC4_40_MD5")
        assert score == 0
        # Should match either EXPORT or RC4
        assert len(warnings) > 0

    def test_score_cipher_unknown(self):
        score, _ = _score_cipher("unknown")
        assert score == 0

    # Chain scoring
    def test_score_chain_full(self):
        score, _ = _score_chain(["leaf", "inter", "root"])
        assert score == 15

    def test_score_chain_two(self):
        score, _ = _score_chain(["leaf", "inter"])
        assert score == 15

    def test_score_chain_single(self):
        score, warnings = _score_chain(["leaf"])
        assert score == 10
        assert any("Incomplete" in w for w in warnings)

    def test_score_chain_empty(self):
        score, warnings = _score_chain([])
        assert score == 5
        assert any("No chain" in w for w in warnings)

    # Grade mapping
    def test_grade_mapping_a_plus(self):
        assert _score_to_grade(100) == "A+"
        assert _score_to_grade(95) == "A+"

    def test_grade_mapping_a(self):
        assert _score_to_grade(94) == "A"
        assert _score_to_grade(85) == "A"

    def test_grade_mapping_b(self):
        assert _score_to_grade(84) == "B"
        assert _score_to_grade(70) == "B"

    def test_grade_mapping_c(self):
        assert _score_to_grade(69) == "C"
        assert _score_to_grade(55) == "C"

    def test_grade_mapping_d(self):
        assert _score_to_grade(54) == "D"
        assert _score_to_grade(40) == "D"

    def test_grade_mapping_f(self):
        assert _score_to_grade(39) == "F"
        assert _score_to_grade(0) == "F"


# ===========================================================================
# TestGradeWarnings — warning generation for each condition
# ===========================================================================

class TestGradeWarnings:
    """Test that warnings are generated correctly for each condition."""

    def test_no_warnings_for_perfect_cert(self):
        """Perfect cert should have no warnings."""
        report = _make_report(
            protocol="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            key_type="EC 256",
            chain=["leaf", "inter", "root"],
        )
        graded = grade_cert(report)
        assert graded.warnings == []

    def test_warning_tls10_deprecated(self):
        """TLS 1.0 generates deprecation warning."""
        report = _make_report(protocol="TLSv1.0")
        graded = grade_cert(report)
        assert any("TLSv1.0" in w or "deprecated" in w for w in graded.warnings)

    def test_warning_tls11_deprecated(self):
        """TLS 1.1 generates deprecation warning."""
        report = _make_report(protocol="TLSv1.1")
        graded = grade_cert(report)
        assert any("TLSv1.1" in w or "deprecated" in w for w in graded.warnings)

    def test_warning_self_signed(self):
        """Self-signed cert generates warning."""
        report = _make_report(is_self_signed=True)
        graded = grade_cert(report)
        assert any("elf-signed" in w for w in graded.warnings)

    def test_warning_expired(self):
        """Expired cert generates warning."""
        report = _make_report(is_expired=True, days_until_expiry=-5)
        graded = grade_cert(report)
        assert any("expired" in w.lower() for w in graded.warnings)

    def test_warning_near_expiry(self):
        """Cert expiring within 30 days generates warning."""
        report = _make_report(days_until_expiry=7)
        graded = grade_cert(report)
        assert any("expires within" in w.lower() for w in graded.warnings)

    def test_warning_weak_key_rsa1024(self):
        """RSA 1024 generates weak key warning."""
        report = _make_report(key_type="RSA 1024")
        graded = grade_cert(report)
        assert any("Weak" in w and "1024" in w for w in graded.warnings)

    def test_warning_key_unknown(self):
        """Unknown key type generates warning."""
        report = _make_report(key_type="unknown")
        graded = grade_cert(report)
        assert any("unknown" in w.lower() for w in graded.warnings)

    def test_warning_weak_cipher_3des(self):
        """3DES cipher generates weak cipher warning."""
        report = _make_report(cipher="TLS_RSA_WITH_3DES_EDE_CBC_SHA")
        graded = grade_cert(report)
        assert any("3DES" in w for w in graded.warnings)

    def test_warning_weak_cipher_rc4(self):
        """RC4 cipher generates weak cipher warning."""
        report = _make_report(cipher="TLS_RSA_WITH_RC4_128_SHA")
        graded = grade_cert(report)
        assert any("RC4" in w for w in graded.warnings)

    def test_warning_weak_cipher_null(self):
        """NULL cipher generates weak cipher warning."""
        report = _make_report(cipher="TLS_RSA_WITH_NULL_SHA256")
        graded = grade_cert(report)
        assert any("NULL" in w for w in graded.warnings)

    def test_warning_incomplete_chain(self):
        """Single cert chain generates incomplete chain warning."""
        report = _make_report(chain=["leaf_only"])
        graded = grade_cert(report)
        assert any("Incomplete" in w or "single" in w.lower() for w in graded.warnings)

    def test_warning_no_chain_info(self):
        """Empty chain generates no chain info warning."""
        report = _make_report(chain=[])
        graded = grade_cert(report)
        assert any("No chain" in w for w in graded.warnings)

    def test_multiple_warnings_accumulate(self):
        """Multiple issues accumulate all warnings."""
        report = _make_report(
            protocol="TLSv1.0",
            cipher="TLS_RSA_WITH_RC4_128_SHA",
            key_type="RSA 1024",
            is_self_signed=True,
            chain=["leaf"],
        )
        graded = grade_cert(report)
        # Should have at least: deprecated TLS, weak cipher, weak key, self-signed, incomplete chain
        assert len(graded.warnings) >= 4


# ===========================================================================
# TestJARMFingerprint — async tests with mocked sockets
# ===========================================================================

class TestJARMFingerprint:
    """Test JARM fingerprinting functions."""

    def test_build_client_hello_structure(self):
        """Client Hello should be a valid TLS record."""
        hello = _build_client_hello(
            tls_version=(3, 3),
            cipher_suites=[0xc02f, 0xc030],
            host="example.com",
        )
        # Must start with TLS record header: type=22, version=0x0301
        assert hello[0] == 0x16  # Handshake
        assert hello[1] == 0x03  # TLS major version
        assert hello[2] == 0x01  # TLS minor version (record always 1.0)
        # Record length (2 bytes) at offset 3-4
        record_len = struct.unpack("!H", hello[3:5])[0]
        assert record_len == len(hello) - 5
        # Handshake type at offset 5 should be 1 (ClientHello)
        assert hello[5] == 0x01

    def test_build_client_hello_tls13_extensions(self):
        """TLS 1.3 Client Hello should include supported_versions and key_share."""
        hello = _build_client_hello(
            tls_version=(3, 4),
            cipher_suites=[0x1301, 0x1302],
            host="example.com",
        )
        # Should contain supported_versions extension (type 0x002b)
        assert b"\x00\x2b" in hello
        # Should contain key_share extension (type 0x0033)
        assert b"\x00\x33" in hello

    def test_build_client_hello_contains_sni(self):
        """Client Hello should contain the SNI hostname."""
        hello = _build_client_hello(
            tls_version=(3, 3),
            cipher_suites=[0xc02f],
            host="test.example.com",
        )
        assert b"test.example.com" in hello

    def test_build_extensions_includes_sni(self):
        """Extensions builder includes SNI."""
        exts = _build_extensions("myhost.com", (3, 3))
        assert b"myhost.com" in exts

    def test_build_extensions_tls13_includes_key_share(self):
        """TLS 1.3 extensions include key_share."""
        exts = _build_extensions("myhost.com", (3, 4))
        # key_share extension type 0x0033
        assert b"\x00\x33" in exts

    def test_parse_server_hello_valid(self):
        """Parse a valid ServerHello response."""
        # Build a minimal ServerHello:
        # Record: type=22, version=0x0303, length=...
        # Handshake: type=2, length=...
        # ServerHello: version=0x0303, random(32), session_id_len=0, cipher=c02f, compression=0
        server_hello_body = (
            b"\x03\x03"              # server version TLS 1.2
            + b"\x00" * 32           # random
            + b"\x00"                # session ID length = 0
            + b"\xc0\x2f"            # cipher suite
            + b"\x00"                # compression method
        )
        handshake = b"\x02" + struct.pack("!I", len(server_hello_body))[1:] + server_hello_body
        record = b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake

        result = _parse_server_hello(record)
        assert "0303" in result  # server version
        assert "c02f" in result  # cipher suite

    def test_parse_server_hello_alert(self):
        """Parse a TLS Alert response."""
        # Alert: type=21, version=0x0303, length=2, level=2, desc=0x28
        alert = b"\x15\x03\x03\x00\x02\x02\x28"
        result = _parse_server_hello(alert)
        assert "alert" in result
        assert "0228" in result

    def test_parse_server_hello_too_short(self):
        """Short data returns empty fingerprint."""
        result = _parse_server_hello(b"\x16\x03")
        assert result == "|||"

    def test_parse_server_hello_empty(self):
        """Empty data returns empty fingerprint."""
        result = _parse_server_hello(b"")
        assert result == "|||"

    def test_parse_server_hello_non_handshake(self):
        """Non-handshake record returns partial fingerprint."""
        # Application data record (type 0x17)
        data = b"\x17\x03\x03\x00\x05hello"
        result = _parse_server_hello(data)
        assert "|||" in result

    @pytest.mark.asyncio
    async def test_send_jarm_probe_success(self):
        """Successful probe returns parsed server hello."""
        # Build a mock ServerHello response
        server_hello_body = (
            b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\xc0\x2f" + b"\x00"
        )
        handshake = b"\x02" + struct.pack("!I", len(server_hello_body))[1:] + server_hello_body
        response = b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake

        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=response)

        mock_writer = AsyncMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("src.recon.certs.asyncio.open_connection",
                   return_value=(mock_reader, mock_writer)):
            result = await _send_jarm_probe(
                "example.com", 443, (3, 3), [0xc02f, 0xc030]
            )

        assert result != "|||"
        assert "c02f" in result
        mock_writer.write.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_jarm_probe_timeout(self):
        """Timeout returns empty fingerprint."""
        with patch("src.recon.certs.asyncio.open_connection",
                   side_effect=asyncio.TimeoutError()):
            result = await _send_jarm_probe(
                "slow.example.com", 443, (3, 3), [0xc02f]
            )
        assert result == "|||"

    @pytest.mark.asyncio
    async def test_send_jarm_probe_connection_refused(self):
        """Connection refused returns empty fingerprint."""
        with patch("src.recon.certs.asyncio.open_connection",
                   side_effect=ConnectionRefusedError()):
            result = await _send_jarm_probe(
                "down.example.com", 443, (3, 3), [0xc02f]
            )
        assert result == "|||"

    @pytest.mark.asyncio
    async def test_send_jarm_probe_empty_response(self):
        """Empty response returns empty fingerprint."""
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"")

        mock_writer = AsyncMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("src.recon.certs.asyncio.open_connection",
                   return_value=(mock_reader, mock_writer)):
            result = await _send_jarm_probe(
                "example.com", 443, (3, 3), [0xc02f]
            )
        assert result == "|||"

    @pytest.mark.asyncio
    async def test_jarm_fingerprint_all_probes_succeed(self):
        """Successful JARM produces a 62-char hex hash."""
        server_hello_body = (
            b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\xc0\x2f" + b"\x00"
        )
        handshake = b"\x02" + struct.pack("!I", len(server_hello_body))[1:] + server_hello_body
        response = b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake

        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=response)

        mock_writer = AsyncMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("src.recon.certs.asyncio.open_connection",
                   return_value=(mock_reader, mock_writer)):
            result = await jarm_fingerprint("example.com", 443)

        assert len(result) == 62
        # Should be valid hex
        int(result, 16)

    @pytest.mark.asyncio
    async def test_jarm_fingerprint_all_probes_fail(self):
        """All probes failing returns empty string."""
        with patch("src.recon.certs.asyncio.open_connection",
                   side_effect=ConnectionRefusedError()):
            result = await jarm_fingerprint("down.example.com", 443)
        assert result == ""

    @pytest.mark.asyncio
    async def test_jarm_fingerprint_partial_failure(self):
        """Some probes failing still produces a hash."""
        call_count = 0

        async def mock_open_connection(host, port):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First probe succeeds
                server_hello_body = (
                    b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\xc0\x2f" + b"\x00"
                )
                handshake = (
                    b"\x02" + struct.pack("!I", len(server_hello_body))[1:]
                    + server_hello_body
                )
                response = (
                    b"\x16\x03\x03"
                    + struct.pack("!H", len(handshake))
                    + handshake
                )

                reader = AsyncMock()
                reader.read = AsyncMock(return_value=response)
                writer = AsyncMock()
                writer.write = MagicMock()
                writer.drain = AsyncMock()
                writer.close = MagicMock()
                writer.wait_closed = AsyncMock()
                return reader, writer
            else:
                raise ConnectionRefusedError()

        with patch("src.recon.certs.asyncio.open_connection",
                   side_effect=mock_open_connection):
            result = await jarm_fingerprint("partial.example.com", 443)

        # Should still produce a hash (not all "|||")
        assert len(result) == 62

    @pytest.mark.asyncio
    async def test_jarm_fingerprint_deterministic(self):
        """Same server responses produce the same JARM hash."""
        server_hello_body = (
            b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\xc0\x2f" + b"\x00"
        )
        handshake = b"\x02" + struct.pack("!I", len(server_hello_body))[1:] + server_hello_body
        response = b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake

        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=response)

        mock_writer = AsyncMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("src.recon.certs.asyncio.open_connection",
                   return_value=(mock_reader, mock_writer)):
            result1 = await jarm_fingerprint("example.com", 443)

        mock_reader2 = AsyncMock()
        mock_reader2.read = AsyncMock(return_value=response)

        mock_writer2 = AsyncMock()
        mock_writer2.write = MagicMock()
        mock_writer2.drain = AsyncMock()
        mock_writer2.close = MagicMock()
        mock_writer2.wait_closed = AsyncMock()

        with patch("src.recon.certs.asyncio.open_connection",
                   return_value=(mock_reader2, mock_writer2)):
            result2 = await jarm_fingerprint("example.com", 443)

        assert result1 == result2

    @pytest.mark.asyncio
    async def test_jarm_probes_definition(self):
        """Verify JARM probe definitions are structured correctly."""
        assert len(_JARM_PROBES) == 3

        for tls_ver, ciphers in _JARM_PROBES:
            assert isinstance(tls_ver, tuple)
            assert len(tls_ver) == 2
            assert isinstance(ciphers, list)
            assert len(ciphers) > 0
            for cs in ciphers:
                assert 0 <= cs <= 0xFFFF

    def test_jarm_probe_tls_versions(self):
        """Probes cover TLS 1.0, 1.2, and 1.3."""
        versions = [probe[0] for probe in _JARM_PROBES]
        assert (3, 1) in versions  # TLS 1.0
        assert (3, 3) in versions  # TLS 1.2
        assert (3, 4) in versions  # TLS 1.3


# ===========================================================================
# TestIntegration — end-to-end grading via inspect_cert
# ===========================================================================

class TestIntegrationGrading:
    """Test that inspect_cert automatically runs grading."""

    @pytest.mark.asyncio
    async def test_inspect_cert_includes_grade(self):
        """inspect_cert should auto-grade the certificate."""
        from unittest.mock import patch, MagicMock

        # Build mock socket
        cert_dict = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "Let's Encrypt R3"),),),
            "notBefore": "Jan  1 00:00:00 2026 GMT",
            "notAfter": "Jan  1 00:00:00 2028 GMT",
            "serialNumber": "0A1B2C3D",
            "subjectAltName": (("DNS", "example.com"),),
        }
        rsa_oid = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"
        der_cert = b"\x00" * 1200 + rsa_oid + b"\x00" * 100

        ssock = MagicMock()
        ssock.getpeercert = lambda binary_form=False: der_cert if binary_form else cert_dict
        ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        ssock.version.return_value = "TLSv1.3"
        ssock.close = MagicMock()

        mock_sock = MagicMock()

        with patch("src.recon.certs.socket.create_connection", return_value=mock_sock):
            with patch("src.recon.certs.ssl.create_default_context") as mock_ctx_cls:
                mock_ctx = MagicMock()
                mock_ctx.wrap_socket.return_value = ssock
                mock_ctx_cls.return_value = mock_ctx

                from ghostmcp.recon.certs import inspect_cert
                report = await inspect_cert("example.com")

        # Should have grade populated
        assert report.grade != ""
        assert report.score > 0
        assert report.grade_details != {}
        assert report.error is None

    @pytest.mark.asyncio
    async def test_inspect_cert_error_skips_grading(self):
        """inspect_cert with connection error should skip grading."""
        from ghostmcp.recon.certs import inspect_cert

        with patch("src.recon.certs.socket.create_connection",
                   side_effect=ConnectionRefusedError("refused")):
            report = await inspect_cert("bad.example.com")

        assert report.error is not None
        assert report.grade == ""
        assert report.score == 0
