"""TLS certificate inspection module — connect and pull cert details."""

from __future__ import annotations

import asyncio
import hashlib
import socket
import ssl
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class CertReport:
    """Full TLS certificate report for a host:port."""

    host: str
    port: int
    subject: str
    issuer: str
    not_before: str
    not_after: str
    days_until_expiry: int
    sans: list[str]              # Subject Alternative Names
    serial: str
    fingerprint_sha256: str
    protocol: str                # TLS 1.2, TLS 1.3
    cipher: str                  # cipher suite name
    key_type: str                # RSA 2048, EC 256, etc
    is_self_signed: bool
    is_expired: bool
    chain: list[str]             # [leaf CN, intermediate CN, root CN]
    error: str | None = None
    grade: str = ""              # A+ through F
    score: int = 0               # 0-100
    grade_details: dict = field(default_factory=dict)  # per-category scores
    jarm_hash: str = ""          # JARM fingerprint (if computed)
    warnings: list[str] = field(default_factory=list)


def _extract_cn(rdns: tuple) -> str:
    """Extract the Common Name from an RDN sequence tuple."""
    for rdn in rdns:
        for attr in rdn:
            if attr[0] == "commonName":
                return attr[1]
    return ""


def _format_rdn(rdns: tuple) -> str:
    """Format an RDN sequence tuple as a human-readable string."""
    parts: list[str] = []
    for rdn in rdns:
        for attr in rdn:
            parts.append(f"{attr[0]}={attr[1]}")
    return ", ".join(parts)


def _extract_sans(cert_dict: dict) -> list[str]:
    """Extract Subject Alternative Names from parsed cert dict."""
    san_entries = cert_dict.get("subjectAltName", ())
    return [value for _type, value in san_entries]


def _parse_cert_date(date_str: str) -> datetime:
    """Parse certificate date string (e.g. 'Jan  5 00:00:00 2026 GMT')."""
    # OpenSSL date format: 'Mon DD HH:MM:SS YYYY GMT'
    return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def _detect_key_type(cert_dict: dict) -> str:
    """Detect key type and size from certificate dict.

    The parsed cert dict doesn't directly expose key info, so we
    inspect what's available. For full key info we use the DER cert.
    """
    # serialNumber length can hint at key size but isn't reliable
    # Best effort from available data
    return "unknown"


def _detect_key_type_from_der(der_cert: bytes) -> str:
    """Detect key type from DER-encoded certificate bytes.

    Inspects the SubjectPublicKeyInfo OID in the raw DER to determine
    the algorithm. Uses basic ASN.1 pattern matching — no external deps.
    """
    # RSA OID: 1.2.840.113549.1.1.1 → bytes 06 09 2a 86 48 86 f7 0d 01 01 01
    rsa_oid = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"
    # EC OID: 1.2.840.10045.2.1 → bytes 06 07 2a 86 48 ce 3d 02 01
    ec_oid = b"\x06\x07\x2a\x86\x48\xce\x3d\x02\x01"

    if rsa_oid in der_cert:
        # Estimate RSA key size from the cert size (rough heuristic)
        cert_len = len(der_cert)
        if cert_len > 1500:
            return "RSA 4096"
        elif cert_len > 1000:
            return "RSA 2048"
        else:
            return "RSA 1024"
    elif ec_oid in der_cert:
        # Check for common EC curve OIDs
        # P-256: 1.2.840.10045.3.1.7 → 06 08 2a 86 48 ce 3d 03 01 07
        p256_oid = b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"
        # P-384: 1.3.132.0.34 → 06 05 2b 81 04 00 22
        p384_oid = b"\x06\x05\x2b\x81\x04\x00\x22"
        if p256_oid in der_cert:
            return "EC 256"
        elif p384_oid in der_cert:
            return "EC 384"
        return "EC"

    return "unknown"


def _connect_and_inspect(host: str, port: int) -> CertReport:
    """Synchronous TLS connection + cert extraction. Runs via to_thread.
    
    Strategy: Try verified connection first (gets parsed cert dict).
    If verification fails (self-signed, expired), retry with CERT_NONE
    and parse the DER bytes with the cryptography library.
    """
    der_cert = None
    cert_dict = {}
    cipher_info = None
    tls_version = None
    verification_failed = False

    # Attempt 1: Verified connection (gets full parsed cert dict)
    try:
        ctx = ssl.create_default_context()
        sock = socket.create_connection((host, port), timeout=10)
        try:
            ssock = ctx.wrap_socket(sock, server_hostname=host)
            cert_dict = ssock.getpeercert(binary_form=False) or {}
            der_cert = ssock.getpeercert(binary_form=True)
            cipher_info = ssock.cipher()
            tls_version = ssock.version()
            ssock.close()
        except ssl.SSLCertVerificationError:
            verification_failed = True
            sock.close()
        except Exception:
            verification_failed = True
            sock.close()
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return CertReport(
            host=host, port=port, subject="", issuer="", not_before="",
            not_after="", days_until_expiry=0, sans=[], serial="",
            fingerprint_sha256="", protocol="", cipher="", key_type="",
            is_self_signed=False, is_expired=False, chain=[],
            error=f"{type(e).__name__}: {e}",
        )

    # Attempt 2: Unverified connection (for self-signed/expired certs)
    if verification_failed:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = socket.create_connection((host, port), timeout=10)
            ssock = ctx.wrap_socket(sock, server_hostname=host)
            der_cert = ssock.getpeercert(binary_form=True)
            cipher_info = ssock.cipher()
            tls_version = ssock.version()
            ssock.close()
        except Exception as e:
            return CertReport(
                host=host, port=port, subject="", issuer="", not_before="",
                not_after="", days_until_expiry=0, sans=[], serial="",
                fingerprint_sha256="", protocol="", cipher="", key_type="",
                is_self_signed=False, is_expired=False, chain=[],
                error=f"SSL Error: {e}",
            )

    # Parse cert data — from cert_dict if verified, or DER if unverified
    subject_str = ""
    issuer_str = ""
    not_before_str = ""
    not_after_str = ""
    days_until_expiry = 0
    is_expired = False
    sans = []
    serial = ""
    is_self_signed = False
    chain = []

    if cert_dict:
        # We got a parsed dict from verified connection
        subject_rdns = cert_dict.get("subject", ())
        issuer_rdns = cert_dict.get("issuer", ())
        subject_str = _format_rdn(subject_rdns)
        issuer_str = _format_rdn(issuer_rdns)
        not_before_str = cert_dict.get("notBefore", "")
        not_after_str = cert_dict.get("notAfter", "")
        sans = _extract_sans(cert_dict)
        serial = cert_dict.get("serialNumber", "")
        is_self_signed = subject_str == issuer_str and subject_str != ""

        if not_after_str:
            try:
                expiry_dt = _parse_cert_date(not_after_str)
                delta = expiry_dt - datetime.now(timezone.utc)
                days_until_expiry = delta.days
                is_expired = days_until_expiry < 0
            except (ValueError, AttributeError):
                pass

        subject_cn = _extract_cn(subject_rdns)
        issuer_cn = _extract_cn(issuer_rdns)
        if subject_cn:
            chain.append(subject_cn)
        if issuer_cn and issuer_cn != subject_cn:
            chain.append(issuer_cn)

    elif der_cert:
        # Parse DER bytes with cryptography library
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            cert_obj = x509.load_der_x509_certificate(der_cert, default_backend())
            subject_str = cert_obj.subject.rfc4514_string()
            issuer_str = cert_obj.issuer.rfc4514_string()
            not_before_str = cert_obj.not_valid_before_utc.isoformat()
            not_after_str = cert_obj.not_valid_after_utc.isoformat()
            serial = format(cert_obj.serial_number, 'x')
            is_self_signed = subject_str == issuer_str

            delta = cert_obj.not_valid_after_utc - datetime.now(timezone.utc)
            days_until_expiry = delta.days
            is_expired = days_until_expiry < 0

            # SANs
            try:
                san_ext = cert_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                sans = san_ext.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                pass

            # Chain (leaf only for unverified)
            try:
                cn = cert_obj.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                if cn:
                    chain.append(cn[0].value)
                issuer_cn_attrs = cert_obj.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                if issuer_cn_attrs and issuer_cn_attrs[0].value != (cn[0].value if cn else ""):
                    chain.append(issuer_cn_attrs[0].value)
            except Exception:
                pass

        except ImportError:
            # No cryptography library — best effort from DER
            subject_str = "(unverified cert - install cryptography for full parsing)"
            issuer_str = ""

    # Fingerprint
    fingerprint = hashlib.sha256(der_cert).hexdigest() if der_cert else ""

    # Protocol / Cipher
    protocol = tls_version or "unknown"
    cipher_name = cipher_info[0] if cipher_info else "unknown"

    # Key type from DER
    key_type = _detect_key_type_from_der(der_cert) if der_cert else "unknown"

    return CertReport(
        host=host,
        port=port,
        subject=subject_str,
        issuer=issuer_str,
        not_before=not_before_str,
        not_after=not_after_str,
        days_until_expiry=days_until_expiry,
        sans=sans,
        serial=serial,
        fingerprint_sha256=fingerprint,
        protocol=protocol,
        cipher=cipher_name,
        key_type=key_type,
        is_self_signed=is_self_signed,
        is_expired=is_expired,
        chain=chain,
    )


# ---------------------------------------------------------------------------
# Certificate Grading (A+ through F)
# ---------------------------------------------------------------------------

def _score_protocol(protocol: str) -> tuple[int, list[str]]:
    """Score protocol version. Max 30 points."""
    warnings: list[str] = []
    proto = protocol.upper().replace(" ", "")

    if "1.3" in proto or "TLSV1.3" in proto:
        return 30, warnings
    elif "1.2" in proto or "TLSV1.2" in proto:
        return 20, warnings
    elif "1.1" in proto or "TLSV1.1" in proto:
        warnings.append("TLSv1.1 is deprecated (RFC 8996)")
        return 5, warnings
    elif "1.0" in proto or "TLSV1.0" in proto or "TLSV1" == proto:
        warnings.append("TLSv1.0 is deprecated (RFC 8996)")
        return 0, warnings
    elif proto in ("", "UNKNOWN"):
        return 0, warnings
    else:
        # SSLv3 or unrecognized
        return 0, warnings


def _score_key_strength(key_type: str) -> tuple[int, list[str]]:
    """Score key type/size. Max 20 points."""
    warnings: list[str] = []
    kt = key_type.upper()

    if "EC" in kt:
        # EC 256, EC 384, EC 521 are all strong
        return 20, warnings
    elif "RSA" in kt:
        if "4096" in kt:
            return 20, warnings
        elif "2048" in kt:
            return 15, warnings
        elif "1024" in kt:
            warnings.append("Weak RSA key (1024 bits)")
            return 5, warnings
        else:
            # RSA with unknown size, assume weak
            warnings.append("RSA key with unknown size")
            return 10, warnings
    elif kt in ("", "UNKNOWN"):
        warnings.append("Key type unknown")
        return 0, warnings
    else:
        return 10, warnings


def _score_validity(report: CertReport) -> tuple[int, list[str]]:
    """Score certificate validity. Max 20 points."""
    warnings: list[str] = []
    score = 20

    if report.is_expired:
        warnings.append("Certificate is expired")
        return 0, warnings

    if report.is_self_signed:
        warnings.append("Self-signed certificate")
        return 0, warnings

    if 0 < report.days_until_expiry < 30:
        warnings.append(f"Certificate expires within {report.days_until_expiry} days")
        score -= 5

    return score, warnings


def _score_cipher(cipher: str) -> tuple[int, list[str]]:
    """Score cipher suite strength. Max 15 points."""
    warnings: list[str] = []
    c = cipher.upper()

    # Check for weak ciphers first
    weak_patterns = ("3DES", "DES_CBC3", "RC4", "NULL", "EXPORT", "ANON")
    for weak in weak_patterns:
        if weak in c:
            warnings.append(f"Weak cipher detected ({weak})")
            return 0, warnings

    # Strong ciphers
    if "AES_256_GCM" in c or "AES256GCM" in c:
        return 15, warnings
    elif "CHACHA20" in c:
        return 15, warnings
    elif "AES_128_GCM" in c or "AES128GCM" in c:
        return 12, warnings
    elif "AES_256_CBC" in c or "AES256" in c:
        return 10, warnings
    elif "AES_128_CBC" in c or "AES128" in c:
        return 10, warnings
    elif "AES" in c:
        # Generic AES — decent
        return 10, warnings
    elif c in ("", "UNKNOWN"):
        return 0, warnings
    else:
        # Unknown cipher, give partial credit
        return 8, warnings


def _score_chain(chain: list[str]) -> tuple[int, list[str]]:
    """Score chain completeness. Max 15 points."""
    warnings: list[str] = []

    if len(chain) >= 2:
        return 15, warnings
    elif len(chain) == 1:
        warnings.append("Incomplete certificate chain (single cert)")
        return 10, warnings
    else:
        warnings.append("No chain information available")
        return 5, warnings


def _score_to_grade(score: int) -> str:
    """Convert numeric score (0-100) to letter grade."""
    if score >= 95:
        return "A+"
    elif score >= 85:
        return "A"
    elif score >= 70:
        return "B"
    elif score >= 55:
        return "C"
    elif score >= 40:
        return "D"
    else:
        return "F"


def grade_cert(report: CertReport) -> CertReport:
    """Grade a certificate report on a 0-100 scale with A+ through F grading.

    Scoring categories:
    - Protocol (30 pts): TLSv1.3=30, TLSv1.2=20, TLSv1.1=5, TLSv1.0/other=0
    - Key strength (20 pts): EC/RSA4096=20, RSA2048=15, RSA1024=5
    - Certificate validity (20 pts): Valid+not-self-signed=20, penalties for near-expiry
    - Cipher strength (15 pts): AES256GCM/CHACHA20=15, AES128GCM=12, weak=0
    - Chain completeness (15 pts): Full chain=15, single cert=10, none=5

    Returns the report with grade, score, grade_details, and warnings populated.
    """
    all_warnings: list[str] = []

    proto_score, proto_warnings = _score_protocol(report.protocol)
    all_warnings.extend(proto_warnings)

    key_score, key_warnings = _score_key_strength(report.key_type)
    all_warnings.extend(key_warnings)

    validity_score, validity_warnings = _score_validity(report)
    all_warnings.extend(validity_warnings)

    cipher_score, cipher_warnings = _score_cipher(report.cipher)
    all_warnings.extend(cipher_warnings)

    chain_score, chain_warnings = _score_chain(report.chain)
    all_warnings.extend(chain_warnings)

    total_score = proto_score + key_score + validity_score + cipher_score + chain_score
    grade = _score_to_grade(total_score)

    report.score = total_score
    report.grade = grade
    report.grade_details = {
        "protocol": proto_score,
        "key_strength": key_score,
        "validity": validity_score,
        "cipher": cipher_score,
        "chain": chain_score,
    }
    report.warnings = all_warnings

    return report


# ---------------------------------------------------------------------------
# JARM TLS Fingerprinting
# ---------------------------------------------------------------------------

# JARM works by sending specially crafted TLS Client Hello packets and
# fingerprinting the Server Hello responses. This is a simplified 3-probe
# implementation (TLS 1.0, 1.2, 1.3) for server clustering.

def _build_client_hello(
    tls_version: tuple[int, int],
    cipher_suites: list[int],
    host: str,
    extensions: bytes = b"",
) -> bytes:
    """Build a TLS Client Hello handshake packet.

    Args:
        tls_version: (major, minor) e.g. (3, 1) for TLS 1.0
        cipher_suites: list of 2-byte cipher suite IDs
        host: SNI hostname
        extensions: raw extension bytes (or auto-built if empty)

    Returns:
        Complete TLS record bytes ready to send on the wire.
    """
    # Build cipher suites payload
    cs_bytes = b""
    for cs in cipher_suites:
        cs_bytes += struct.pack("!H", cs)
    cs_length = struct.pack("!H", len(cs_bytes))

    # Session ID (empty)
    session_id = b"\x00"

    # Compression methods (null only)
    compression = b"\x01\x00"

    # Build extensions if not provided
    if not extensions:
        extensions = _build_extensions(host, tls_version)

    ext_length = struct.pack("!H", len(extensions))

    # Client Hello body
    client_hello_body = (
        struct.pack("!H", (tls_version[0] << 8) | tls_version[1])  # client version
        + b"\x00" * 32  # random (32 bytes of zeros for fingerprinting consistency)
        + session_id
        + cs_length + cs_bytes
        + compression
        + ext_length + extensions
    )

    # Handshake header (type=1 for ClientHello)
    handshake = b"\x01" + struct.pack("!I", len(client_hello_body))[1:] + client_hello_body

    # TLS record layer (type=22 for handshake)
    # Record version is always TLS 1.0 (0x0301) for compatibility
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake

    return record


def _build_extensions(host: str, tls_version: tuple[int, int]) -> bytes:
    """Build TLS extensions for the Client Hello."""
    extensions = b""

    # SNI extension (type 0x0000)
    host_bytes = host.encode("ascii")
    sni_entry = struct.pack("!BH", 0, len(host_bytes)) + host_bytes  # type=hostname, length, name
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry  # list length + entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
    extensions += sni_ext

    # Supported groups / elliptic curves (type 0x000a)
    groups = struct.pack("!HHH", 0x0017, 0x0018, 0x0019)  # x25519, P-256, P-384
    groups_list = struct.pack("!H", len(groups)) + groups
    groups_ext = struct.pack("!HH", 0x000a, len(groups_list)) + groups_list
    extensions += groups_ext

    # EC point formats (type 0x000b)
    ec_formats = b"\x01\x00"  # 1 format: uncompressed
    ec_ext = struct.pack("!HH", 0x000b, len(ec_formats)) + ec_formats
    extensions += ec_ext

    # Signature algorithms (type 0x000d)
    sig_algs = struct.pack("!HHHH",
        0x0401,  # rsa_pkcs1_sha256
        0x0501,  # rsa_pkcs1_sha384
        0x0601,  # rsa_pkcs1_sha512
        0x0403,  # ecdsa_secp256r1_sha256
    )
    sig_list = struct.pack("!H", len(sig_algs)) + sig_algs
    sig_ext = struct.pack("!HH", 0x000d, len(sig_list)) + sig_list
    extensions += sig_ext

    # ALPN extension (type 0x0010) — advertise h2, http/1.1
    alpn_protos = b"\x02h2\x08http/1.1"
    alpn_list = struct.pack("!H", len(alpn_protos)) + alpn_protos
    alpn_ext = struct.pack("!HH", 0x0010, len(alpn_list)) + alpn_list
    extensions += alpn_ext

    # Supported versions extension (type 0x002b) — TLS 1.3 specific
    if tls_version == (3, 4):  # TLS 1.3
        versions = b"\x03\x03\x04\x03\x03"  # length=3, TLS 1.3 (0x0304), TLS 1.2 (0x0303)
        sv_ext = struct.pack("!HH", 0x002b, len(versions)) + versions
        extensions += sv_ext

        # Key share extension (type 0x0033) — required for TLS 1.3
        # Offer x25519 key share (type 0x001d) with 32 bytes of zeros
        key_share_entry = struct.pack("!HH", 0x001d, 32) + b"\x00" * 32
        key_share_list = struct.pack("!H", len(key_share_entry)) + key_share_entry
        ks_ext = struct.pack("!HH", 0x0033, len(key_share_list)) + key_share_list
        extensions += ks_ext

    return extensions


def _parse_server_hello(data: bytes) -> str:
    """Parse a TLS Server Hello response and extract fingerprint components.

    Returns a string like "TLSVersion|CipherSuite" or "|||" on failure.
    """
    if len(data) < 7:
        return "|||"

    # Check for TLS record (type 22 = handshake)
    if data[0] != 0x16:
        # Could be an alert (0x15) or other response
        if data[0] == 0x15 and len(data) >= 7:
            # TLS Alert — extract alert level and description
            return f"alert|{data[5]:02x}{data[6]:02x}"
        return "|||"

    # Record version
    record_version = f"{data[1]:02x}{data[2]:02x}"

    # Skip record header (5 bytes), check handshake type
    if len(data) < 10:
        return f"{record_version}|||"

    # Handshake type should be 2 (ServerHello)
    if data[5] != 0x02:
        return f"{record_version}|{data[5]:02x}||"

    # Skip handshake header (5+4=9 bytes), read server version
    offset = 9
    if len(data) < offset + 2:
        return f"{record_version}|||"

    server_version = f"{data[offset]:02x}{data[offset+1]:02x}"
    offset += 2

    # Skip random (32 bytes)
    offset += 32
    if len(data) < offset + 1:
        return f"{record_version}|{server_version}||"

    # Skip session ID
    session_id_len = data[offset]
    offset += 1 + session_id_len

    # Read cipher suite (2 bytes)
    if len(data) < offset + 2:
        return f"{record_version}|{server_version}||"

    cipher_suite = f"{data[offset]:02x}{data[offset+1]:02x}"
    offset += 2

    return f"{record_version}|{server_version}|{cipher_suite}"


# JARM probe definitions: (tls_version, cipher_suite_list)
# Probe 1: TLS 1.0 with common ciphers
_JARM_PROBE_TLS10 = (
    (3, 1),  # TLS 1.0
    [
        0x002f,  # TLS_RSA_WITH_AES_128_CBC_SHA
        0x0035,  # TLS_RSA_WITH_AES_256_CBC_SHA
        0x000a,  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
        0xc013,  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        0xc014,  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        0xc009,  # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
        0xc00a,  # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    ],
)

# Probe 2: TLS 1.2 with modern ciphers
_JARM_PROBE_TLS12 = (
    (3, 3),  # TLS 1.2
    [
        0xc02c,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xc02b,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xc030,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xc02f,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xcca9,  # TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        0xcca8,  # TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        0x009e,  # TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        0x009f,  # TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
        0x002f,  # TLS_RSA_WITH_AES_128_CBC_SHA
        0x0035,  # TLS_RSA_WITH_AES_256_CBC_SHA
    ],
)

# Probe 3: TLS 1.3 ciphers (using supported_versions extension)
_JARM_PROBE_TLS13 = (
    (3, 4),  # TLS 1.3 (record says 1.0, but supported_versions says 1.3)
    [
        0x1301,  # TLS_AES_128_GCM_SHA256
        0x1302,  # TLS_AES_256_GCM_SHA384
        0x1303,  # TLS_CHACHA20_POLY1305_SHA256
    ],
)

_JARM_PROBES = [_JARM_PROBE_TLS10, _JARM_PROBE_TLS12, _JARM_PROBE_TLS13]


async def _send_jarm_probe(
    host: str,
    port: int,
    tls_version: tuple[int, int],
    cipher_suites: list[int],
    timeout: float = 4.0,
) -> str:
    """Send a single JARM probe and return the parsed Server Hello fingerprint.

    Returns "|||" (empty fingerprint) on timeout or connection failure.
    """
    try:
        hello = _build_client_hello(tls_version, cipher_suites, host)

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )

        writer.write(hello)
        await writer.drain()

        # Read response (up to 1500 bytes is plenty for ServerHello)
        data = await asyncio.wait_for(reader.read(1500), timeout=timeout)

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        if not data:
            return "|||"

        return _parse_server_hello(data)

    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return "|||"
    except Exception:
        return "|||"


async def jarm_fingerprint(host: str, port: int = 443) -> str:
    """Compute a JARM-style TLS fingerprint for a host.

    Sends 3 TLS Client Hello probes (TLS 1.0, 1.2, 1.3) with varying
    cipher suite lists and hashes the Server Hello responses into a
    single fingerprint string.

    This is a simplified implementation (3 probes vs the standard 10)
    but produces consistent hashes useful for clustering servers with
    identical TLS configurations.

    Args:
        host: Target hostname.
        port: TLS port (default 443).

    Returns:
        62-character hex fingerprint (SHA-256 truncated), or empty string on
        complete failure.
    """
    raw_responses: list[str] = []

    async def _run_all_probes():
        for tls_ver, ciphers in _JARM_PROBES:
            resp = await _send_jarm_probe(host, port, tls_ver, ciphers)
            raw_responses.append(resp)

    try:
        await asyncio.wait_for(_run_all_probes(), timeout=45)
    except (asyncio.TimeoutError, Exception):
        # Fill remaining probes with empty on timeout
        while len(raw_responses) < len(_JARM_PROBES):
            raw_responses.append("|||")

    # If all probes failed, return empty
    if all(r == "|||" for r in raw_responses):
        return ""

    # Concatenate raw responses and hash
    combined = "|".join(raw_responses)
    full_hash = hashlib.sha256(combined.encode()).hexdigest()

    # Return first 62 characters (like official JARM)
    return full_hash[:62]


async def inspect_cert(host: str, port: int = 443) -> CertReport:
    """Connect to host:port, pull TLS cert, parse all fields.

    Args:
        host: Target hostname (e.g. "example.com").
        port: TLS port (default 443).

    Returns:
        CertReport with all certificate details, grade, and warnings.
        Error field set on failure.
    """
    try:
        report = await asyncio.to_thread(_connect_and_inspect, host, port)
    except ConnectionRefusedError:
        return CertReport(
            host=host, port=port, subject="", issuer="",
            not_before="", not_after="", days_until_expiry=0,
            sans=[], serial="", fingerprint_sha256="",
            protocol="", cipher="", key_type="", is_self_signed=False,
            is_expired=False, chain=[], error=f"Connection refused: {host}:{port}",
        )
    except (socket.timeout, TimeoutError):
        return CertReport(
            host=host, port=port, subject="", issuer="",
            not_before="", not_after="", days_until_expiry=0,
            sans=[], serial="", fingerprint_sha256="",
            protocol="", cipher="", key_type="", is_self_signed=False,
            is_expired=False, chain=[], error=f"Connection timed out: {host}:{port}",
        )
    except OSError as e:
        return CertReport(
            host=host, port=port, subject="", issuer="",
            not_before="", not_after="", days_until_expiry=0,
            sans=[], serial="", fingerprint_sha256="",
            protocol="", cipher="", key_type="", is_self_signed=False,
            is_expired=False, chain=[], error=f"Connection error: {e}",
        )

    # Apply grading (always runs, fast, no network)
    if not report.error:
        report = grade_cert(report)

    return report
