"""TLS certificate inspection module — connect and pull cert details."""

from __future__ import annotations

import asyncio
import hashlib
import socket
import ssl
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


async def inspect_cert(host: str, port: int = 443) -> CertReport:
    """Connect to host:port, pull TLS cert, parse all fields.

    Args:
        host: Target hostname (e.g. "example.com").
        port: TLS port (default 443).

    Returns:
        CertReport with all certificate details, or error field set on failure.
    """
    try:
        return await asyncio.to_thread(_connect_and_inspect, host, port)
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
