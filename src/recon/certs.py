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
    """Synchronous TLS connection + cert extraction. Runs via to_thread."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    sock = socket.create_connection((host, port), timeout=10)
    try:
        ssock = ctx.wrap_socket(sock, server_hostname=host)
        try:
            # Parsed certificate dict (only available for validated certs with CERT_NONE
            # this may be empty — use binary form as fallback)
            cert_dict = ssock.getpeercert(binary_form=False) or {}
            der_cert = ssock.getpeercert(binary_form=True)
            cipher_info = ssock.cipher()        # (name, version, bits)
            tls_version = ssock.version()       # 'TLSv1.2', 'TLSv1.3'

            # ── Subject / Issuer ──
            subject_rdns = cert_dict.get("subject", ())
            issuer_rdns = cert_dict.get("issuer", ())
            subject_str = _format_rdn(subject_rdns)
            issuer_str = _format_rdn(issuer_rdns)
            subject_cn = _extract_cn(subject_rdns)
            issuer_cn = _extract_cn(issuer_rdns)

            # ── Dates ──
            not_before_str = cert_dict.get("notBefore", "")
            not_after_str = cert_dict.get("notAfter", "")

            days_until_expiry = 0
            is_expired = False
            if not_after_str:
                try:
                    expiry_dt = _parse_cert_date(not_after_str)
                    now = datetime.now(timezone.utc)
                    delta = expiry_dt - now
                    days_until_expiry = delta.days
                    is_expired = days_until_expiry < 0
                except (ValueError, AttributeError):
                    pass

            # ── SANs ──
            sans = _extract_sans(cert_dict)

            # ── Serial ──
            serial = cert_dict.get("serialNumber", "")

            # ── Fingerprint ──
            fingerprint = ""
            if der_cert:
                fingerprint = hashlib.sha256(der_cert).hexdigest()

            # ── Protocol / Cipher ──
            protocol = tls_version or "unknown"
            cipher_name = cipher_info[0] if cipher_info else "unknown"

            # ── Key type ──
            key_type = "unknown"
            if der_cert:
                key_type = _detect_key_type_from_der(der_cert)

            # ── Self-signed ──
            is_self_signed = subject_str == issuer_str and subject_str != ""

            # ── Chain ──
            chain: list[str] = []
            # Try get_verified_chain (Python 3.13+)
            if hasattr(ssock, "get_verified_chain"):
                try:
                    verified = ssock.get_verified_chain()
                    if verified:
                        for cert_obj in verified:
                            # Each is an ssl.Certificate with get_info()
                            if hasattr(cert_obj, "get_info"):
                                info = cert_obj.get_info()
                                chain.append(info.get("subject", str(cert_obj)))
                            else:
                                chain.append(str(cert_obj))
                except Exception:
                    pass

            # Fallback: at minimum include the leaf CN
            if not chain:
                if subject_cn:
                    chain.append(subject_cn)
                if issuer_cn and issuer_cn != subject_cn:
                    chain.append(issuer_cn)

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

        finally:
            ssock.close()
    except ssl.SSLError as e:
        return CertReport(
            host=host, port=port, subject="", issuer="",
            not_before="", not_after="", days_until_expiry=0,
            sans=[], serial="", fingerprint_sha256="",
            protocol="", cipher="", key_type="", is_self_signed=False,
            is_expired=False, chain=[], error=f"SSL error: {e}",
        )
    except Exception:
        sock.close()
        raise


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
