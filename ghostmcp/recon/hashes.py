"""Hash intelligence module — identify unknown files via threat intel APIs."""

from __future__ import annotations

import asyncio
import hashlib
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx

TIMEOUT = 5.0
VT_RATE_LIMIT = 4  # requests per minute


@dataclass
class HashReport:
    hash_value: str
    hash_type: str  # md5, sha1, sha256, sha512
    circl: dict | None = None  # {known: bool, filename: str, source: str}
    malwarebazaar: dict | None = None  # {family: str, tags: list, first_seen: str, file_type: str}
    threatfox: dict | None = None  # {malware: str, c2: list, campaign: str}
    virustotal: dict | None = None  # {detections: int, total: int, name: str}
    errors: dict = field(default_factory=dict)  # service -> error message
    verdict: str = "unknown"


def detect_hash_type(h: str) -> str | None:
    """Detect hash algorithm from hex string length."""
    h = h.strip().lower()
    length_map = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
    if all(c in "0123456789abcdef" for c in h):
        return length_map.get(len(h))
    return None


def compute_file_hashes(filepath: str) -> dict[str, str]:
    """Compute MD5, SHA1, SHA256 for a local file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def _determine_verdict(report: HashReport) -> str:
    """Apply verdict logic based on service results."""
    has_bazaar = report.malwarebazaar is not None
    has_threatfox = report.threatfox is not None
    has_vt = report.virustotal is not None

    # Malware confirmed by abuse.ch services
    if has_bazaar or has_threatfox:
        return "malicious"

    # VT detections
    if has_vt:
        detections = report.virustotal.get("detections", 0)
        if detections > 10:
            return "malicious"
        if detections >= 1:
            return "suspicious"

    # CIRCL known (NSRL = National Software Reference Library)
    if report.circl and report.circl.get("known"):
        return "clean"

    return "unknown"


class HashLookup:
    """Async hash intelligence lookup against multiple free TI services."""

    def __init__(self) -> None:
        self._vt_key: str | None = os.environ.get("VT_API_KEY")
        self._vt_timestamps: list[float] = []

    async def lookup(self, hash_value: str) -> HashReport:
        """Query all available services for a given hash."""
        hash_value = hash_value.strip().lower()
        hash_type = detect_hash_type(hash_value)
        if not hash_type:
            raise ValueError(f"Cannot detect hash type for: {hash_value!r}")

        report = HashReport(hash_value=hash_value, hash_type=hash_type)

        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            tasks = [
                self._query_circl(client, hash_value, hash_type, report),
                self._query_malwarebazaar(client, hash_value, report),
                self._query_threatfox(client, hash_value, report),
            ]
            if self._vt_key:
                tasks.append(self._query_virustotal(client, hash_value, report))

            await asyncio.gather(*tasks)

        report.verdict = _determine_verdict(report)
        return report

    async def lookup_file(self, filepath: str) -> HashReport:
        """Compute file hashes and look up via SHA256."""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        hashes = await asyncio.to_thread(compute_file_hashes, filepath)
        report = await self.lookup(hashes["sha256"])
        return report

    # ── Service queries ──────────────────────────────────────────────

    async def _query_circl(
        self, client: httpx.AsyncClient, h: str, hash_type: str, report: HashReport
    ) -> None:
        """CIRCL hashlookup — NSRL and known software database."""
        # CIRCL supports md5, sha1, sha256
        if hash_type not in ("md5", "sha1", "sha256"):
            return
        url = f"https://hashlookup.circl.lu/lookup/{hash_type}/{h}"
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                report.circl = {
                    "known": True,
                    "filename": data.get("FileName", ""),
                    "source": data.get("source", "NSRL"),
                }
            elif resp.status_code == 404:
                report.circl = {"known": False, "filename": "", "source": ""}
            else:
                report.errors["circl"] = f"HTTP {resp.status_code}"
        except (httpx.TimeoutException, httpx.ConnectError) as e:
            report.errors["circl"] = str(e)

    async def _query_malwarebazaar(
        self, client: httpx.AsyncClient, h: str, report: HashReport
    ) -> None:
        """MalwareBazaar — malware sample database by abuse.ch."""
        url = "https://mb-api.abuse.ch/api/v1/"
        try:
            resp = await client.post(url, data={"query": "get_info", "hash": h})
            if resp.status_code == 200:
                data = resp.json()
                if data.get("query_status") == "hash_not_found":
                    return  # Not in database — leave as None
                if data.get("query_status") == "ok" and data.get("data"):
                    entry = data["data"][0]
                    report.malwarebazaar = {
                        "family": entry.get("signature", "unknown"),
                        "tags": entry.get("tags") or [],
                        "first_seen": entry.get("first_seen", ""),
                        "file_type": entry.get("file_type", ""),
                    }
            else:
                report.errors["malwarebazaar"] = f"HTTP {resp.status_code}"
        except (httpx.TimeoutException, httpx.ConnectError) as e:
            report.errors["malwarebazaar"] = str(e)

    async def _query_threatfox(
        self, client: httpx.AsyncClient, h: str, report: HashReport
    ) -> None:
        """ThreatFox — IOC database by abuse.ch."""
        url = "https://threatfox-api.abuse.ch/api/v1/"
        payload = {"query": "search_hash", "hash": h}
        try:
            resp = await client.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("query_status") == "no_result":
                    return
                if data.get("query_status") == "ok" and data.get("data"):
                    entries = data["data"]
                    c2_list = []
                    malware = ""
                    campaign = ""
                    for entry in entries:
                        if entry.get("ioc"):
                            c2_list.append(entry["ioc"])
                        if not malware:
                            malware = entry.get("malware_printable", "")
                        if not campaign:
                            campaign = entry.get("tags", [""])[0] if entry.get("tags") else ""
                    report.threatfox = {
                        "malware": malware,
                        "c2": c2_list,
                        "campaign": campaign,
                    }
            else:
                report.errors["threatfox"] = f"HTTP {resp.status_code}"
        except (httpx.TimeoutException, httpx.ConnectError) as e:
            report.errors["threatfox"] = str(e)

    async def _query_virustotal(
        self, client: httpx.AsyncClient, h: str, report: HashReport
    ) -> None:
        """VirusTotal — AV detection aggregator (requires API key)."""
        if not self._vt_key:
            return

        # Rate limiting: max 4 requests per minute
        now = time.time()
        self._vt_timestamps = [t for t in self._vt_timestamps if now - t < 60]
        if len(self._vt_timestamps) >= VT_RATE_LIMIT:
            wait = 60 - (now - self._vt_timestamps[0])
            if wait > 0:
                await asyncio.sleep(wait)

        url = f"https://www.virustotal.com/api/v3/files/{h}"
        headers = {"x-apikey": self._vt_key}
        try:
            self._vt_timestamps.append(time.time())
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                detections = stats.get("malicious", 0) + stats.get("suspicious", 0)
                total = sum(stats.values()) if stats else 0
                report.virustotal = {
                    "detections": detections,
                    "total": total,
                    "name": data.get("meaningful_name", data.get("names", [""])[0] if data.get("names") else ""),
                }
            elif resp.status_code == 404:
                pass  # Hash not in VT — leave as None
            else:
                report.errors["virustotal"] = f"HTTP {resp.status_code}"
        except (httpx.TimeoutException, httpx.ConnectError) as e:
            report.errors["virustotal"] = str(e)
