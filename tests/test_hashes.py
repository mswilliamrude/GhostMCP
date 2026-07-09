"""Tests for hash detection, file hashing, verdict logic, and HashLookup."""

from __future__ import annotations

import hashlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ghostmcp.recon.hashes import (
    HashReport,
    detect_hash_type,
    compute_file_hashes,
    _determine_verdict,
    HashLookup,
)


class TestDetectHashType:
    """Tests for detect_hash_type()."""

    @pytest.mark.parametrize("hex_str,expected", [
        ("d41d8cd98f00b204e9800998ecf8427e", "md5"),  # 32 chars
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"),  # 40 chars
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"),  # 64 chars
        ("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", "sha512"),  # 128 chars
    ])
    def test_valid_hashes(self, hex_str, expected):
        assert detect_hash_type(hex_str) == expected

    def test_strips_whitespace(self):
        md5 = "  d41d8cd98f00b204e9800998ecf8427e  "
        assert detect_hash_type(md5) == "md5"

    def test_case_insensitive(self):
        md5_upper = "D41D8CD98F00B204E9800998ECF8427E"
        assert detect_hash_type(md5_upper) == "md5"

    def test_invalid_characters(self):
        # Contains 'g' which is not hex
        assert detect_hash_type("g41d8cd98f00b204e9800998ecf8427e") is None

    def test_wrong_length(self):
        # 31 chars (not a standard hash length)
        assert detect_hash_type("d41d8cd98f00b204e9800998ecf842") is None

    def test_empty_string(self):
        assert detect_hash_type("") is None

    def test_non_hex_string(self):
        assert detect_hash_type("not-a-hash-at-all") is None

    @pytest.mark.parametrize("length", [32, 40, 64, 128])
    def test_correct_lengths_with_zeros(self, length):
        """Hash of all zeros with correct length is detected."""
        h = "0" * length
        assert detect_hash_type(h) is not None


class TestComputeFileHashes:
    """Tests for compute_file_hashes()."""

    def test_computes_all_three(self, temp_file_with_content):
        filepath, content = temp_file_with_content
        result = compute_file_hashes(filepath)
        assert "md5" in result
        assert "sha1" in result
        assert "sha256" in result

    def test_hash_values_correct(self, known_hashes):
        filepath = known_hashes["filepath"]
        result = compute_file_hashes(filepath)
        assert result["md5"] == known_hashes["md5"]
        assert result["sha1"] == known_hashes["sha1"]
        assert result["sha256"] == known_hashes["sha256"]

    def test_hashes_are_hex_strings(self, temp_file_with_content):
        filepath, _ = temp_file_with_content
        result = compute_file_hashes(filepath)
        for algo, h in result.items():
            assert all(c in "0123456789abcdef" for c in h)

    def test_hash_lengths(self, temp_file_with_content):
        filepath, _ = temp_file_with_content
        result = compute_file_hashes(filepath)
        assert len(result["md5"]) == 32
        assert len(result["sha1"]) == 40
        assert len(result["sha256"]) == 64

    def test_empty_file(self, tmp_path):
        filepath = tmp_path / "empty.bin"
        filepath.write_bytes(b"")
        result = compute_file_hashes(str(filepath))
        # Known empty file hashes
        assert result["md5"] == hashlib.md5(b"").hexdigest()
        assert result["sha256"] == hashlib.sha256(b"").hexdigest()

    def test_nonexistent_file_raises(self):
        with pytest.raises((FileNotFoundError, OSError)):
            compute_file_hashes("/nonexistent/path/file.bin")


class TestDetermineVerdict:
    """Tests for _determine_verdict() logic."""

    def _make_report(self, **kwargs):
        return HashReport(
            hash_value="a" * 64,
            hash_type="sha256",
            **kwargs,
        )

    def test_malwarebazaar_means_malicious(self):
        report = self._make_report(malwarebazaar={"family": "emotet", "tags": [], "first_seen": "", "file_type": ""})
        assert _determine_verdict(report) == "malicious"

    def test_threatfox_means_malicious(self):
        report = self._make_report(threatfox={"malware": "cobalt", "c2": [], "campaign": ""})
        assert _determine_verdict(report) == "malicious"

    def test_vt_high_detections_malicious(self):
        report = self._make_report(virustotal={"detections": 15, "total": 70, "name": "malware.exe"})
        assert _determine_verdict(report) == "malicious"

    def test_vt_low_detections_suspicious(self):
        report = self._make_report(virustotal={"detections": 3, "total": 70, "name": "suspicious.exe"})
        assert _determine_verdict(report) == "suspicious"

    def test_vt_single_detection_suspicious(self):
        report = self._make_report(virustotal={"detections": 1, "total": 70, "name": "file.exe"})
        assert _determine_verdict(report) == "suspicious"

    def test_vt_boundary_11_detections_malicious(self):
        report = self._make_report(virustotal={"detections": 11, "total": 70, "name": "file"})
        assert _determine_verdict(report) == "malicious"

    def test_vt_boundary_10_detections_suspicious(self):
        report = self._make_report(virustotal={"detections": 10, "total": 70, "name": "file"})
        assert _determine_verdict(report) == "suspicious"

    def test_circl_known_clean(self):
        report = self._make_report(circl={"known": True, "filename": "calc.exe", "source": "NSRL"})
        assert _determine_verdict(report) == "clean"

    def test_circl_unknown_is_unknown(self):
        report = self._make_report(circl={"known": False, "filename": "", "source": ""})
        assert _determine_verdict(report) == "unknown"

    def test_nothing_found_unknown(self):
        report = self._make_report()
        assert _determine_verdict(report) == "unknown"

    def test_malwarebazaar_overrides_circl_clean(self):
        """Malware services take priority over CIRCL clean."""
        report = self._make_report(
            malwarebazaar={"family": "trojan", "tags": [], "first_seen": "", "file_type": ""},
            circl={"known": True, "filename": "legit.exe", "source": "NSRL"},
        )
        assert _determine_verdict(report) == "malicious"

    def test_vt_zero_detections_not_suspicious(self):
        report = self._make_report(virustotal={"detections": 0, "total": 70, "name": "clean.exe"})
        assert _determine_verdict(report) == "unknown"


class TestHashLookup:
    """Tests for HashLookup.lookup() with mocked HTTP."""

    @pytest.mark.asyncio
    async def test_lookup_invalid_hash_raises(self):
        hl = HashLookup()
        with pytest.raises(ValueError, match="Cannot detect hash type"):
            await hl.lookup("not_a_valid_hash")

    @pytest.mark.asyncio
    async def test_lookup_empty_hash_raises(self):
        hl = HashLookup()
        with pytest.raises(ValueError):
            await hl.lookup("")

    @pytest.mark.asyncio
    async def test_lookup_queries_services(self):
        """Lookup should query CIRCL, MalwareBazaar, and ThreatFox."""
        sha256 = "a" * 64

        mock_resp_circl = MagicMock()
        mock_resp_circl.status_code = 404
        mock_resp_circl.json.return_value = {}

        mock_resp_bazaar = MagicMock()
        mock_resp_bazaar.status_code = 200
        mock_resp_bazaar.json.return_value = {"query_status": "hash_not_found"}

        mock_resp_threatfox = MagicMock()
        mock_resp_threatfox.status_code = 200
        mock_resp_threatfox.json.return_value = {"query_status": "no_result"}

        async def mock_get(url, **kwargs):
            if "circl" in url:
                return mock_resp_circl
            return MagicMock(status_code=404)

        async def mock_post(url, **kwargs):
            if "abuse.ch/api/v1" in url:
                return mock_resp_bazaar
            if "threatfox" in url:
                return mock_resp_threatfox
            return MagicMock(status_code=404)

        with patch("httpx.AsyncClient.get", side_effect=mock_get):
            with patch("httpx.AsyncClient.post", side_effect=mock_post):
                hl = HashLookup()
                report = await hl.lookup(sha256)

        assert report.hash_value == sha256
        assert report.hash_type == "sha256"
        assert report.verdict == "unknown"

    @pytest.mark.asyncio
    async def test_lookup_malwarebazaar_hit(self):
        """MalwareBazaar positive hit should set verdict to malicious."""
        sha256 = "b" * 64

        mock_resp_circl = MagicMock()
        mock_resp_circl.status_code = 404

        mock_resp_bazaar = MagicMock()
        mock_resp_bazaar.status_code = 200
        mock_resp_bazaar.json.return_value = {
            "query_status": "ok",
            "data": [{
                "signature": "Emotet",
                "tags": ["banking", "trojan"],
                "first_seen": "2024-01-01",
                "file_type": "exe",
            }],
        }

        mock_resp_threatfox = MagicMock()
        mock_resp_threatfox.status_code = 200
        mock_resp_threatfox.json.return_value = {"query_status": "no_result"}

        async def mock_get(url, **kwargs):
            return mock_resp_circl

        async def mock_post(url, **kwargs):
            if "threatfox" in url:
                return mock_resp_threatfox
            return mock_resp_bazaar

        with patch("httpx.AsyncClient.get", side_effect=mock_get):
            with patch("httpx.AsyncClient.post", side_effect=mock_post):
                hl = HashLookup()
                report = await hl.lookup(sha256)

        assert report.malwarebazaar is not None
        assert report.malwarebazaar["family"] == "Emotet"
        assert report.verdict == "malicious"

    @pytest.mark.asyncio
    async def test_lookup_file_nonexistent_raises(self):
        hl = HashLookup()
        with pytest.raises(FileNotFoundError):
            await hl.lookup_file("/nonexistent/path/file.txt")
