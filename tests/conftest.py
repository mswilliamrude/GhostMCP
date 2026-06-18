"""Shared fixtures for GhostMCP test suite."""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest


# ---------------------------------------------------------------------------
# pytest-asyncio config + custom markers
# ---------------------------------------------------------------------------

def pytest_configure(config):
    """Set asyncio_mode to auto for all async tests."""
    config.addinivalue_line("markers", "asyncio: mark test as async")
    config.addinivalue_line(
        "markers",
        "integration: mark test as integration (requires live API keys, "
        "run with: pytest -m integration)",
    )
    config.addinivalue_line(
        "markers",
        "paid: mark test as requiring a paid API key "
        "(run with: pytest -m paid)",
    )


def pytest_collection_modifyitems(config, items):
    """Skip integration and paid tests unless explicitly requested.

    Usage:
        pytest                          # runs only unit tests (default)
        pytest -m integration           # runs only integration tests
        pytest -m paid                  # runs only paid API tests
        pytest -m "integration or paid" # runs both
        pytest -m ""                    # runs everything
    """
    run_integration = False
    run_paid = False

    # Check if the user explicitly requested these markers
    markexpr = config.getoption("-m", default="")
    if "integration" in markexpr:
        run_integration = True
    if "paid" in markexpr:
        run_paid = True

    skip_integration = pytest.mark.skip(
        reason="Integration test — run with: pytest -m integration"
    )
    skip_paid = pytest.mark.skip(
        reason="Paid API test — run with: pytest -m paid"
    )

    for item in items:
        if "integration" in item.keywords and not run_integration:
            item.add_marker(skip_integration)
        if "paid" in item.keywords and not run_paid:
            item.add_marker(skip_paid)


# ---------------------------------------------------------------------------
# Integration test helpers
# ---------------------------------------------------------------------------

def require_env(var_name: str) -> str:
    """Get an env var or skip the test if not set."""
    val = os.environ.get(var_name, "")
    if not val:
        pytest.skip(f"{var_name} not set")
    return val


# ---------------------------------------------------------------------------
# Temp file fixtures for hash tests
# ---------------------------------------------------------------------------

@pytest.fixture
def temp_file_with_content(tmp_path):
    """Create a temp file with known content for hash verification."""
    content = b"GhostMCP test file content for hashing"
    filepath = tmp_path / "testfile.bin"
    filepath.write_bytes(content)
    return str(filepath), content


@pytest.fixture
def known_hashes(temp_file_with_content):
    """Return expected hashes for the temp file."""
    filepath, content = temp_file_with_content
    return {
        "filepath": filepath,
        "md5": hashlib.md5(content).hexdigest(),
        "sha1": hashlib.sha1(content).hexdigest(),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


# ---------------------------------------------------------------------------
# Sample Google SERP HTML
# ---------------------------------------------------------------------------

SAMPLE_GOOGLE_HTML = """
<html>
<head><title>test - Google Search</title></head>
<body>
<div class="g">
  <a href="/url?q=https://example.com/result1&sa=U">
    <h3>First Result Title</h3>
  </a>
  <div class="VwiC3b">This is the snippet for result one with <em>keywords</em>.</div>
</div>
<div class="g">
  <a href="/url?q=https://example.org/second&sa=U">
    <h3>Second Result Title</h3>
  </a>
  <div class="VwiC3b">Another snippet with relevant information.</div>
</div>
<div class="g">
  <a href="https://direct-link.io/page">
    <h3>Direct Link Result</h3>
  </a>
  <div class="VwiC3b">A result with a direct URL instead of redirect.</div>
</div>
</body>
</html>
"""

CAPTCHA_GOOGLE_HTML = """
<html>
<body>
<h1>We detected unusual traffic from your computer network</h1>
<p>Please solve the CAPTCHA to continue.</p>
<div class="recaptcha"></div>
</body>
</html>
"""

CONSENT_GOOGLE_HTML = """
<html>
<body>
<div id="CXQnmb">
  <h1>Before you continue to Google</h1>
  <p>consent.google.com</p>
</div>
</body>
</html>
"""

EMPTY_GOOGLE_HTML = """
<html>
<body>
<div id="search">
  <p>Your search did not match any documents.</p>
</div>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Sample Serper API responses
# ---------------------------------------------------------------------------

SAMPLE_SERPER_RESPONSE = {
    "organic": [
        {
            "title": "First Serper Result",
            "link": "https://example.com/serper1",
            "snippet": "Snippet from serper API result one.",
        },
        {
            "title": "Second Serper Result",
            "link": "https://example.org/serper2",
            "snippet": "Snippet from serper API result two.",
        },
        {
            "title": "",
            "link": "https://no-title.com/page",
            "snippet": "Result with empty title.",
        },
    ],
    "searchParameters": {"q": "test query"},
}

EMPTY_SERPER_RESPONSE = {
    "organic": [],
    "searchParameters": {"q": "nothing here"},
}

SERPER_RESPONSE_NO_LINK = {
    "organic": [
        {"title": "No Link Entry", "link": "", "snippet": "Should be skipped."},
        {"title": "Valid Entry", "link": "https://valid.com", "snippet": "Kept."},
    ],
}


# ---------------------------------------------------------------------------
# Mock httpx response factory
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_httpx_response():
    """Factory for creating mock httpx responses."""
    def _make_response(status_code=200, json_data=None, text="", headers=None):
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text
        resp.headers = headers or {}
        if json_data is not None:
            resp.json.return_value = json_data
        resp.raise_for_status = MagicMock()
        if status_code >= 400:
            from httpx import HTTPStatusError, Request, Response
            resp.raise_for_status.side_effect = HTTPStatusError(
                f"HTTP {status_code}",
                request=MagicMock(),
                response=resp,
            )
        return resp
    return _make_response
