"""Tests for Perplexity AI search-augmented research tool."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Sample API responses
# ---------------------------------------------------------------------------

SAMPLE_PERPLEXITY_RESPONSE = {
    "id": "chatcmpl-abc123",
    "model": "sonar-pro",
    "choices": [
        {
            "index": 0,
            "message": {
                "role": "assistant",
                "content": (
                    "HTTP/2 Bomb (CVE-2026-49975) is a remote denial-of-service "
                    "vulnerability affecting major web servers including nginx, Apache, "
                    "IIS, Envoy, and Cloudflare Pingora. The attack exploits HPACK "
                    "header compression to exhaust server RAM with a single connection."
                ),
            },
            "finish_reason": "stop",
        }
    ],
    "citations": [
        "https://thehackernews.com/2026/06/new-http2-bomb-vulnerability-allows.html",
        "https://blog.calif.io/p/codex-discovered-a-hidden-http2-bomb",
        "https://nginx.org/en/security_advisories.html",
    ],
    "usage": {
        "prompt_tokens": 42,
        "completion_tokens": 156,
        "total_tokens": 198,
    },
}

SAMPLE_DEEP_RESEARCH_RESPONSE = {
    "id": "chatcmpl-deep456",
    "model": "sonar-deep-research",
    "choices": [
        {
            "index": 0,
            "message": {
                "role": "assistant",
                "content": (
                    "## MikroTik RouterOS Custom Firmware\n\n"
                    "Based on my research, the MikroTikPatch project provides "
                    "a fully automated CI/CD pipeline for producing patched "
                    "RouterOS firmware..."
                ),
            },
            "finish_reason": "stop",
        }
    ],
    "citations": [
        {"url": "https://github.com/elseif/MikroTikPatch", "title": "MikroTikPatch"},
        {"url": "https://margin.re/2022/06/pulling-mikrotik-into-the-limelight/"},
    ],
    "usage": {
        "prompt_tokens": 85,
        "completion_tokens": 2048,
        "total_tokens": 2133,
    },
}

EMPTY_RESPONSE = {
    "id": "chatcmpl-empty",
    "model": "sonar-pro",
    "choices": [],
    "usage": {},
}

NO_CONTENT_RESPONSE = {
    "id": "chatcmpl-nocontent",
    "model": "sonar",
    "choices": [{"index": 0, "message": {"role": "assistant", "content": ""}}],
    "usage": {},
}


# ---------------------------------------------------------------------------
# Helper to build mock httpx response
# ---------------------------------------------------------------------------


def _mock_response(status_code: int = 200, json_data: dict = None, text: str = ""):
    """Create a mock httpx.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.text = text or str(json_data)
    return resp


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def set_perplexity_key(monkeypatch):
    """Set a fake API key for all tests."""
    monkeypatch.setenv("GHOST_PERPLEXITY_KEY", "pplx-test-key-fake123")


class TestGhostPerplexityBasic:
    """Basic functionality tests."""

    @pytest.mark.asyncio
    async def test_missing_query(self):
        """Empty query returns error."""
        from src.mcp import ghost_perplexity

        result = await ghost_perplexity(query="")
        assert "Error" in result
        assert "required" in result

    @pytest.mark.asyncio
    async def test_missing_api_key(self, monkeypatch):
        """Missing API key returns helpful error."""
        monkeypatch.delenv("GHOST_PERPLEXITY_KEY", raising=False)
        from src.mcp import ghost_perplexity

        result = await ghost_perplexity(query="test query")
        assert "GHOST_PERPLEXITY_KEY" in result
        assert "perplexity.ai" in result

    @pytest.mark.asyncio
    async def test_invalid_model(self):
        """Invalid model name returns error."""
        from src.mcp import ghost_perplexity

        result = await ghost_perplexity(query="test", model="gpt-4")
        assert "Error" in result
        assert "unknown model" in result

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient.post")
    async def test_successful_query(self, mock_post):
        """Successful query returns formatted response with citations."""
        mock_post.return_value = _mock_response(200, SAMPLE_PERPLEXITY_RESPONSE)
        from src.mcp import ghost_perplexity

        result = await ghost_perplexity(query="HTTP/2 Bomb vulnerability")
        assert "[perplexity/sonar-pro]" in result
        assert "HTTP/2 Bomb" in result
        assert "CVE-2026-49975" in result
        assert "Sources" in result
        assert "thehackernews.com" in result
        assert "Tokens:" in result

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient.post")
    async def test_deep_research_model(self, mock_post):
        """Deep research model returns results with dict citations."""
        mock_post.return_value = _mock_response(200, SAMPLE_DEEP_RESEARCH_RESPONSE)
        from src.mcp import ghost_perplexity

        result = await ghost_perplexity(
            query="MikroTik custom firmware", model="sonar-deep-research"
        )
        assert "[perplexity/sonar-deep-research]" in result
        assert "MikroTikPatch" in result
        assert "Sources" in result

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient.post")
    async def test_empty_choices(self, mock_post):
        """Empty choices array returns error."""
        mock_post.return_value = _mock_response(200, EMPTY_RESPONSE)
        from src.mcp import ghost_perplexity

        result = await ghost_perplexity(query="test")
        assert "Error" in result
        assert "No response" in result

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient.post")
    async def test_empty_content(self, mock_post):
        """Empty content string returns error."""
        mock_post.return_value = _mock_response(200, NO_CONTENT_RESPONSE)
        from src.mcp import ghost_perplexity

        result = await ghost_perplexity(query="test")
        assert "Error" in result
        assert "Empty response" in result


class TestGhostPerplexityErrors:
    """Error handling tests."""

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient.post")
    async def test_401_unauthorized(self, mock_post):
        """401 returns helpful auth error."""
        mock_post.return_value = _mock_response(401, text="Unauthorized")
        from src.mcp import ghost_perplexity

        result = await ghost_perplexity(query="test")
        assert "401" in result
        assert "Invalid" in result or "Unauthorized" in result

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient.post")
    async def test_429_rate_limit(self, mock_post):
        """429 returns rate limit message."""
        mock_post.return_value = _mock_response(429, text="Rate limited")
        from src.mcp import ghost_perplexity

        result = await ghost_perplexity(query="test")
        assert "rate limit" in result.lower()

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient.post")
    async def test_500_server_error(self, mock_post):
        """500 returns server error with status code."""
        mock_post.return_value = _mock_response(500, text="Internal Server Error")
        from src.mcp import ghost_perplexity

        result = await ghost_perplexity(query="test")
        assert "500" in result

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient.post")
    async def test_timeout(self, mock_post):
        """Timeout returns helpful message."""
        import httpx

        mock_post.side_effect = httpx.TimeoutException("Connection timed out")
        from src.mcp import ghost_perplexity

        result = await ghost_perplexity(query="very complex research question")
        assert "timed out" in result.lower()

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient.post")
    async def test_connection_error(self, mock_post):
        """Connection error returns helpful message."""
        import httpx

        mock_post.side_effect = httpx.ConnectError("DNS resolution failed")
        from src.mcp import ghost_perplexity

        result = await ghost_perplexity(query="test")
        assert "Cannot connect" in result


class TestGhostPerplexityParameters:
    """Parameter handling tests."""

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient.post")
    async def test_search_recency_week(self, mock_post):
        """Search recency filter is passed to API."""
        mock_post.return_value = _mock_response(200, SAMPLE_PERPLEXITY_RESPONSE)
        from src.mcp import ghost_perplexity

        await ghost_perplexity(query="latest news", search_recency="week")

        # Verify the payload included recency filter
        call_kwargs = mock_post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert payload["search_recency_filter"] == "week"

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient.post")
    async def test_search_recency_invalid_ignored(self, mock_post):
        """Invalid recency filter is silently ignored."""
        mock_post.return_value = _mock_response(200, SAMPLE_PERPLEXITY_RESPONSE)
        from src.mcp import ghost_perplexity

        await ghost_perplexity(query="test", search_recency="invalid_value")

        call_kwargs = mock_post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert "search_recency_filter" not in payload

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient.post")
    async def test_sonar_model(self, mock_post):
        """Sonar model is passed correctly."""
        mock_post.return_value = _mock_response(200, SAMPLE_PERPLEXITY_RESPONSE)
        from src.mcp import ghost_perplexity

        await ghost_perplexity(query="quick question", model="sonar")

        call_kwargs = mock_post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert payload["model"] == "sonar"

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient.post")
    async def test_no_citations(self, mock_post):
        """Response without citations still works."""
        response = {
            "id": "test",
            "model": "sonar-pro",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Answer without citations.",
                    }
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        }
        mock_post.return_value = _mock_response(200, response)
        from src.mcp import ghost_perplexity

        result = await ghost_perplexity(query="simple question")
        assert "Answer without citations" in result
        assert "Sources" not in result

    @pytest.mark.asyncio
    @patch("httpx.AsyncClient.post")
    async def test_api_key_in_header(self, mock_post):
        """API key is sent in Authorization header."""
        mock_post.return_value = _mock_response(200, SAMPLE_PERPLEXITY_RESPONSE)
        from src.mcp import ghost_perplexity

        await ghost_perplexity(query="test")

        call_kwargs = mock_post.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers")
        assert "Bearer pplx-test-key-fake123" in headers["Authorization"]
