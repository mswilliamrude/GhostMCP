"""Tests for ghost_auth_session ephemeral authentication system."""

from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.auth.session_manager import AuthSession, SessionManager, get_session_manager
from src.auth.form_login import FormLoginResult, form_login


# ---------------------------------------------------------------------------
# TestAuthSession — dataclass methods
# ---------------------------------------------------------------------------

class TestAuthSession:
    """Tests for the AuthSession dataclass."""

    def _make_session(self, **kwargs) -> AuthSession:
        """Create a test session with sensible defaults."""
        defaults = {
            "session_id": "test-abc123",
            "auth_type": "bearer",
            "origin": "https://localhost:3000",
            "created_at": time.monotonic(),
            "expires_at": time.monotonic() + 1800,  # 30 min
            "ttl_minutes": 30,
            "_bearer_token": "secret-token-123",
            "_cookies": {"session": "abc"},
            "_headers": {"X-Custom": "value"},
        }
        defaults.update(kwargs)
        return AuthSession(**defaults)

    def test_is_expired_false(self):
        """Session should not be expired when within TTL."""
        session = self._make_session(expires_at=time.monotonic() + 600)
        assert session.is_expired is False

    def test_is_expired_true(self):
        """Session should be expired when past TTL."""
        session = self._make_session(expires_at=time.monotonic() - 1)
        assert session.is_expired is True

    def test_remaining_seconds_positive(self):
        """remaining_seconds should be positive when session is active."""
        session = self._make_session(expires_at=time.monotonic() + 300)
        assert session.remaining_seconds > 0
        assert session.remaining_seconds <= 300

    def test_remaining_seconds_zero_when_expired(self):
        """remaining_seconds should be 0 when session is expired."""
        session = self._make_session(expires_at=time.monotonic() - 100)
        assert session.remaining_seconds == 0

    def test_matches_origin_exact(self):
        """matches_origin should return True for exact origin match."""
        session = self._make_session(origin="https://localhost:3000")
        assert session.matches_origin("https://localhost:3000/api/users") is True
        assert session.matches_origin("https://localhost:3000/") is True

    def test_matches_origin_mismatch(self):
        """matches_origin should return False for different origins."""
        session = self._make_session(origin="https://localhost:3000")
        assert session.matches_origin("https://localhost:4000/api") is False
        assert session.matches_origin("http://localhost:3000/api") is False
        assert session.matches_origin("https://example.com/api") is False

    def test_matches_origin_wildcard(self):
        """matches_origin with '*' should match any URL."""
        session = self._make_session(origin="*")
        assert session.matches_origin("https://anything.com/path") is True
        assert session.matches_origin("http://localhost:9999/test") is True

    def test_get_headers_with_bearer(self):
        """get_headers should include Authorization header for bearer sessions."""
        session = self._make_session(
            _bearer_token="my-secret-token",
            _headers={"X-Custom": "val"},
        )
        headers = session.get_headers()
        assert headers["Authorization"] == "Bearer my-secret-token"
        assert headers["X-Custom"] == "val"

    def test_get_headers_no_bearer(self):
        """get_headers should not include Authorization when no token."""
        session = self._make_session(
            _bearer_token="",
            _headers={"X-API-Key": "abc"},
        )
        headers = session.get_headers()
        assert "Authorization" not in headers
        assert headers["X-API-Key"] == "abc"

    def test_get_cookies(self):
        """get_cookies should return a copy of stored cookies."""
        session = self._make_session(_cookies={"session_id": "xyz", "csrf": "tok"})
        cookies = session.get_cookies()
        assert cookies == {"session_id": "xyz", "csrf": "tok"}
        # Should be a copy, not a reference
        cookies["new"] = "val"
        assert "new" not in session._cookies

    def test_repr_does_not_expose_credentials(self):
        """repr should not show sensitive fields."""
        session = self._make_session(
            _bearer_token="TOP_SECRET",
            _cookies={"secret": "cookie_value"},
            _headers={"Authorization": "Bearer LEAKED"},
        )
        representation = repr(session)
        assert "TOP_SECRET" not in representation
        assert "cookie_value" not in representation
        assert "LEAKED" not in representation


# ---------------------------------------------------------------------------
# TestSessionManager
# ---------------------------------------------------------------------------

class TestSessionManager:
    """Tests for the SessionManager."""

    @pytest.fixture
    def manager(self):
        """Create a fresh session manager for each test."""
        return SessionManager()

    @pytest.mark.asyncio
    async def test_create_session(self, manager):
        """create_session should return a valid AuthSession."""
        session = await manager.create_session(
            auth_type="bearer",
            origin="https://localhost:3000",
            ttl_minutes=30,
            bearer_token="test-token",
        )
        assert session.session_id
        assert len(session.session_id) == 12
        assert session.auth_type == "bearer"
        assert session.origin == "https://localhost:3000"
        assert session.ttl_minutes == 30
        assert session.is_expired is False
        assert session._bearer_token == "test-token"

    @pytest.mark.asyncio
    async def test_get_session_valid(self, manager):
        """get_session should return a valid session by ID."""
        session = await manager.create_session(
            auth_type="cookie",
            origin="https://app.example.com",
            cookies={"sess": "val123"},
        )
        retrieved = await manager.get_session(session.session_id)
        assert retrieved is not None
        assert retrieved.session_id == session.session_id
        assert retrieved._cookies == {"sess": "val123"}

    @pytest.mark.asyncio
    async def test_get_session_not_found(self, manager):
        """get_session should return None for unknown session IDs."""
        result = await manager.get_session("nonexistent-id")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_session_expired(self, manager):
        """get_session should return None for expired sessions."""
        # Create a session with 1 min TTL, then mock time to simulate expiry
        session = await manager.create_session(
            auth_type="bearer",
            origin="https://test.com",
            ttl_minutes=1,
            bearer_token="expiring",
        )
        # Manually expire the session
        session.expires_at = time.monotonic() - 1

        result = await manager.get_session(session.session_id)
        assert result is None

    @pytest.mark.asyncio
    async def test_destroy_session(self, manager):
        """destroy_session should wipe credentials and remove session."""
        session = await manager.create_session(
            auth_type="bearer",
            origin="https://test.com",
            bearer_token="secret",
            cookies={"a": "b"},
            headers={"X-Key": "val"},
        )

        destroyed = await manager.destroy_session(session.session_id)
        assert destroyed is True

        # Credentials should be wiped
        assert session._bearer_token == ""
        assert session._cookies == {}
        assert session._headers == {}

        # Should no longer be retrievable
        result = await manager.get_session(session.session_id)
        assert result is None

    @pytest.mark.asyncio
    async def test_destroy_session_not_found(self, manager):
        """destroy_session should return False for unknown IDs."""
        result = await manager.destroy_session("does-not-exist")
        assert result is False

    @pytest.mark.asyncio
    async def test_destroy_all(self, manager):
        """destroy_all should wipe all sessions."""
        await manager.create_session(auth_type="bearer", origin="https://a.com", bearer_token="t1")
        await manager.create_session(auth_type="cookie", origin="https://b.com", cookies={"x": "1"})
        await manager.create_session(auth_type="basic", origin="https://c.com", headers={"Auth": "x"})

        count = await manager.destroy_all()
        assert count == 3

        sessions = await manager.list_sessions()
        assert sessions == []

    @pytest.mark.asyncio
    async def test_list_sessions(self, manager):
        """list_sessions should return metadata only, never credentials."""
        await manager.create_session(
            auth_type="bearer",
            origin="https://api.example.com",
            ttl_minutes=60,
            bearer_token="super-secret-token",
        )
        await manager.create_session(
            auth_type="cookie",
            origin="https://web.example.com",
            ttl_minutes=15,
            cookies={"session_id": "private_cookie_value"},
        )

        sessions = await manager.list_sessions()
        assert len(sessions) == 2

        for s in sessions:
            # Should have metadata
            assert "session_id" in s
            assert "auth_type" in s
            assert "origin" in s
            assert "ttl_minutes" in s
            assert "remaining_seconds" in s
            assert "expired" in s

            # Should NEVER have credentials
            assert "token" not in s
            assert "bearer_token" not in s
            assert "cookies" not in s
            assert "headers" not in s
            assert "_bearer_token" not in s
            assert "_cookies" not in s
            assert "_headers" not in s

        # Verify no credential values leaked into any string representation
        sessions_str = json.dumps(sessions)
        assert "super-secret-token" not in sessions_str
        assert "private_cookie_value" not in sessions_str

    @pytest.mark.asyncio
    async def test_origin_locking(self, manager):
        """Sessions should be locked to their origin."""
        session = await manager.create_session(
            auth_type="bearer",
            origin="https://localhost:3000",
            bearer_token="locked-token",
        )

        assert session.matches_origin("https://localhost:3000/api/data") is True
        assert session.matches_origin("https://localhost:4000/api/data") is False
        assert session.matches_origin("https://evil.com/steal") is False

    @pytest.mark.asyncio
    async def test_ttl_clamping_min(self, manager):
        """TTL should be clamped to minimum 1 minute."""
        session = await manager.create_session(
            auth_type="bearer",
            origin="https://test.com",
            ttl_minutes=0,
            bearer_token="t",
        )
        assert session.ttl_minutes == 1

    @pytest.mark.asyncio
    async def test_ttl_clamping_max(self, manager):
        """TTL should be clamped to maximum 120 minutes."""
        session = await manager.create_session(
            auth_type="bearer",
            origin="https://test.com",
            ttl_minutes=999,
            bearer_token="t",
        )
        assert session.ttl_minutes == 120

    @pytest.mark.asyncio
    async def test_ttl_clamping_negative(self, manager):
        """Negative TTL should be clamped to 1 minute."""
        session = await manager.create_session(
            auth_type="bearer",
            origin="https://test.com",
            ttl_minutes=-50,
            bearer_token="t",
        )
        assert session.ttl_minutes == 1

    @pytest.mark.asyncio
    async def test_cleanup_expired_on_access(self, manager):
        """Expired sessions should be cleaned up on access."""
        # Create two sessions
        s1 = await manager.create_session(
            auth_type="bearer", origin="https://a.com", bearer_token="t1"
        )
        s2 = await manager.create_session(
            auth_type="bearer", origin="https://b.com", bearer_token="t2"
        )

        # Manually expire s1
        s1.expires_at = time.monotonic() - 1

        # Access triggers cleanup
        sessions = await manager.list_sessions()
        assert len(sessions) == 1
        assert sessions[0]["session_id"] == s2.session_id

    @pytest.mark.asyncio
    async def test_cleanup_wipes_credentials(self, manager):
        """Cleanup should wipe credentials from expired sessions."""
        session = await manager.create_session(
            auth_type="bearer",
            origin="https://test.com",
            bearer_token="sensitive",
            cookies={"key": "val"},
            headers={"X-Auth": "header"},
        )

        # Expire and trigger cleanup
        session.expires_at = time.monotonic() - 1
        await manager.list_sessions()

        # Credentials should be wiped even though session reference still exists
        assert session._bearer_token == ""
        assert session._cookies == {}
        assert session._headers == {}

    def test_singleton_get_session_manager(self):
        """get_session_manager should return the same instance."""
        # Reset the singleton for testing
        import src.auth.session_manager as sm
        sm._session_manager = None

        mgr1 = get_session_manager()
        mgr2 = get_session_manager()
        assert mgr1 is mgr2

        # Cleanup
        sm._session_manager = None


# ---------------------------------------------------------------------------
# TestFormLogin
# ---------------------------------------------------------------------------

class TestFormLogin:
    """Tests for form-based login via Playwright."""

    @pytest.mark.asyncio
    async def test_form_login_no_playwright(self):
        """form_login should return error when Playwright is not installed."""
        # Simulate ImportError by patching sys.modules during import
        import sys
        with patch.dict(sys.modules, {"playwright": None, "playwright.async_api": None}):
            # Re-import triggers ImportError inside form_login
            from src.auth.form_login import form_login as fl
            result = await fl(
                url="https://app.com/login",
                username="user",
                password="pass",
            )
            assert result.success is False
            assert "Playwright not installed" in result.error

    @pytest.mark.asyncio
    async def test_form_login_success(self):
        """form_login should capture cookies on successful login."""
        # Mock the entire Playwright context
        mock_page = AsyncMock()
        mock_context = AsyncMock()
        mock_browser = AsyncMock()

        # Setup page behavior
        mock_username_el = AsyncMock()
        mock_password_el = AsyncMock()
        mock_submit_el = AsyncMock()

        mock_page.goto = AsyncMock()
        mock_page.wait_for_timeout = AsyncMock()
        mock_page.url = "https://app.example.com/dashboard"

        # query_selector returns elements based on selector
        async def mock_query_selector(selector):
            if "username" in selector or "email" in selector:
                return mock_username_el
            if "password" in selector:
                return mock_password_el
            if "submit" in selector:
                return mock_submit_el
            return None

        mock_page.query_selector = AsyncMock(side_effect=mock_query_selector)
        mock_page.evaluate = AsyncMock(return_value={"auth_token": "jwt-xyz"})

        # Context returns cookies
        mock_context.cookies = AsyncMock(return_value=[
            {"name": "session_id", "value": "abc123"},
            {"name": "csrf_token", "value": "def456"},
        ])
        mock_context.new_page = AsyncMock(return_value=mock_page)

        mock_browser.new_context = AsyncMock(return_value=mock_context)
        mock_browser.close = AsyncMock()

        mock_playwright_cm = AsyncMock()
        mock_playwright_cm.chromium = AsyncMock()
        mock_playwright_cm.chromium.launch = AsyncMock(return_value=mock_browser)

        with patch("playwright.async_api.async_playwright") as mock_pw:
            # Setup the async context manager
            mock_pw.return_value.__aenter__ = AsyncMock(return_value=mock_playwright_cm)
            mock_pw.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await form_login(
                url="https://app.example.com/login",
                username="testuser",
                password="testpass",
            )

        assert result.success is True
        assert result.cookies == {"session_id": "abc123", "csrf_token": "def456"}
        assert result.final_url == "https://app.example.com/dashboard"
        assert result.session_storage == {"auth_token": "jwt-xyz"}
        assert result.error == ""

    @pytest.mark.asyncio
    async def test_form_login_missing_username_field(self):
        """form_login should return error when username field not found."""
        mock_page = AsyncMock()
        mock_context = AsyncMock()
        mock_browser = AsyncMock()

        mock_page.goto = AsyncMock()
        mock_page.wait_for_timeout = AsyncMock()
        mock_page.query_selector = AsyncMock(return_value=None)  # No elements found

        mock_context.new_page = AsyncMock(return_value=mock_page)
        mock_browser.new_context = AsyncMock(return_value=mock_context)
        mock_browser.close = AsyncMock()

        mock_playwright_cm = AsyncMock()
        mock_playwright_cm.chromium = AsyncMock()
        mock_playwright_cm.chromium.launch = AsyncMock(return_value=mock_browser)

        with patch("playwright.async_api.async_playwright") as mock_pw:
            mock_pw.return_value.__aenter__ = AsyncMock(return_value=mock_playwright_cm)
            mock_pw.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await form_login(
                url="https://app.example.com/login",
                username="testuser",
                password="testpass",
            )

        assert result.success is False
        assert "Username field not found" in result.error

    @pytest.mark.asyncio
    async def test_form_login_missing_password_field(self):
        """form_login should return error when password field not found."""
        mock_page = AsyncMock()
        mock_context = AsyncMock()
        mock_browser = AsyncMock()

        mock_username_el = AsyncMock()

        # Return username element but not password
        async def mock_query_selector(selector):
            if "username" in selector or "email" in selector:
                return mock_username_el
            return None

        mock_page.goto = AsyncMock()
        mock_page.wait_for_timeout = AsyncMock()
        mock_page.query_selector = AsyncMock(side_effect=mock_query_selector)

        mock_context.new_page = AsyncMock(return_value=mock_page)
        mock_browser.new_context = AsyncMock(return_value=mock_context)
        mock_browser.close = AsyncMock()

        mock_playwright_cm = AsyncMock()
        mock_playwright_cm.chromium = AsyncMock()
        mock_playwright_cm.chromium.launch = AsyncMock(return_value=mock_browser)

        with patch("playwright.async_api.async_playwright") as mock_pw:
            mock_pw.return_value.__aenter__ = AsyncMock(return_value=mock_playwright_cm)
            mock_pw.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await form_login(
                url="https://app.example.com/login",
                username="testuser",
                password="testpass",
            )

        assert result.success is False
        assert "Password field not found" in result.error

    @pytest.mark.asyncio
    async def test_form_login_failure_indicator(self):
        """form_login should detect login failure via indicator selector."""
        mock_page = AsyncMock()
        mock_context = AsyncMock()
        mock_browser = AsyncMock()

        mock_username_el = AsyncMock()
        mock_password_el = AsyncMock()
        mock_submit_el = AsyncMock()
        mock_failure_el = AsyncMock()  # Failure indicator is present

        async def mock_query_selector(selector):
            if "username" in selector or "email" in selector:
                return mock_username_el
            if "password" in selector:
                return mock_password_el
            if "submit" in selector:
                return mock_submit_el
            if selector == ".error-message":
                return mock_failure_el
            return None

        mock_page.goto = AsyncMock()
        mock_page.wait_for_timeout = AsyncMock()
        mock_page.url = "https://app.example.com/login"
        mock_page.query_selector = AsyncMock(side_effect=mock_query_selector)

        mock_context.new_page = AsyncMock(return_value=mock_page)
        mock_browser.new_context = AsyncMock(return_value=mock_context)
        mock_browser.close = AsyncMock()

        mock_playwright_cm = AsyncMock()
        mock_playwright_cm.chromium = AsyncMock()
        mock_playwright_cm.chromium.launch = AsyncMock(return_value=mock_browser)

        with patch("playwright.async_api.async_playwright") as mock_pw:
            mock_pw.return_value.__aenter__ = AsyncMock(return_value=mock_playwright_cm)
            mock_pw.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await form_login(
                url="https://app.example.com/login",
                username="testuser",
                password="wrongpass",
                failure_indicator=".error-message",
            )

        assert result.success is False
        assert "failure indicator" in result.error.lower()

    @pytest.mark.asyncio
    async def test_form_login_exception_handling(self):
        """form_login should handle exceptions gracefully."""
        with patch("playwright.async_api.async_playwright") as mock_pw:
            mock_pw.return_value.__aenter__ = AsyncMock(
                side_effect=RuntimeError("Browser crashed")
            )
            mock_pw.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await form_login(
                url="https://app.example.com/login",
                username="testuser",
                password="testpass",
            )

        assert result.success is False
        assert "RuntimeError" in result.error


# ---------------------------------------------------------------------------
# TestGhostAuthSessionTool — integration test of the MCP tool handler
# ---------------------------------------------------------------------------

class TestGhostAuthSessionTool:
    """Tests for the ghost_auth_session MCP tool."""

    @pytest.fixture(autouse=True)
    def reset_singleton(self):
        """Reset the session manager singleton before each test."""
        import src.auth.session_manager as sm
        sm._session_manager = None
        yield
        sm._session_manager = None

    @pytest.mark.asyncio
    async def test_list_empty(self):
        """list action with no sessions should return informative message."""
        from src.mcp import ghost_auth_session
        result = await ghost_auth_session(action="list")
        assert "No active auth sessions" in result

    @pytest.mark.asyncio
    async def test_create_bearer(self):
        """create bearer session should succeed."""
        from src.mcp import ghost_auth_session
        result = await ghost_auth_session(
            action="create",
            auth_type="bearer",
            origin="https://api.example.com",
            token="my-api-key",
            ttl_minutes=60,
        )
        assert "Bearer auth session created" in result
        assert "https://api.example.com" in result
        assert "60 min" in result

    @pytest.mark.asyncio
    async def test_create_bearer_missing_token(self):
        """create bearer without token should return error."""
        from src.mcp import ghost_auth_session
        result = await ghost_auth_session(
            action="create",
            auth_type="bearer",
            origin="https://api.example.com",
            token="",
        )
        assert "Error" in result
        assert "token" in result.lower()

    @pytest.mark.asyncio
    async def test_create_cookie(self):
        """create cookie session should succeed."""
        from src.mcp import ghost_auth_session
        result = await ghost_auth_session(
            action="create",
            auth_type="cookie",
            origin="https://web.example.com",
            cookies='{"session_id": "abc", "csrf": "xyz"}',
        )
        assert "Cookie auth session created" in result
        assert "2 stored" in result

    @pytest.mark.asyncio
    async def test_create_cookie_invalid_json(self):
        """create cookie with invalid JSON should return error."""
        from src.mcp import ghost_auth_session
        result = await ghost_auth_session(
            action="create",
            auth_type="cookie",
            origin="https://web.example.com",
            cookies="not valid json",
        )
        assert "Error" in result
        assert "invalid cookies JSON" in result

    @pytest.mark.asyncio
    async def test_create_basic(self):
        """create basic auth session should succeed."""
        from src.mcp import ghost_auth_session
        result = await ghost_auth_session(
            action="create",
            auth_type="basic",
            origin="https://api.example.com",
            username="admin",
            password="secret",
        )
        assert "Basic auth session created" in result

    @pytest.mark.asyncio
    async def test_create_missing_origin(self):
        """create without origin should return error."""
        from src.mcp import ghost_auth_session
        result = await ghost_auth_session(
            action="create",
            auth_type="bearer",
            origin="",
            token="t",
        )
        assert "Error" in result
        assert "origin" in result.lower()

    @pytest.mark.asyncio
    async def test_create_form_missing_credentials(self):
        """create form without credentials should return error."""
        from src.mcp import ghost_auth_session
        result = await ghost_auth_session(
            action="create",
            auth_type="form",
            origin="https://app.com",
            url="https://app.com/login",
            username="",
            password="",
        )
        assert "Error" in result
        assert "username and password" in result.lower()

    @pytest.mark.asyncio
    async def test_destroy(self):
        """destroy should remove session."""
        from src.mcp import ghost_auth_session

        # Create first
        create_result = await ghost_auth_session(
            action="create",
            auth_type="bearer",
            origin="https://api.com",
            token="to-destroy",
        )
        # Extract session ID from result
        for line in create_result.split("\n"):
            if "Session ID:" in line:
                sid = line.split(":")[-1].strip()
                break

        # Destroy
        result = await ghost_auth_session(action="destroy", session_id=sid)
        assert "destroyed" in result.lower()
        assert "wiped" in result.lower()

    @pytest.mark.asyncio
    async def test_destroy_not_found(self):
        """destroy non-existent session should report not found."""
        from src.mcp import ghost_auth_session
        result = await ghost_auth_session(action="destroy", session_id="fake-id")
        assert "not found" in result.lower()

    @pytest.mark.asyncio
    async def test_destroy_all(self):
        """destroy_all should wipe all sessions."""
        from src.mcp import ghost_auth_session

        # Create a few sessions
        await ghost_auth_session(action="create", auth_type="bearer", origin="https://a.com", token="t1")
        await ghost_auth_session(action="create", auth_type="bearer", origin="https://b.com", token="t2")

        result = await ghost_auth_session(action="destroy_all")
        assert "2 wiped" in result

    @pytest.mark.asyncio
    async def test_list_after_create(self):
        """list should show created sessions."""
        from src.mcp import ghost_auth_session

        await ghost_auth_session(
            action="create",
            auth_type="bearer",
            origin="https://api.example.com",
            token="secret-token",
            ttl_minutes=45,
        )

        result = await ghost_auth_session(action="list")
        assert "Active Auth Sessions" in result
        assert "bearer" in result
        assert "https://api.example.com" in result
        assert "45 min" in result
        # Credentials should NOT appear
        assert "secret-token" not in result

    @pytest.mark.asyncio
    async def test_unknown_action(self):
        """Unknown action should return error."""
        from src.mcp import ghost_auth_session
        result = await ghost_auth_session(action="invalid")
        assert "Error" in result
        assert "unknown action" in result.lower()

    @pytest.mark.asyncio
    async def test_unknown_auth_type(self):
        """Unknown auth_type should return error."""
        from src.mcp import ghost_auth_session
        result = await ghost_auth_session(
            action="create",
            auth_type="oauth2",
            origin="https://test.com",
        )
        assert "Error" in result
        assert "unknown auth_type" in result.lower()
