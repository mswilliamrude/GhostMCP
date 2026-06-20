"""Ephemeral session-scoped authentication for GhostMCP.

Credentials exist only in memory for the duration of the MCP session.
Never persisted to disk, database, logs, or Unimind.
Auto-wiped after TTL expires or on disconnect.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse


@dataclass
class AuthSession:
    """An ephemeral authentication session."""
    session_id: str
    auth_type: str           # "form", "bearer", "cookie", "basic"
    origin: str              # locked to this origin (scheme + host + port)
    created_at: float        # monotonic time
    expires_at: float        # monotonic time
    ttl_minutes: int

    # Auth data (NEVER serialized or logged)
    _cookies: dict = field(default_factory=dict, repr=False)
    _headers: dict = field(default_factory=dict, repr=False)
    _bearer_token: str = field(default="", repr=False)

    @property
    def is_expired(self) -> bool:
        return time.monotonic() > self.expires_at

    @property
    def remaining_seconds(self) -> float:
        return max(0, self.expires_at - time.monotonic())

    def matches_origin(self, url: str) -> bool:
        """Check if a URL matches this session's locked origin."""
        parsed = urlparse(url)
        target_origin = f"{parsed.scheme}://{parsed.netloc}"
        return target_origin == self.origin or self.origin == "*"

    def get_headers(self) -> dict[str, str]:
        """Get auth headers to inject into requests. Never include raw credentials in logs."""
        headers = dict(self._headers)
        if self._bearer_token:
            headers["Authorization"] = f"Bearer {self._bearer_token}"
        return headers

    def get_cookies(self) -> dict[str, str]:
        """Get cookies to inject into requests."""
        return dict(self._cookies)


class SessionManager:
    """Manages ephemeral auth sessions. Singleton per MCP process.

    Safety controls:
    - Sessions stored in memory-only dict
    - Auto-cleanup of expired sessions on every access
    - Origin locking prevents credential leakage to wrong domains
    - No serialization/persistence methods exist (by design)
    - __repr__ and __str__ never expose credentials
    """

    def __init__(self):
        self._sessions: dict[str, AuthSession] = {}
        self._lock = asyncio.Lock()

    async def create_session(
        self,
        auth_type: str,
        origin: str,
        ttl_minutes: int = 30,
        bearer_token: str = "",
        cookies: dict = None,
        headers: dict = None,
    ) -> AuthSession:
        """Create a new ephemeral auth session.

        Args:
            auth_type: "bearer", "cookie", "basic", "form"
            origin: Origin to lock session to (e.g., "https://localhost:3000")
            ttl_minutes: Session lifetime (default 30, max 120)
            bearer_token: Bearer/API token
            cookies: Dict of cookie name->value
            headers: Dict of custom auth headers

        Returns:
            AuthSession with session_id for reference
        """
        async with self._lock:
            self._cleanup_expired()

            ttl_minutes = max(1, min(120, ttl_minutes))
            now = time.monotonic()

            session = AuthSession(
                session_id=str(uuid.uuid4())[:12],
                auth_type=auth_type,
                origin=origin,
                created_at=now,
                expires_at=now + (ttl_minutes * 60),
                ttl_minutes=ttl_minutes,
                _bearer_token=bearer_token,
                _cookies=cookies or {},
                _headers=headers or {},
            )

            self._sessions[session.session_id] = session
            return session

    async def get_session(self, session_id: str) -> Optional[AuthSession]:
        """Get a session by ID. Returns None if expired or not found."""
        async with self._lock:
            self._cleanup_expired()
            session = self._sessions.get(session_id)
            if session and not session.is_expired:
                return session
            return None

    async def destroy_session(self, session_id: str) -> bool:
        """Immediately destroy a session, wiping credentials from memory."""
        async with self._lock:
            if session_id in self._sessions:
                session = self._sessions.pop(session_id)
                # Explicitly clear sensitive data
                session._bearer_token = ""
                session._cookies.clear()
                session._headers.clear()
                return True
            return False

    async def destroy_all(self) -> int:
        """Destroy all sessions. Called on MCP disconnect."""
        async with self._lock:
            count = len(self._sessions)
            for session in self._sessions.values():
                session._bearer_token = ""
                session._cookies.clear()
                session._headers.clear()
            self._sessions.clear()
            return count

    async def list_sessions(self) -> list[dict]:
        """List active sessions (metadata only, never credentials)."""
        async with self._lock:
            self._cleanup_expired()
            return [
                {
                    "session_id": s.session_id,
                    "auth_type": s.auth_type,
                    "origin": s.origin,
                    "ttl_minutes": s.ttl_minutes,
                    "remaining_seconds": int(s.remaining_seconds),
                    "expired": s.is_expired,
                }
                for s in self._sessions.values()
            ]

    def _cleanup_expired(self) -> None:
        """Remove expired sessions. Called internally on every access."""
        expired = [sid for sid, s in self._sessions.items() if s.is_expired]
        for sid in expired:
            session = self._sessions.pop(sid)
            session._bearer_token = ""
            session._cookies.clear()
            session._headers.clear()


# Module-level singleton
_session_manager: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    """Get or create the singleton session manager."""
    global _session_manager
    if _session_manager is None:
        _session_manager = SessionManager()
    return _session_manager
