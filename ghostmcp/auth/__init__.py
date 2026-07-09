"""Ephemeral session-scoped authentication for GhostMCP.

Provides memory-only credential storage with auto-expiry and origin locking.
Never persisted, logged, or sent to any external service.
"""

from .session_manager import AuthSession, SessionManager, get_session_manager
from .form_login import FormLoginResult, form_login

__all__ = [
    "AuthSession",
    "SessionManager",
    "get_session_manager",
    "FormLoginResult",
    "form_login",
]
