"""Tests for CAPTCHA Layer 3 — API solver fallback client.

Tests the CapSolver and 2Captcha integration with mocked HTTP responses.
All tests use mocked httpx to avoid hitting real APIs.
"""

from __future__ import annotations

import asyncio
import datetime
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ghostmcp.captcha.api_solver import (
    APISolveResult,
    BudgetState,
    CaptchaAPISolver,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_response(json_data: dict, status_code: int = 200) -> MagicMock:
    """Create a mock httpx Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data
    return resp


# ---------------------------------------------------------------------------
# TestAPISolverInit
# ---------------------------------------------------------------------------


class TestAPISolverInit:
    """Test solver initialization and configuration."""

    def test_explicit_config(self):
        solver = CaptchaAPISolver(api_key="test-key", service="capsolver")
        assert solver.api_key == "test-key"
        assert solver.service == "capsolver"
        assert solver.available is True

    def test_env_var_config(self, monkeypatch):
        monkeypatch.setenv("GHOST_CAPTCHA_KEY", "env-key-123")
        monkeypatch.setenv("GHOST_CAPTCHA_SERVICE", "2captcha")
        solver = CaptchaAPISolver()
        assert solver.api_key == "env-key-123"
        assert solver.service == "2captcha"
        assert solver.available is True

    def test_no_key_not_available(self, monkeypatch):
        monkeypatch.delenv("GHOST_CAPTCHA_KEY", raising=False)
        solver = CaptchaAPISolver(api_key="", service="capsolver")
        assert solver.available is False

    def test_invalid_service_not_available(self):
        solver = CaptchaAPISolver(api_key="key", service="unknown_service")
        assert solver.available is False

    def test_default_service_is_capsolver(self, monkeypatch):
        monkeypatch.delenv("GHOST_CAPTCHA_SERVICE", raising=False)
        solver = CaptchaAPISolver(api_key="key")
        assert solver.service == "capsolver"

    def test_budget_defaults(self):
        solver = CaptchaAPISolver(api_key="key", service="capsolver")
        assert solver.daily_budget == 0.0
        assert solver.monthly_budget == 5.0

    def test_custom_budget(self):
        solver = CaptchaAPISolver(
            api_key="key",
            service="capsolver",
            daily_budget_usd=1.0,
            monthly_budget_usd=10.0,
        )
        assert solver.daily_budget == 1.0
        assert solver.monthly_budget == 10.0


# ---------------------------------------------------------------------------
# TestBudgetControls
# ---------------------------------------------------------------------------


class TestBudgetControls:
    """Test daily/monthly budget enforcement."""

    def test_within_budget_initially(self):
        solver = CaptchaAPISolver(
            api_key="key", service="capsolver",
            daily_budget_usd=1.0, monthly_budget_usd=5.0,
        )
        assert solver.within_budget is True

    def test_daily_budget_exceeded(self):
        solver = CaptchaAPISolver(
            api_key="key", service="capsolver",
            daily_budget_usd=0.01, monthly_budget_usd=5.0,
        )
        # Manually set budget state
        now = datetime.datetime.now()
        solver.budget.last_reset_day = now.day
        solver.budget.last_reset_month = now.month
        solver.budget.daily_spent_usd = 0.02
        assert solver.within_budget is False

    def test_monthly_budget_exceeded(self):
        solver = CaptchaAPISolver(
            api_key="key", service="capsolver",
            daily_budget_usd=0.0, monthly_budget_usd=0.005,
        )
        now = datetime.datetime.now()
        solver.budget.last_reset_day = now.day
        solver.budget.last_reset_month = now.month
        solver.budget.monthly_spent_usd = 0.01
        assert solver.within_budget is False

    def test_unlimited_daily_allows_spending(self):
        solver = CaptchaAPISolver(
            api_key="key", service="capsolver",
            daily_budget_usd=0.0, monthly_budget_usd=5.0,
        )
        now = datetime.datetime.now()
        solver.budget.last_reset_day = now.day
        solver.budget.last_reset_month = now.month
        solver.budget.daily_spent_usd = 100.0  # Huge spend
        # daily_budget=0 means no daily limit, only monthly matters
        assert solver.within_budget is True

    def test_daily_reset_on_new_day(self):
        solver = CaptchaAPISolver(
            api_key="key", service="capsolver",
            daily_budget_usd=0.01, monthly_budget_usd=5.0,
        )
        # Set state for yesterday
        now = datetime.datetime.now()
        yesterday_day = (now - datetime.timedelta(days=1)).day
        solver.budget.last_reset_day = yesterday_day
        solver.budget.last_reset_month = now.month
        solver.budget.daily_spent_usd = 999.0
        solver.budget.daily_solves = 500
        # Accessing within_budget triggers _maybe_reset_counters
        assert solver.within_budget is True
        assert solver.budget.daily_spent_usd == 0.0
        assert solver.budget.daily_solves == 0

    def test_monthly_reset_on_new_month(self):
        solver = CaptchaAPISolver(
            api_key="key", service="capsolver",
            daily_budget_usd=0.0, monthly_budget_usd=0.005,
        )
        now = datetime.datetime.now()
        # Simulate last month (different month number)
        old_month = (now.month - 1) if now.month > 1 else 12
        solver.budget.last_reset_day = now.day
        solver.budget.last_reset_month = old_month
        solver.budget.monthly_spent_usd = 999.0
        solver.budget.monthly_solves = 1000
        assert solver.within_budget is True
        assert solver.budget.monthly_spent_usd == 0.0
        assert solver.budget.monthly_solves == 0


# ---------------------------------------------------------------------------
# TestCapSolverRecaptcha
# ---------------------------------------------------------------------------


class TestCapSolverRecaptcha:
    """Test CapSolver reCAPTCHA v2 solving."""

    @pytest.mark.asyncio
    async def test_success(self):
        solver = CaptchaAPISolver(api_key="test-key", service="capsolver")

        create_resp = make_response({"errorId": 0, "taskId": "task-123"})
        poll_resp = make_response({
            "status": "ready",
            "solution": {"gRecaptchaResponse": "token-abc-xyz"},
        })

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=[create_resp, poll_resp])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            result = await solver.solve_recaptcha_v2("site-key", "https://example.com")

        assert result.success is True
        assert result.solution == "token-abc-xyz"
        assert result.task_id == "task-123"
        assert result.service == "capsolver"
        assert result.latency_ms >= 0

    @pytest.mark.asyncio
    async def test_create_error(self):
        solver = CaptchaAPISolver(api_key="test-key", service="capsolver")

        create_resp = make_response({
            "errorId": 1,
            "errorDescription": "Invalid API key",
        })

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=create_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            result = await solver.solve_recaptcha_v2("site-key", "https://example.com")

        assert result.success is False
        assert "Invalid API key" in result.error

    @pytest.mark.asyncio
    async def test_no_task_id_returned(self):
        solver = CaptchaAPISolver(api_key="test-key", service="capsolver")

        create_resp = make_response({"errorId": 0, "taskId": ""})

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=create_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            result = await solver.solve_recaptcha_v2("site-key", "https://example.com")

        assert result.success is False
        assert "no task ID" in result.error

    @pytest.mark.asyncio
    async def test_poll_error(self):
        solver = CaptchaAPISolver(api_key="test-key", service="capsolver")

        create_resp = make_response({"errorId": 0, "taskId": "task-456"})
        poll_resp = make_response({
            "errorId": 12,
            "errorDescription": "Task expired",
        })

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=[create_resp, poll_resp])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            result = await solver.solve_recaptcha_v2("site-key", "https://example.com")

        assert result.success is False
        assert "Task expired" in result.error
        assert result.task_id == "task-456"

    @pytest.mark.asyncio
    async def test_timeout_after_max_polls(self):
        solver = CaptchaAPISolver(api_key="test-key", service="capsolver")

        create_resp = make_response({"errorId": 0, "taskId": "task-789"})
        # Always return "processing" — never ready
        processing_resp = make_response({"status": "processing", "errorId": 0})

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=[create_resp] + [processing_resp] * 60)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            result = await solver.solve_recaptcha_v2("site-key", "https://example.com")

        assert result.success is False
        assert "timeout" in result.error
        assert result.task_id == "task-789"

    @pytest.mark.asyncio
    async def test_http_timeout_exception(self):
        solver = CaptchaAPISolver(api_key="test-key", service="capsolver")

        import httpx as httpx_mod
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx_mod.TimeoutException("timed out"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            result = await solver.solve_recaptcha_v2("site-key", "https://example.com")

        assert result.success is False
        assert "timeout" in result.error.lower()

    @pytest.mark.asyncio
    async def test_not_configured(self):
        solver = CaptchaAPISolver(api_key="", service="capsolver")
        result = await solver.solve_recaptcha_v2("site-key", "https://example.com")
        assert result.success is False
        assert "not configured" in result.error

    @pytest.mark.asyncio
    async def test_budget_exceeded(self):
        solver = CaptchaAPISolver(
            api_key="key", service="capsolver",
            daily_budget_usd=0.001, monthly_budget_usd=5.0,
        )
        now = datetime.datetime.now()
        solver.budget.last_reset_day = now.day
        solver.budget.last_reset_month = now.month
        solver.budget.daily_spent_usd = 0.01

        result = await solver.solve_recaptcha_v2("site-key", "https://example.com")
        assert result.success is False
        assert "Budget exceeded" in result.error


# ---------------------------------------------------------------------------
# TestCapSolverImage
# ---------------------------------------------------------------------------


class TestCapSolverImage:
    """Test CapSolver image grid solving."""

    @pytest.mark.asyncio
    async def test_success(self):
        solver = CaptchaAPISolver(api_key="test-key", service="capsolver")

        create_resp = make_response({"errorId": 0, "taskId": "img-task-1"})
        poll_resp = make_response({
            "status": "ready",
            "solution": {"text": "1,3,5,7"},
        })

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=[create_resp, poll_resp])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            result = await solver.solve_image_grid("base64data==", "Select traffic lights")

        assert result.success is True
        assert result.solution == "1,3,5,7"
        assert result.task_id == "img-task-1"
        assert result.service == "capsolver"

    @pytest.mark.asyncio
    async def test_create_error(self):
        solver = CaptchaAPISolver(api_key="test-key", service="capsolver")

        create_resp = make_response({
            "errorId": 1,
            "errorDescription": "Insufficient balance",
        })

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=create_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            result = await solver.solve_image_grid("base64data==", "Select buses")

        assert result.success is False
        assert "Insufficient balance" in result.error

    @pytest.mark.asyncio
    async def test_poll_timeout(self):
        solver = CaptchaAPISolver(api_key="test-key", service="capsolver")

        create_resp = make_response({"errorId": 0, "taskId": "img-task-2"})
        processing_resp = make_response({"status": "processing", "errorId": 0})

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=[create_resp] + [processing_resp] * 30)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            result = await solver.solve_image_grid("base64data==", "Select crosswalks")

        assert result.success is False
        assert "timeout" in result.error.lower()

    @pytest.mark.asyncio
    async def test_exception_handling(self):
        solver = CaptchaAPISolver(api_key="test-key", service="capsolver")

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=RuntimeError("connection reset"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            result = await solver.solve_image_grid("base64data==", "Select fire hydrants")

        assert result.success is False
        assert "connection reset" in result.error


# ---------------------------------------------------------------------------
# Test2CaptchaRecaptcha
# ---------------------------------------------------------------------------


class Test2CaptchaRecaptcha:
    """Test 2Captcha reCAPTCHA v2 solving."""

    @pytest.mark.asyncio
    async def test_success(self):
        solver = CaptchaAPISolver(api_key="2cap-key", service="2captcha")

        create_resp = make_response({"status": 1, "request": "req-id-abc"})
        ready_resp = make_response({"status": 1, "request": "solved-token-xyz"})

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[create_resp, ready_resp])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            result = await solver.solve_recaptcha_v2("site-key", "https://example.com")

        assert result.success is True
        assert result.solution == "solved-token-xyz"
        assert result.task_id == "req-id-abc"
        assert result.service == "2captcha"

    @pytest.mark.asyncio
    async def test_create_error(self):
        solver = CaptchaAPISolver(api_key="2cap-key", service="2captcha")

        create_resp = make_response({"status": 0, "request": "ERROR_WRONG_USER_KEY"})

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=create_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            result = await solver.solve_recaptcha_v2("site-key", "https://example.com")

        assert result.success is False
        assert "ERROR_WRONG_USER_KEY" in result.error

    @pytest.mark.asyncio
    async def test_polling_with_not_ready(self):
        solver = CaptchaAPISolver(api_key="2cap-key", service="2captcha")

        create_resp = make_response({"status": 1, "request": "req-id-wait"})
        not_ready_resp = make_response({"status": 0, "request": "CAPCHA_NOT_READY"})
        ready_resp = make_response({"status": 1, "request": "final-token"})

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[create_resp, not_ready_resp, not_ready_resp, ready_resp])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            result = await solver.solve_recaptcha_v2("site-key", "https://example.com")

        assert result.success is True
        assert result.solution == "final-token"

    @pytest.mark.asyncio
    async def test_poll_error_response(self):
        solver = CaptchaAPISolver(api_key="2cap-key", service="2captcha")

        create_resp = make_response({"status": 1, "request": "req-err"})
        error_resp = make_response({"status": 0, "request": "ERROR_CAPTCHA_UNSOLVABLE"})

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[create_resp, error_resp])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            result = await solver.solve_recaptcha_v2("site-key", "https://example.com")

        assert result.success is False
        assert "ERROR_CAPTCHA_UNSOLVABLE" in result.error

    @pytest.mark.asyncio
    async def test_timeout(self):
        solver = CaptchaAPISolver(api_key="2cap-key", service="2captcha")

        create_resp = make_response({"status": 1, "request": "req-timeout"})
        not_ready_resp = make_response({"status": 0, "request": "CAPCHA_NOT_READY"})

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[create_resp] + [not_ready_resp] * 60)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            result = await solver.solve_recaptcha_v2("site-key", "https://example.com")

        assert result.success is False
        assert "timeout" in result.error.lower()

    @pytest.mark.asyncio
    async def test_exception(self):
        solver = CaptchaAPISolver(api_key="2cap-key", service="2captcha")

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=ConnectionError("network down"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            result = await solver.solve_recaptcha_v2("site-key", "https://example.com")

        assert result.success is False
        assert "network down" in result.error


# ---------------------------------------------------------------------------
# Test2CaptchaImage
# ---------------------------------------------------------------------------


class Test2CaptchaImage:
    """Test 2Captcha image grid solving."""

    @pytest.mark.asyncio
    async def test_success(self):
        solver = CaptchaAPISolver(api_key="2cap-key", service="2captcha")

        create_resp = make_response({"status": 1, "request": "img-req-1"})
        ready_resp = make_response({"status": 1, "request": "click:2/4/6"})

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=create_resp)
        mock_client.get = AsyncMock(return_value=ready_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            result = await solver.solve_image_grid("base64img==", "Select bicycles")

        assert result.success is True
        assert result.solution == "click:2/4/6"
        assert result.task_id == "img-req-1"
        assert result.service == "2captcha"

    @pytest.mark.asyncio
    async def test_create_error(self):
        solver = CaptchaAPISolver(api_key="2cap-key", service="2captcha")

        create_resp = make_response({"status": 0, "request": "ERROR_ZERO_BALANCE"})

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=create_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            result = await solver.solve_image_grid("base64img==", "Select motorcycles")

        assert result.success is False
        assert "ERROR_ZERO_BALANCE" in result.error

    @pytest.mark.asyncio
    async def test_polling_not_ready_then_success(self):
        solver = CaptchaAPISolver(api_key="2cap-key", service="2captcha")

        create_resp = make_response({"status": 1, "request": "img-req-2"})
        not_ready_resp = make_response({"status": 0, "request": "CAPCHA_NOT_READY"})
        ready_resp = make_response({"status": 1, "request": "click:1/5"})

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=create_resp)
        mock_client.get = AsyncMock(side_effect=[not_ready_resp, not_ready_resp, ready_resp])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            result = await solver.solve_image_grid("base64img==", "Select stairs")

        assert result.success is True
        assert result.solution == "click:1/5"

    @pytest.mark.asyncio
    async def test_timeout(self):
        solver = CaptchaAPISolver(api_key="2cap-key", service="2captcha")

        create_resp = make_response({"status": 1, "request": "img-req-timeout"})
        not_ready_resp = make_response({"status": 0, "request": "CAPCHA_NOT_READY"})

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=create_resp)
        mock_client.get = AsyncMock(return_value=not_ready_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            result = await solver.solve_image_grid("base64img==", "Select palm trees")

        assert result.success is False
        assert "timeout" in result.error.lower()

    @pytest.mark.asyncio
    async def test_exception(self):
        solver = CaptchaAPISolver(api_key="2cap-key", service="2captcha")

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=OSError("socket closed"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            result = await solver.solve_image_grid("base64img==", "Select taxis")

        assert result.success is False
        assert "socket closed" in result.error


# ---------------------------------------------------------------------------
# TestBudgetTracking
# ---------------------------------------------------------------------------


class TestBudgetTracking:
    """Test that budget is tracked correctly on success/failure."""

    @pytest.mark.asyncio
    async def test_cost_incremented_on_success(self):
        solver = CaptchaAPISolver(api_key="key", service="capsolver")

        create_resp = make_response({"errorId": 0, "taskId": "t1"})
        poll_resp = make_response({
            "status": "ready",
            "solution": {"gRecaptchaResponse": "token"},
        })

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=[create_resp, poll_resp])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            result = await solver.solve_recaptcha_v2("sk", "https://test.com")

        assert result.success is True
        assert result.cost_usd == 0.002
        assert solver.budget.daily_spent_usd == 0.002
        assert solver.budget.monthly_spent_usd == 0.002
        assert solver.budget.daily_solves == 1
        assert solver.budget.monthly_solves == 1

    @pytest.mark.asyncio
    async def test_cost_not_incremented_on_failure(self):
        solver = CaptchaAPISolver(api_key="key", service="capsolver")

        create_resp = make_response({"errorId": 1, "errorDescription": "fail"})

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=create_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            result = await solver.solve_recaptcha_v2("sk", "https://test.com")

        assert result.success is False
        assert result.cost_usd == 0.0
        assert solver.budget.daily_spent_usd == 0.0
        assert solver.budget.monthly_spent_usd == 0.0
        assert solver.budget.daily_solves == 0

    @pytest.mark.asyncio
    async def test_multiple_solves_accumulate(self):
        solver = CaptchaAPISolver(api_key="key", service="2captcha")

        create_resp = make_response({"status": 1, "request": "req-1"})
        ready_resp = make_response({"status": 1, "request": "token"})

        for i in range(3):
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=[create_resp, ready_resp])
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)

            with patch("httpx.AsyncClient", return_value=mock_client), \
                 patch("asyncio.sleep", new_callable=AsyncMock):
                await solver.solve_recaptcha_v2("sk", "https://test.com")

        assert solver.budget.daily_solves == 3
        assert solver.budget.monthly_solves == 3
        assert abs(solver.budget.daily_spent_usd - 0.009) < 1e-9
        assert abs(solver.budget.monthly_spent_usd - 0.009) < 1e-9

    @pytest.mark.asyncio
    async def test_image_grid_cost_tracking(self):
        solver = CaptchaAPISolver(api_key="key", service="capsolver")

        create_resp = make_response({"errorId": 0, "taskId": "img-t1"})
        poll_resp = make_response({
            "status": "ready",
            "solution": {"text": "0,2,4"},
        })

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=[create_resp, poll_resp])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client), \
             patch("asyncio.sleep", new_callable=AsyncMock):
            result = await solver.solve_image_grid("img==", "Select boats")

        assert result.success is True
        assert result.cost_usd == 0.002
        assert solver.budget.daily_solves == 1


# ---------------------------------------------------------------------------
# TestGetBudgetStatus
# ---------------------------------------------------------------------------


class TestGetBudgetStatus:
    """Test the get_budget_status() method."""

    def test_status_structure(self):
        solver = CaptchaAPISolver(api_key="key", service="capsolver", monthly_budget_usd=10.0)
        status = solver.get_budget_status()

        assert status["service"] == "capsolver"
        assert status["configured"] is True
        assert status["within_budget"] is True
        assert "daily_spent" in status
        assert "daily_limit" in status
        assert "daily_solves" in status
        assert "monthly_spent" in status
        assert "monthly_limit" in status
        assert "monthly_solves" in status

    def test_status_unconfigured(self):
        solver = CaptchaAPISolver(api_key="", service="capsolver")
        status = solver.get_budget_status()
        assert status["configured"] is False

    def test_status_daily_unlimited(self):
        solver = CaptchaAPISolver(api_key="key", service="capsolver", daily_budget_usd=0.0)
        status = solver.get_budget_status()
        assert status["daily_limit"] == "unlimited"

    def test_status_with_daily_limit(self):
        solver = CaptchaAPISolver(api_key="key", service="capsolver", daily_budget_usd=2.0)
        status = solver.get_budget_status()
        assert status["daily_limit"] == "$2.00"

    def test_status_reflects_spending(self):
        solver = CaptchaAPISolver(api_key="key", service="capsolver", monthly_budget_usd=5.0)
        now = datetime.datetime.now()
        solver.budget.last_reset_day = now.day
        solver.budget.last_reset_month = now.month
        solver.budget.daily_spent_usd = 0.123
        solver.budget.daily_solves = 50
        solver.budget.monthly_spent_usd = 1.456
        solver.budget.monthly_solves = 600

        status = solver.get_budget_status()
        assert status["daily_spent"] == "$0.123"
        assert status["daily_solves"] == 50
        assert status["monthly_spent"] == "$1.456"
        assert status["monthly_solves"] == 600
        assert status["monthly_limit"] == "$5.00"

    def test_status_over_budget(self):
        solver = CaptchaAPISolver(
            api_key="key", service="capsolver",
            daily_budget_usd=0.01, monthly_budget_usd=5.0,
        )
        now = datetime.datetime.now()
        solver.budget.last_reset_day = now.day
        solver.budget.last_reset_month = now.month
        solver.budget.daily_spent_usd = 0.05

        status = solver.get_budget_status()
        assert status["within_budget"] is False


# ---------------------------------------------------------------------------
# TestUnknownService
# ---------------------------------------------------------------------------


class TestUnknownService:
    """Test behavior with an unknown service name that passes available check."""

    @pytest.mark.asyncio
    async def test_unknown_service_recaptcha(self):
        # Force an invalid service but with a key, bypass available check
        solver = CaptchaAPISolver(api_key="key", service="capsolver")
        solver.service = "badservice"
        # available will be False because badservice not in SERVICES
        result = await solver.solve_recaptcha_v2("sk", "https://test.com")
        assert result.success is False
        assert "not configured" in result.error

    @pytest.mark.asyncio
    async def test_unknown_service_image(self):
        solver = CaptchaAPISolver(api_key="key", service="capsolver")
        solver.service = "badservice"
        result = await solver.solve_image_grid("img==", "Select cats")
        assert result.success is False
        assert "not configured" in result.error
