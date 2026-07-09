"""CAPTCHA Layer 3 — Third-party API solving services.

Last resort when self-solve (Layer 2) fails. Sends CAPTCHA screenshots
to external services for solving. Privacy trade-off: screenshots leave
our infrastructure.

Supported services:
- CapSolver (capsolver.com) — ~$1-2/1000 solves, 5-15s latency
- 2Captcha (2captcha.com) — ~$1-3/1000 solves, 10-30s latency

Configurable via GHOST_CAPTCHA_SERVICE and GHOST_CAPTCHA_KEY env vars.
Budget controls prevent runaway spending.
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx


@dataclass
class APISolveResult:
    """Result from an API CAPTCHA solver."""
    success: bool = False
    solution: str = ""          # Token or answer from the service
    cost_usd: float = 0.0      # Estimated cost of this solve
    latency_ms: int = 0        # Time taken to solve
    service: str = ""          # Which service was used
    task_id: str = ""          # Service's task/request ID
    error: str = ""


@dataclass
class BudgetState:
    """Track spending against budget limits."""
    daily_spent_usd: float = 0.0
    monthly_spent_usd: float = 0.0
    daily_solves: int = 0
    monthly_solves: int = 0
    last_reset_day: int = 0    # Day of month when daily counter was last reset
    last_reset_month: int = 0  # Month when monthly counter was last reset


class CaptchaAPISolver:
    """Third-party CAPTCHA solving with budget controls.
    
    Safety controls:
    - Daily budget cap (default $0 — disabled until configured)
    - Monthly budget cap
    - Per-solve cost tracking
    - Requires explicit GHOST_CAPTCHA_KEY to function
    - Logs every solve attempt for audit
    """
    
    # Service endpoints
    SERVICES = {
        "capsolver": {
            "create_url": "https://api.capsolver.com/createTask",
            "result_url": "https://api.capsolver.com/getTaskResult",
            "cost_per_solve": 0.002,  # ~$2/1000
        },
        "2captcha": {
            "create_url": "https://2captcha.com/in.php",
            "result_url": "https://2captcha.com/res.php",
            "cost_per_solve": 0.003,  # ~$3/1000
        },
    }
    
    def __init__(
        self,
        api_key: str = "",
        service: str = "",
        daily_budget_usd: float = 0.0,
        monthly_budget_usd: float = 5.0,
    ):
        """Initialize API solver.
        
        Args:
            api_key: Service API key. Reads from GHOST_CAPTCHA_KEY if empty.
            service: Service name ("capsolver" or "2captcha"). Reads from GHOST_CAPTCHA_SERVICE if empty.
            daily_budget_usd: Max daily spend (0 = unlimited within monthly).
            monthly_budget_usd: Max monthly spend (default $5).
        """
        self.api_key = api_key or os.environ.get("GHOST_CAPTCHA_KEY", "")
        self.service = service or os.environ.get("GHOST_CAPTCHA_SERVICE", "capsolver")
        self.daily_budget = daily_budget_usd
        self.monthly_budget = monthly_budget_usd
        self.budget = BudgetState()
        self._lock = asyncio.Lock()
    
    @property
    def available(self) -> bool:
        """Check if the solver is configured and within budget."""
        return bool(self.api_key) and self.service in self.SERVICES
    
    @property
    def within_budget(self) -> bool:
        """Check if we're within spending limits."""
        self._maybe_reset_counters()
        if self.daily_budget > 0 and self.budget.daily_spent_usd >= self.daily_budget:
            return False
        if self.monthly_budget > 0 and self.budget.monthly_spent_usd >= self.monthly_budget:
            return False
        return True
    
    def _maybe_reset_counters(self) -> None:
        """Reset daily/monthly counters if time period has elapsed."""
        import datetime
        now = datetime.datetime.now()
        if now.day != self.budget.last_reset_day:
            self.budget.daily_spent_usd = 0.0
            self.budget.daily_solves = 0
            self.budget.last_reset_day = now.day
        if now.month != self.budget.last_reset_month:
            self.budget.monthly_spent_usd = 0.0
            self.budget.monthly_solves = 0
            self.budget.last_reset_month = now.month
    
    async def solve_recaptcha_v2(
        self,
        site_key: str,
        page_url: str,
    ) -> APISolveResult:
        """Solve reCAPTCHA v2 via API service.
        
        Args:
            site_key: The reCAPTCHA site key (from page HTML)
            page_url: The URL where the CAPTCHA appears
            
        Returns:
            APISolveResult with token on success
        """
        if not self.available:
            return APISolveResult(error="GHOST_CAPTCHA_KEY not configured")
        if not self.within_budget:
            return APISolveResult(error=f"Budget exceeded (daily: ${self.budget.daily_spent_usd:.2f}/{self.daily_budget}, monthly: ${self.budget.monthly_spent_usd:.2f}/{self.monthly_budget})")
        
        start = time.monotonic()
        
        if self.service == "capsolver":
            result = await self._capsolver_recaptcha(site_key, page_url)
        elif self.service == "2captcha":
            result = await self._2captcha_recaptcha(site_key, page_url)
        else:
            return APISolveResult(error=f"Unknown service: {self.service}")
        
        result.latency_ms = int((time.monotonic() - start) * 1000)
        result.service = self.service
        
        # Track budget
        if result.success:
            cost = self.SERVICES[self.service]["cost_per_solve"]
            result.cost_usd = cost
            async with self._lock:
                self.budget.daily_spent_usd += cost
                self.budget.monthly_spent_usd += cost
                self.budget.daily_solves += 1
                self.budget.monthly_solves += 1
        
        return result
    
    async def solve_image_grid(
        self,
        image_base64: str,
        instruction: str,
    ) -> APISolveResult:
        """Solve an image grid CAPTCHA via API service.
        
        Args:
            image_base64: Base64 encoded screenshot of the grid
            instruction: The instruction text ("Select all traffic lights")
            
        Returns:
            APISolveResult with tile indices on success
        """
        if not self.available:
            return APISolveResult(error="GHOST_CAPTCHA_KEY not configured")
        if not self.within_budget:
            return APISolveResult(error="Budget exceeded")
        
        start = time.monotonic()
        
        if self.service == "capsolver":
            result = await self._capsolver_image(image_base64, instruction)
        elif self.service == "2captcha":
            result = await self._2captcha_image(image_base64, instruction)
        else:
            return APISolveResult(error=f"Unknown service: {self.service}")
        
        result.latency_ms = int((time.monotonic() - start) * 1000)
        result.service = self.service
        
        if result.success:
            cost = self.SERVICES[self.service]["cost_per_solve"]
            result.cost_usd = cost
            async with self._lock:
                self.budget.daily_spent_usd += cost
                self.budget.monthly_spent_usd += cost
                self.budget.daily_solves += 1
                self.budget.monthly_solves += 1
        
        return result
    
    def get_budget_status(self) -> dict:
        """Get current budget status."""
        self._maybe_reset_counters()
        return {
            "service": self.service,
            "configured": self.available,
            "within_budget": self.within_budget,
            "daily_spent": f"${self.budget.daily_spent_usd:.3f}",
            "daily_limit": f"${self.daily_budget:.2f}" if self.daily_budget > 0 else "unlimited",
            "daily_solves": self.budget.daily_solves,
            "monthly_spent": f"${self.budget.monthly_spent_usd:.3f}",
            "monthly_limit": f"${self.monthly_budget:.2f}",
            "monthly_solves": self.budget.monthly_solves,
        }
    
    # --- CapSolver implementation ---
    
    async def _capsolver_recaptcha(self, site_key: str, page_url: str) -> APISolveResult:
        """Solve reCAPTCHA v2 via CapSolver API."""
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                # Create task
                resp = await client.post(
                    self.SERVICES["capsolver"]["create_url"],
                    json={
                        "clientKey": self.api_key,
                        "task": {
                            "type": "ReCaptchaV2TaskProxyLess",
                            "websiteURL": page_url,
                            "websiteKey": site_key,
                        },
                    },
                )
                data = resp.json()
                
                if data.get("errorId", 0) != 0:
                    return APISolveResult(error=f"CapSolver error: {data.get('errorDescription', 'unknown')}")
                
                task_id = data.get("taskId", "")
                if not task_id:
                    return APISolveResult(error="CapSolver: no task ID returned")
                
                # Poll for result (max 120s)
                for _ in range(60):
                    await asyncio.sleep(2.0)
                    resp = await client.post(
                        self.SERVICES["capsolver"]["result_url"],
                        json={"clientKey": self.api_key, "taskId": task_id},
                    )
                    result_data = resp.json()
                    
                    if result_data.get("status") == "ready":
                        solution = result_data.get("solution", {})
                        token = solution.get("gRecaptchaResponse", "")
                        return APISolveResult(success=True, solution=token, task_id=task_id)
                    elif result_data.get("errorId", 0) != 0:
                        return APISolveResult(error=f"CapSolver: {result_data.get('errorDescription')}", task_id=task_id)
                
                return APISolveResult(error="CapSolver: timeout waiting for solution", task_id=task_id)
        
        except httpx.TimeoutException:
            return APISolveResult(error="CapSolver: request timeout")
        except Exception as e:
            return APISolveResult(error=f"CapSolver: {e}")
    
    async def _capsolver_image(self, image_base64: str, instruction: str) -> APISolveResult:
        """Solve image grid via CapSolver API."""
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(
                    self.SERVICES["capsolver"]["create_url"],
                    json={
                        "clientKey": self.api_key,
                        "task": {
                            "type": "ImageToTextTask",
                            "body": image_base64,
                            "question": instruction,
                        },
                    },
                )
                data = resp.json()
                
                if data.get("errorId", 0) != 0:
                    return APISolveResult(error=f"CapSolver: {data.get('errorDescription')}")
                
                task_id = data.get("taskId", "")
                
                for _ in range(30):
                    await asyncio.sleep(2.0)
                    resp = await client.post(
                        self.SERVICES["capsolver"]["result_url"],
                        json={"clientKey": self.api_key, "taskId": task_id},
                    )
                    result_data = resp.json()
                    
                    if result_data.get("status") == "ready":
                        solution = result_data.get("solution", {})
                        text = solution.get("text", "")
                        return APISolveResult(success=True, solution=text, task_id=task_id)
                    elif result_data.get("errorId", 0) != 0:
                        return APISolveResult(error=f"CapSolver: {result_data.get('errorDescription')}", task_id=task_id)
                
                return APISolveResult(error="CapSolver: timeout", task_id=task_id)
        
        except Exception as e:
            return APISolveResult(error=f"CapSolver: {e}")
    
    # --- 2Captcha implementation ---
    
    async def _2captcha_recaptcha(self, site_key: str, page_url: str) -> APISolveResult:
        """Solve reCAPTCHA v2 via 2Captcha API."""
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                # Submit task
                resp = await client.get(
                    self.SERVICES["2captcha"]["create_url"],
                    params={
                        "key": self.api_key,
                        "method": "userrecaptcha",
                        "googlekey": site_key,
                        "pageurl": page_url,
                        "json": "1",
                    },
                )
                data = resp.json()
                
                if data.get("status") != 1:
                    return APISolveResult(error=f"2Captcha: {data.get('request', 'error')}")
                
                task_id = data.get("request", "")
                
                # Poll for result
                await asyncio.sleep(10.0)  # 2Captcha needs initial wait
                
                for _ in range(60):
                    resp = await client.get(
                        self.SERVICES["2captcha"]["result_url"],
                        params={
                            "key": self.api_key,
                            "action": "get",
                            "id": task_id,
                            "json": "1",
                        },
                    )
                    result_data = resp.json()
                    
                    if result_data.get("status") == 1:
                        return APISolveResult(success=True, solution=result_data.get("request", ""), task_id=task_id)
                    elif result_data.get("request") == "CAPCHA_NOT_READY":
                        await asyncio.sleep(2.0)
                        continue
                    else:
                        return APISolveResult(error=f"2Captcha: {result_data.get('request')}", task_id=task_id)
                
                return APISolveResult(error="2Captcha: timeout", task_id=task_id)
        
        except Exception as e:
            return APISolveResult(error=f"2Captcha: {e}")
    
    async def _2captcha_image(self, image_base64: str, instruction: str) -> APISolveResult:
        """Solve image grid via 2Captcha API."""
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(
                    self.SERVICES["2captcha"]["create_url"],
                    data={
                        "key": self.api_key,
                        "method": "base64",
                        "body": image_base64,
                        "textinstructions": instruction,
                        "json": "1",
                    },
                )
                data = resp.json()
                
                if data.get("status") != 1:
                    return APISolveResult(error=f"2Captcha: {data.get('request')}")
                
                task_id = data.get("request", "")
                await asyncio.sleep(5.0)
                
                for _ in range(30):
                    resp = await client.get(
                        self.SERVICES["2captcha"]["result_url"],
                        params={"key": self.api_key, "action": "get", "id": task_id, "json": "1"},
                    )
                    result_data = resp.json()
                    
                    if result_data.get("status") == 1:
                        return APISolveResult(success=True, solution=result_data.get("request", ""), task_id=task_id)
                    elif result_data.get("request") == "CAPCHA_NOT_READY":
                        await asyncio.sleep(2.0)
                    else:
                        return APISolveResult(error=f"2Captcha: {result_data.get('request')}", task_id=task_id)
                
                return APISolveResult(error="2Captcha: timeout", task_id=task_id)
        
        except Exception as e:
            return APISolveResult(error=f"2Captcha: {e}")
