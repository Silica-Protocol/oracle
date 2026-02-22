"""Oracle API client for E2E tests."""

from __future__ import annotations

import aiohttp
from typing import Any, Dict, Optional


class OracleClient:
    """Async HTTP client for the Oracle API."""

    def __init__(
        self,
        base_url: str,
        token: Optional[str] = None,
        timeout_seconds: float = 10.0,
    ):
        assert base_url, "Base URL must not be empty"
        assert base_url.startswith("http"), "Base URL must include scheme"

        self.base_url = base_url.rstrip("/")
        self.token = token
        self._timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> "OracleClient":
        await self.open()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    async def open(self) -> None:
        assert self._session is None, "Session already open"
        self._session = aiohttp.ClientSession(timeout=self._timeout)

    async def close(self) -> None:
        if self._session is None:
            return
        await self._session.close()
        self._session = None

    def _session_or_raise(self) -> aiohttp.ClientSession:
        assert self._session is not None, "Client session not initialized"
        assert not self._session.closed, "Client session closed"
        return self._session

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def _get(self, path: str) -> Dict[str, Any]:
        session = self._session_or_raise()
        async with session.get(
            f"{self.base_url}{path}",
            headers=self._headers(),
        ) as resp:
            resp.raise_for_status()
            return await resp.json()

    async def _post(self, path: str, data: Dict[str, Any]) -> Dict[str, Any]:
        session = self._session_or_raise()
        async with session.post(
            f"{self.base_url}{path}",
            json=data,
            headers=self._headers(),
        ) as resp:
            resp.raise_for_status()
            return await resp.json()

    async def _put(self, path: str, data: Dict[str, Any]) -> Dict[str, Any]:
        session = self._session_or_raise()
        async with session.put(
            f"{self.base_url}{path}",
            json=data,
            headers=self._headers(),
        ) as resp:
            resp.raise_for_status()
            return await resp.json()

    # Health endpoints

    async def health(self) -> bool:
        """Check if oracle is healthy."""
        session = self._session_or_raise()
        try:
            async with session.get(
                f"{self.base_url}/health",
                timeout=aiohttp.ClientTimeout(total=2),
            ) as resp:
                return resp.status == 200
        except aiohttp.ClientError:
            return False

    # Reputation endpoints

    async def get_reputation(self, user_id: str) -> Dict[str, Any]:
        """Get user reputation."""
        return await self._get(f"/reputation/{user_id}")

    async def get_slash_history(self, user_id: str) -> Dict[str, Any]:
        """Get user slash history."""
        return await self._get(f"/reputation/{user_id}/history")

    async def get_user_results(self, user_id: str) -> Dict[str, Any]:
        """Get user result history."""
        return await self._get(f"/reputation/{user_id}/results")

    async def get_thresholds(self) -> Dict[str, Any]:
        """Get current reputation thresholds."""
        return await self._get("/reputation/thresholds")

    async def update_thresholds(
        self,
        thresholds: Dict[str, Any],
        admin_api_key: str,
    ) -> Dict[str, Any]:
        """Update reputation thresholds (admin only)."""
        data = {**thresholds, "admin_api_key": admin_api_key}
        return await self._put("/reputation/thresholds", data)

    async def get_pending_reviews(self) -> Dict[str, Any]:
        """Get pending suspicious activity reviews."""
        return await self._get("/reputation/pending-reviews")

    async def resolve_activity(
        self,
        activity_id: str,
        decision: str,
        admin_api_key: str,
    ) -> Dict[str, Any]:
        """Resolve a suspicious activity."""
        return await self._post(
            f"/reputation/review/{activity_id}",
            {"decision": decision, "admin_api_key": admin_api_key},
        )

    async def get_stats(self) -> Dict[str, Any]:
        """Get overall stats."""
        return await self._get("/reputation/stats")

    # BOINC proxy endpoints

    async def get_boinc_master(self) -> str:
        """Get BOINC master file."""
        session = self._session_or_raise()
        async with session.get(f"{self.base_url}/boinc/") as resp:
            resp.raise_for_status()
            return await resp.text()

    # Oracle endpoints

    async def get_oracle_info(self) -> Dict[str, Any]:
        """Get oracle info."""
        return await self._get("/oracle/info")

    async def verify_work(self, work_data: Dict[str, Any]) -> Dict[str, Any]:
        """Submit work for verification."""
        return await self._post("/oracle/verify", work_data)
