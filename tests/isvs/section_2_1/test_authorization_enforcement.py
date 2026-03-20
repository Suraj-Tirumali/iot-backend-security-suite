"""
ISVS 2.1.1 — Authorization Enforcement
========================================
Tests that protected endpoints enforce authentication and
that users cannot access other users' resources (BOLA).
"""

import pytest
import httpx

BASE_URL = "http://localhost:8000"
TEST_EMAIL = "sectest@example.com"
TEST_PASSWORD = "SecTest1234"


@pytest.fixture(scope="module")
async def token() -> str:
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        # Ensure user exists
        await client.post(
            "/auth/register",
            json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
        )
        response = await client.post(
            "/auth/login",
            json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
        )
        assert response.status_code == 200, f"Login failed: {response.text}"
        return response.json()["access_token"]


@pytest.mark.asyncio
async def test_devices_endpoint_requires_auth():
    """ISVS 2.1.1 — Device list endpoint must reject unauthenticated requests."""
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        response = await client.get("/devices")
        assert response.status_code in (401, 403), (
            f"Devices endpoint returned {response.status_code} without auth — "
            "ISVS 2.1.1 violated"
        )


@pytest.mark.asyncio
async def test_me_endpoint_requires_auth():
    """ISVS 2.1.1 — /auth/me must reject unauthenticated requests."""
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        response = await client.get("/auth/me")
        assert response.status_code in (401, 403), (
            f"/auth/me returned {response.status_code} without auth"
        )


@pytest.mark.asyncio
async def test_telemetry_endpoint_requires_auth():
    """ISVS 2.1.1 — Telemetry submission must require authentication."""
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        response = await client.post(
            "/devices/sensor-001/telemetry",
            json={"payload": {"temp": 23}},
        )
        assert response.status_code in (401, 403), (
            f"Telemetry endpoint returned {response.status_code} without auth"
        )


@pytest.mark.asyncio
async def test_vulnerable_bola_exposes_any_user(token: str):
    """
    ISVS 2.1.1 — Confirms the vulnerable endpoint has BOLA.
    Any caller can retrieve any user's data by guessing user IDs.
    """
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        response = await client.get("/vulnerable/user-info/1")
        assert response.status_code == 200, (
            "Vulnerable BOLA endpoint did not return user data"
        )
        data = response.json()
        assert "hashed_password" in data, (
            "Vulnerable endpoint did not expose hashed_password as expected"
        )


@pytest.mark.asyncio
async def test_secure_endpoint_does_not_expose_other_users(token: str):
    """
    ISVS 2.1.1 — /auth/me only returns the authenticated user's own data.
    """
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        response = await client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == TEST_EMAIL, (
            "Secure endpoint returned wrong user's data"
        )
        assert "hashed_password" not in data, (
            "Secure endpoint exposed hashed_password in response"
        )