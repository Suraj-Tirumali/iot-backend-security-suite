"""
ISVS Section 4 — Error Disclosure
====================================
Tests that error responses do not leak internal implementation details.
Compares secure vs vulnerable endpoint behavior.
"""

import pytest
import httpx

BASE_URL = "http://localhost:8000"


@pytest.mark.asyncio
async def test_secure_404_does_not_leak_internals():
    """
    ISVS 4.3 — 404 responses must not expose internal paths or stack traces.
    """
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        response = await client.get("/nonexistent/endpoint/path")
        assert response.status_code == 404
        body = response.text.lower()
        assert "traceback" not in body, (
            "404 response contains stack trace — ISVS 4.3 violated"
        )
        assert "sqlalchemy" not in body, (
            "404 response leaks SQLAlchemy internals — ISVS 4.3 violated"
        )


@pytest.mark.asyncio
async def test_secure_401_does_not_leak_internals():
    """
    ISVS 4.3 — Auth failures must not expose internal user data.
    """
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        response = await client.post(
            "/auth/login",
            json={"email": "test@example.com", "password": "wrongpassword1A"},
        )
        assert response.status_code == 401
        body = response.text.lower()
        assert "hashed_password" not in body, (
            "401 response leaks hashed password — ISVS 4.3 violated"
        )
        assert "traceback" not in body, (
            "401 response contains stack trace — ISVS 4.3 violated"
        )


@pytest.mark.asyncio
async def test_vulnerable_debug_endpoint_leaks_internals():
    """
    Confirms the vulnerable debug endpoint DOES leak internal details.
    This is the negative control — proves our framework detects disclosure.
    ISVS 4.3 VIOLATED by this endpoint intentionally.
    """
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        response = await client.get("/vulnerable/debug-info")
        assert response.status_code == 200
        data = response.json()
        assert "python_version" in data, (
            "Vulnerable endpoint did not expose python_version as expected"
        )
        assert "internal_note" in data, (
            "Vulnerable endpoint did not expose internal_note as expected"
        )


@pytest.mark.asyncio
async def test_secure_endpoint_error_format_is_consistent():
    """
    ISVS 4.3 — All error responses must follow a consistent format.
    Inconsistent formats help attackers fingerprint vulnerabilities.
    """
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        r1 = await client.post(
            "/auth/login",
            json={"email": "wrong@example.com", "password": "WrongPass1"},
        )
        r2 = await client.get("/auth/me")

        # Both should return JSON with a 'detail' key
        assert "detail" in r1.json(), (
            "Login error response missing 'detail' key"
        )
        assert "detail" in r2.json(), (
            "Auth error response missing 'detail' key"
        )