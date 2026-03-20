"""
ISVS Section 4 — Input Validation
====================================
Tests that the API correctly validates and rejects malformed input.
"""

import pytest
import httpx

BASE_URL = "http://localhost:8000"


@pytest.mark.asyncio
async def test_oversized_payload_handled():
    """
    ISVS 4.2 — The API should handle oversized payloads gracefully.
    The vulnerable echo endpoint accepts any size — confirm it does not crash.
    The secure endpoints should reject or limit large payloads.
    """
    large_message = "A" * 100_000

    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        response = await client.post(
            "/vulnerable/echo",
            json={"message": large_message},
            timeout=15,
        )
        # Should not return 500 — graceful handling required
        assert response.status_code != 500, (
            "Server returned 500 on oversized payload — ISVS 4.2 violated"
        )


@pytest.mark.asyncio
async def test_invalid_json_returns_422():
    """
    ISVS 4.2 — Invalid request bodies must return 422, not 500.
    A 500 on bad input indicates missing input validation.
    """
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        response = await client.post(
            "/auth/login",
            content=b"not-valid-json",
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 422, (
            f"Invalid JSON returned {response.status_code} — expected 422"
        )


@pytest.mark.asyncio
async def test_missing_required_fields_returns_422():
    """
    ISVS 4.2 — Requests missing required fields must return 422.
    """
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        response = await client.post(
            "/auth/login",
            json={"email": "test@example.com"},  # missing password
        )
        assert response.status_code == 422, (
            f"Missing field returned {response.status_code} — expected 422"
        )


@pytest.mark.asyncio
async def test_invalid_email_format_rejected():
    """
    ISVS 4.2 — Invalid email format must be rejected at registration.
    """
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        response = await client.post(
            "/auth/register",
            json={"email": "not-an-email", "password": "ValidPass1"},
        )
        assert response.status_code == 422, (
            f"Invalid email accepted: {response.status_code}"
        )


@pytest.mark.asyncio
async def test_sql_injection_attempt_handled():
    """
    ISVS 4.2 — SQL injection attempts must not cause 500 errors.
    SQLAlchemy parameterized queries should prevent injection.
    """
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        response = await client.post(
            "/auth/login",
            json={
                "email": "' OR '1'='1",
                "password": "' OR '1'='1",
            },
        )
        assert response.status_code in (401, 422), (
            f"SQL injection attempt returned {response.status_code} — "
            "expected 401 or 422"
        )
        assert response.status_code != 500, (
            "SQL injection caused a 500 error — possible injection vulnerability"
        )