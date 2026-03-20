"""
ISVS 2.1.2 — Brute Force Protection
=====================================
Tests that login endpoints resist brute force attacks.
Compares behavior of secure vs vulnerable endpoints.
"""

import pytest
import httpx

from framework.runners.brute_force import common_passwords
from framework.runners.rate_limit_prober import probe_brute_force

BASE_URL = "http://localhost:8000"
TEST_EMAIL = "sectest@example.com"
TEST_PASSWORD = "SecTest1234"


@pytest.fixture(scope="module", autouse=True)
async def ensure_user_exists():
    """Ensure the test user exists before any test in this module runs."""
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        await client.post(
            "/auth/register",
            json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
        )


@pytest.mark.asyncio
async def test_secure_login_has_no_user_enumeration():
    """
    ISVS 2.1.5 — Same error must be returned for unknown email
    and wrong password to prevent user enumeration.
    """
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        wrong_pw = await client.post(
            "/auth/login",
            json={"email": TEST_EMAIL, "password": "WrongPass999"},
        )
        no_user = await client.post(
            "/auth/login",
            json={"email": "doesnotexist@example.com", "password": "WrongPass999"},
        )
        assert wrong_pw.status_code == no_user.status_code, (
            "Different status codes for wrong password vs unknown email — "
            "user enumeration possible. ISVS 2.1.5 violated"
        )
        assert wrong_pw.json().get("detail") == no_user.json().get("detail"), (
            "Different error messages — user enumeration possible. ISVS 2.1.5 violated"
        )


@pytest.mark.asyncio
async def test_vulnerable_endpoint_has_user_enumeration():
    """
    Confirms the vulnerable endpoint DOES expose user enumeration.
    Existing user gets 401 (wrong password), unknown user gets 404.
    """
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        wrong_pw = await client.post(
            "/vulnerable/login-no-lockout",
            json={"email": TEST_EMAIL, "password": "correct"},
        )
        no_user = await client.post(
            "/vulnerable/login-no-lockout",
            json={"email": "doesnotexist@example.com", "password": "correct"},
        )
        assert wrong_pw.status_code != no_user.status_code, (
            f"Vulnerable endpoint unexpectedly returns same status for both cases: "
            f"existing={wrong_pw.status_code} unknown={no_user.status_code}"
        )


@pytest.mark.asyncio
async def test_vulnerable_endpoint_has_no_brute_force_protection():
    """
    ISVS 2.1.2 — Confirms the vulnerable endpoint accepts unlimited
    login attempts without any rate limiting or lockout.
    """
    passwords = common_passwords(limit=15)
    result = await probe_brute_force(
        url=f"{BASE_URL}/vulnerable/login-no-lockout",
        email=TEST_EMAIL,
        passwords=passwords,
        concurrency=3,
    )
    assert not result.is_protected, (
        "Vulnerable endpoint unexpectedly has brute force protection"
    )
    assert result.status_counts.get(429) is None, (
        "Vulnerable endpoint returned 429 — unexpected rate limiting"
    )