"""
ISVS 2.1 — JWT Controls
========================
Tests that JWT tokens issued by the API meet ISVS security requirements.
"""

import pytest
import httpx

from framework.analyzers.jwt_analyzer import analyze_jwt, summarize

BASE_URL = "http://localhost:8000"
TEST_EMAIL = "sectest@example.com"
TEST_PASSWORD = "SecTest1234"


@pytest.fixture(scope="module")
async def access_token() -> str:
    """Get a valid access token for JWT analysis."""
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
        assert response.status_code == 200
        return response.json()["access_token"]


@pytest.fixture(scope="module")
async def weak_token() -> str:
    """Get a weak JWT from the vulnerable endpoint."""
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        response = await client.post(
            "/vulnerable/login-weak-jwt",
            json={"email": TEST_EMAIL, "password": "anything"},
        )
        assert response.status_code == 200
        return response.json()["access_token"]


@pytest.mark.asyncio
async def test_secure_token_has_valid_algorithm(access_token: str):
    """
    ISVS 2.1.4 — Token algorithm must not be 'none' and must be a
    strong algorithm (HS256, RS256, or ES256).
    """
    result = analyze_jwt(access_token)
    alg = result.header.get("alg", "").upper()

    assert alg != "NONE", "CRITICAL: Token uses 'none' algorithm — unsigned"
    assert alg in ("HS256", "RS256", "ES256"), (
        f"Token uses unexpected algorithm: {alg}"
    )


@pytest.mark.asyncio
async def test_secure_token_has_expiry(access_token: str):
    """
    ISVS 2.1.3 — Access tokens must have an expiry claim (exp).
    """
    result = analyze_jwt(access_token)
    assert result.payload.get("exp") is not None, (
        "CRITICAL: Token has no expiry claim — ISVS 2.1.3 violated"
    )


@pytest.mark.asyncio
async def test_secure_token_expiry_is_reasonable(access_token: str):
    """
    ISVS 2.1.3 — Token expiry must not be unreasonably far in the future.
    Tokens valid for more than 24 hours are a security risk.
    """
    import time
    result = analyze_jwt(access_token)
    exp = result.payload.get("exp", 0)
    seconds_until_expiry = exp - time.time()

    assert seconds_until_expiry > 0, "Token is already expired"
    assert seconds_until_expiry <= 86400, (
        f"Token expiry is too long: {seconds_until_expiry / 3600:.1f} hours — "
        "ISVS 2.1.3 violated"
    )


@pytest.mark.asyncio
async def test_secure_token_has_subject_claim(access_token: str):
    """
    ISVS 2.1.1 — Token must identify the subject (user).
    """
    result = analyze_jwt(access_token)
    assert result.payload.get("sub"), (
        "Token missing subject (sub) claim"
    )


@pytest.mark.asyncio
async def test_secure_token_has_type_claim(access_token: str):
    """
    Token type claim prevents reset tokens being used as access tokens.
    """
    result = analyze_jwt(access_token)
    assert result.payload.get("type") == "access", (
        "Token missing or incorrect type claim"
    )


@pytest.mark.asyncio
async def test_weak_token_detected_as_insecure(weak_token: str):
    """
    Verifies the analyzer correctly flags the vulnerable endpoint's token.
    The weak token has an expiry year of 2099 — should be flagged.
    """
    result = analyze_jwt(weak_token)
    issue_text = " ".join(result.issues)
    assert "unreasonably far" in issue_text or "expiry" in issue_text.lower(), (
        "Analyzer failed to detect the unreasonably long token expiry"
    )


@pytest.mark.asyncio
async def test_tampered_token_rejected():
    """
    ISVS 2.1.4 — Tampered tokens must be rejected by the API.
    """
    # Take a valid token and corrupt the signature
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        login = await client.post(
            "/auth/login",
            json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
        )
        token = login.json()["access_token"]
        tampered = token[:-10] + "tampered!!"

        response = await client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {tampered}"},
        )
        assert response.status_code == 401, (
            "Tampered token was not rejected — ISVS 2.1.4 violated"
        )


@pytest.mark.asyncio
async def test_missing_token_rejected():
    """
    ISVS 2.1.1 — Requests without tokens must be rejected.
    """
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        response = await client.get("/auth/me")
        assert response.status_code == 403, (
            f"Expected 403 for missing token, got {response.status_code}"
        )