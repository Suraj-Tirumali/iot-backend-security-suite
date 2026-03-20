"""
Shared fixtures for all test modules.
"""

import asyncio
import pytest
import httpx


BASE_URL = "http://localhost:8000"

# Test credentials — registered once per session
TEST_EMAIL = "sectest@example.com"
TEST_PASSWORD = "SecTest1234"


@pytest.fixture(scope="session")
def event_loop():
    """Create a single event loop for the entire test session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def base_url() -> str:
    return BASE_URL


@pytest.fixture(scope="session")
async def registered_user(base_url: str) -> dict:
    """
    Register a test user once per session.
    If already registered, log in and return the token.
    """
    async with httpx.AsyncClient(base_url=base_url) as client:
        # Try to register
        response = await client.post(
            "/auth/register",
            json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
        )

        # Login regardless (handles already-registered case)
        login = await client.post(
            "/auth/login",
            json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
        )
        assert login.status_code == 200, f"Login failed: {login.text}"
        token = login.json()["access_token"]

        return {
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD,
            "token": token,
        }


@pytest.fixture(scope="session")
async def auth_headers(registered_user: dict) -> dict:
    """Return Authorization headers for authenticated requests."""
    return {"Authorization": f"Bearer {registered_user['token']}"}


@pytest.fixture(scope="session")
async def http_client(base_url: str):
    """Shared async HTTP client for the test session."""
    async with httpx.AsyncClient(base_url=base_url, timeout=15) as client:
        yield client