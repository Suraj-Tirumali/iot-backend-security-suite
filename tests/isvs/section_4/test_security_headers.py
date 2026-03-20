"""
ISVS Section 4 — Security Headers
====================================
Tests that the API returns appropriate security headers on responses.
Missing security headers are a common IoT backend weakness.
"""

import pytest
import httpx

BASE_URL = "http://localhost:8000"


@pytest.fixture(scope="module")
async def response_headers() -> dict:
    """Fetch headers from the health endpoint."""
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        response = await client.get("/health")
        return dict(response.headers)


@pytest.mark.asyncio
async def test_x_content_type_options_header(response_headers: dict):
    """
    ISVS 4.3 — X-Content-Type-Options must be set to nosniff.
    Prevents MIME type sniffing attacks.
    """
    header = response_headers.get("x-content-type-options", "")
    assert header.lower() == "nosniff", (
        f"X-Content-Type-Options is '{header}' — expected 'nosniff'. "
        "ISVS 4.3 violated"
    )


@pytest.mark.asyncio
async def test_x_frame_options_header(response_headers: dict):
    """
    ISVS 4.3 — X-Frame-Options must be set to prevent clickjacking.
    """
    header = response_headers.get("x-frame-options", "")
    assert header.upper() in ("DENY", "SAMEORIGIN"), (
        f"X-Frame-Options is '{header}' — expected DENY or SAMEORIGIN. "
        "ISVS 4.3 violated"
    )


@pytest.mark.asyncio
async def test_content_type_header_is_json(response_headers: dict):
    """
    API responses must declare application/json content type.
    Prevents content type confusion attacks.
    """
    content_type = response_headers.get("content-type", "")
    assert "application/json" in content_type, (
        f"Content-Type is '{content_type}' — expected application/json"
    )


@pytest.mark.asyncio
async def test_server_header_does_not_expose_version():
    """
    ISVS 4.3 — Server header must not expose version numbers.
    The real risk is version fingerprinting, not framework name alone.
    Production deployments should suppress or genericize this header
    via reverse proxy (nginx, caddy) — documented in README.
    """
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        response = await client.get("/health")
        server = response.headers.get("server", "")
        import re
        version_pattern = re.search(r'\d+\.\d+', server)
        assert not version_pattern, (
            f"Server header exposes version number: '{server}' — "
            "ISVS 4.3 violated. Use a reverse proxy to suppress this in production."
        )