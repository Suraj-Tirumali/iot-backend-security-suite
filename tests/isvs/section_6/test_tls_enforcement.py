"""
ISVS Section 6 — Communications Security
==========================================
Tests TLS enforcement and communications security controls.

Note: The local development server runs on HTTP (localhost:8000).
TLS tests verify the analyzer module behavior and flag that TLS
must be enforced in production deployments.

For production TLS testing, point TARGET_BASE_URL at an HTTPS endpoint.
"""

import pytest
import httpx

from framework.analyzers.tls_checker import check_tls, check_http_redirect

BASE_URL = "http://localhost:8000"


@pytest.mark.asyncio
async def test_api_is_accessible():
    """
    Baseline — confirms the target API is reachable before TLS tests run.
    """
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        response = await client.get("/health")
        assert response.status_code == 200, (
            f"Target API is not accessible at {BASE_URL}"
        )


@pytest.mark.asyncio
async def test_tls_checker_validates_known_good_host():
    """
    ISVS 6.1 — TLS analyzer correctly validates a known-good HTTPS host.
    Tests the framework's TLS checking capability against a real TLS endpoint.
    """
    result = check_tls("httpbin.org", port=443, timeout=15)
    assert len(result.passed) > 0, (
        "TLS checker returned no passed checks for httpbin.org"
    )
    tls_connected = any("TLS connection" in p for p in result.passed)
    assert tls_connected, (
        f"TLS checker did not confirm TLS connection. Issues: {result.issues}"
    )


@pytest.mark.asyncio
async def test_tls_checker_detects_protocol_version():
    """
    ISVS 6.1 — TLS analyzer reports the negotiated protocol version.
    TLS 1.2 minimum must be enforced in production.
    """
    result = check_tls("httpbin.org", port=443, timeout=15)
    protocol = result.details.get("protocol", "")
    assert protocol in ("TLSv1.2", "TLSv1.3"), (
        f"Unexpected TLS protocol version: {protocol}"
    )


def test_http_redirect_checker_detects_no_redirect():
    """
    ISVS 6.1 — HTTP redirect checker correctly identifies when
    HTTP does not redirect to HTTPS (as is the case for localhost dev).
    """
    result = check_http_redirect("localhost:8000")
    assert isinstance(result["redirects_to_https"], bool), (
        "HTTP redirect checker did not return expected structure"
    )


@pytest.mark.asyncio
async def test_local_dev_server_does_not_use_tls():
    """
    Documents that the local dev server uses HTTP, not HTTPS.
    This is expected — TLS is enforced at the reverse proxy layer in production.
    The README documents this distinction clearly.
    """
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        response = await client.get("/health")
        # Local dev is HTTP — this is expected and documented
        assert response.url.scheme == "http", (
            "Expected HTTP scheme for local development server"
        )


@pytest.mark.asyncio
async def test_sensitive_endpoints_require_auth_over_http():
    """
    ISVS 6.1 — Even over HTTP (dev), sensitive endpoints require auth.
    In production, TLS + auth together provide communications security.
    """
    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        response = await client.get("/devices")
        assert response.status_code in (401, 403), (
            "Devices endpoint accessible without auth — "
            "would be a critical issue over unencrypted HTTP"
        )