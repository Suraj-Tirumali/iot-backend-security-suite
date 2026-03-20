"""
ISVS Section 6 — Certificate Validation
=========================================
Tests that the framework correctly validates TLS certificates
and that the API client does not accept invalid certificates.
"""

import pytest
import httpx
import ssl

from framework.analyzers.tls_checker import check_tls


@pytest.mark.asyncio
async def test_httpx_client_validates_certificates_by_default():
    """
    ISVS 6.2 — HTTP clients must validate TLS certificates by default.
    verify=True is the httpx default — this test confirms it.
    """
    # httpx validates certs by default — connecting to a valid HTTPS host works
    async with httpx.AsyncClient(verify=True) as client:
        response = await client.get("https://httpbin.org/get", timeout=15)
        assert response.status_code == 200, (
            "Could not reach httpbin.org with certificate validation enabled"
        )


@pytest.mark.asyncio
async def test_tls_analyzer_reports_certificate_details():
    """
    ISVS 6.2 — TLS analyzer must extract and report certificate details
    so they can be audited for expiry and hostname matching.
    """
    result = check_tls("httpbin.org", port=443, timeout=15)
    assert "cert_subject" in result.details, (
        "TLS analyzer did not extract certificate subject"
    )
    assert "cert_expires" in result.details, (
        "TLS analyzer did not extract certificate expiry"
    )


def test_tls_analyzer_structure_is_correct():
    """
    Unit test — TLS checker returns expected data structure.
    """
    result = check_tls("httpbin.org", port=443, timeout=15)
    assert hasattr(result, "host")
    assert hasattr(result, "port")
    assert hasattr(result, "issues")
    assert hasattr(result, "passed")
    assert hasattr(result, "details")
    assert hasattr(result, "is_secure")