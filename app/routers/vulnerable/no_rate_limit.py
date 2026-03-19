"""
VULNERABLE ENDPOINTS — NO RATE LIMITING
========================================
These endpoints have no rate limiting, no throttling, and no
request size enforcement. They simulate IoT backend APIs that
are exposed to volumetric attacks.

ISVS 4.1 — Platform security controls tested here.
"""

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/vulnerable", tags=["vulnerable — no rate limit"])


class PingPayload(BaseModel):
    message: str


@router.get(
    "/ping",
    summary="[VULNERABLE] Unauthenticated endpoint with no rate limit",
)
async def unprotected_ping():
    """
    VULNERABILITY: No authentication, no rate limiting.
    Can be flooded with requests without any throttling.

    ISVS 4.1 VIOLATED — API endpoints must implement rate limiting
    to protect against denial of service.

    TEST TARGET: test_rate_limit_prober.py
    """
    return {"message": "pong", "protected": False}


@router.post(
    "/echo",
    summary="[VULNERABLE] Echo endpoint with no input size limit",
)
async def unprotected_echo(payload: PingPayload):
    """
    VULNERABILITY: No request size validation, no rate limiting.
    Accepts arbitrarily large payloads.

    ISVS 4.2 VIOLATED — Input validation must reject oversized payloads.

    TEST TARGET: test_input_validation.py
    """
    return {
        "echo": payload.message,
        "length": len(payload.message),
        "protected": False,
    }


@router.get(
    "/debug-info",
    summary="[VULNERABLE] Exposes internal debug information",
)
async def debug_info():
    """
    VULNERABILITY: Exposes internal stack information, environment
    details, and configuration hints in the response.

    ISVS 4.3 VIOLATED — Error responses must not disclose internal
    implementation details.

    TEST TARGET: test_error_disclosure.py
    """
    import sys
    import platform

    return {
        "python_version": sys.version,
        "platform": platform.platform(),
        "debug_mode": True,
        "internal_note": "Database at postgres:5432, admin user: iotuser",
        "warning": "This endpoint should never exist in production",
    }