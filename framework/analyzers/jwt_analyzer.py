"""
JWT Analyzer
============
Inspects JWT tokens for ISVS 2.1 security control compliance.
Does not require the secret key — analyzes the token structure
and claims only, as an attacker or auditor would.
"""

import base64
import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class JWTAnalysisResult:
    token: str
    header: dict = field(default_factory=dict)
    payload: dict = field(default_factory=dict)
    issues: list[str] = field(default_factory=list)
    passed: list[str] = field(default_factory=list)

    @property
    def is_secure(self) -> bool:
        return len(self.issues) == 0


def _decode_segment(segment: str) -> dict:
    """Decode a base64url-encoded JWT segment without verification."""
    # Add padding if needed
    padding = 4 - len(segment) % 4
    if padding != 4:
        segment += "=" * padding
    decoded = base64.urlsafe_b64decode(segment)
    return json.loads(decoded)


def analyze_jwt(token: str) -> JWTAnalysisResult:
    """
    Analyze a JWT token for ISVS 2.1 compliance issues.

    Checks performed:
    - Algorithm is not 'none' (ISVS 2.1.4)
    - Algorithm is HS256 or RS256, not weak variants
    - Token has an expiry claim (ISVS 2.1.3)
    - Expiry is not unreasonably far in the future
    - Token has a subject claim
    - Token type claim is present
    """
    result = JWTAnalysisResult(token=token)

    parts = token.split(".")
    if len(parts) != 3:
        result.issues.append("CRITICAL: Token is not a valid JWT structure")
        return result

    try:
        result.header = _decode_segment(parts[0])
        result.payload = _decode_segment(parts[1])
    except Exception as e:
        result.issues.append(f"CRITICAL: Failed to decode JWT segments: {e}")
        return result

    # Check algorithm
    alg = result.header.get("alg", "").upper()
    if not alg or alg == "NONE":
        result.issues.append(
            "CRITICAL [ISVS 2.1.4]: Algorithm is 'none' — token is unsigned"
        )
    elif alg in ("HS256", "RS256", "ES256"):
        result.passed.append(f"Algorithm is acceptable: {alg}")
    else:
        result.issues.append(
            f"WARNING [ISVS 2.1.4]: Weak or unexpected algorithm: {alg}"
        )

    # Check expiry
    import time

    exp = result.payload.get("exp")
    if not exp:
        result.issues.append(
            "CRITICAL [ISVS 2.1.3]: Token has no expiry (exp) claim"
        )
    else:
        now = time.time()
        seconds_until_expiry = exp - now
        days_until_expiry = seconds_until_expiry / 86400

        if seconds_until_expiry < 0:
            result.issues.append("INFO: Token is already expired")
        elif days_until_expiry > 30:
            result.issues.append(
                f"WARNING [ISVS 2.1.3]: Token expiry is unreasonably far: "
                f"{days_until_expiry:.0f} days from now"
            )
        else:
            result.passed.append(
                f"Token expiry is reasonable: {seconds_until_expiry:.0f}s from now"
            )

    # Check subject
    if not result.payload.get("sub"):
        result.issues.append(
            "WARNING [ISVS 2.1.1]: Token has no subject (sub) claim"
        )
    else:
        result.passed.append(f"Subject claim present: {result.payload['sub']}")

    # Check token type
    if not result.payload.get("type"):
        result.issues.append(
            "WARNING: Token has no type claim — "
            "reset tokens could be used as access tokens"
        )
    else:
        result.passed.append(f"Token type claim present: {result.payload['type']}")

    return result


def summarize(result: JWTAnalysisResult) -> dict[str, Any]:
    """Return a JSON-serializable summary of the analysis."""
    return {
        "secure": result.is_secure,
        "algorithm": result.header.get("alg"),
        "subject": result.payload.get("sub"),
        "token_type": result.payload.get("type"),
        "expires_at": result.payload.get("exp"),
        "issues": result.issues,
        "passed": result.passed,
    }