"""
Unit tests for framework/analyzers/jwt_analyzer.py
Tests the analyzer logic in isolation — no running server needed.
"""

import time
import pytest
from jose import jwt

from framework.analyzers.jwt_analyzer import analyze_jwt, summarize


SECRET = "test-secret-key"
ALGORITHM = "HS256"


def make_token(payload: dict, secret: str = SECRET, algorithm: str = ALGORITHM) -> str:
    return jwt.encode(payload, secret, algorithm=algorithm)


def test_valid_token_passes_all_checks():
    """A well-formed token should have no issues."""
    token = make_token({
        "sub": "user@example.com",
        "exp": int(time.time()) + 1800,
        "type": "access",
    })
    result = analyze_jwt(token)
    assert result.is_secure
    assert len(result.issues) == 0


def test_detects_missing_expiry():
    """Token without exp claim must be flagged."""
    token = make_token({
        "sub": "user@example.com",
        "type": "access",
    })
    result = analyze_jwt(token)
    assert not result.is_secure
    issues = " ".join(result.issues)
    assert "expiry" in issues.lower() or "exp" in issues.lower()


def test_detects_unreasonably_long_expiry():
    """Token expiring in 2099 must be flagged."""
    token = make_token({
        "sub": "user@example.com",
        "exp": 4102444800,  # year 2099
        "type": "access",
    })
    result = analyze_jwt(token)
    assert not result.is_secure
    issues = " ".join(result.issues)
    assert "unreasonably far" in issues


def test_detects_missing_subject():
    """Token without sub claim must be flagged."""
    token = make_token({
        "exp": int(time.time()) + 1800,
        "type": "access",
    })
    result = analyze_jwt(token)
    assert not result.is_secure
    issues = " ".join(result.issues)
    assert "subject" in issues.lower() or "sub" in issues.lower()


def test_detects_missing_type_claim():
    """Token without type claim must be flagged."""
    token = make_token({
        "sub": "user@example.com",
        "exp": int(time.time()) + 1800,
    })
    result = analyze_jwt(token)
    issues = " ".join(result.issues)
    assert "type" in issues.lower()


def test_detects_invalid_jwt_structure():
    """Malformed token string must return critical issue."""
    result = analyze_jwt("not.a.valid.jwt.string")
    assert not result.is_secure
    issues = " ".join(result.issues)
    assert "not a valid" in issues.lower() or "failed" in issues.lower() or "invalid" in issues.lower()


def test_summarize_returns_expected_keys():
    """summarize() must return a JSON-serializable dict with expected keys."""
    token = make_token({
        "sub": "user@example.com",
        "exp": int(time.time()) + 1800,
        "type": "access",
    })
    result = analyze_jwt(token)
    summary = summarize(result)
    assert "secure" in summary
    assert "algorithm" in summary
    assert "subject" in summary
    assert "issues" in summary
    assert "passed" in summary


def test_algorithm_hs256_passes():
    """HS256 algorithm must be accepted."""
    token = make_token({
        "sub": "user@example.com",
        "exp": int(time.time()) + 1800,
        "type": "access",
    })
    result = analyze_jwt(token)
    assert result.header.get("alg") == "HS256"
    alg_issues = [i for i in result.issues if "algorithm" in i.lower()]
    assert len(alg_issues) == 0


def test_already_expired_token_flagged():
    """Expired token must be noted in issues."""
    token = make_token({
        "sub": "user@example.com",
        "exp": int(time.time()) - 3600,  # expired 1 hour ago
        "type": "access",
    })
    result = analyze_jwt(token)
    issues = " ".join(result.issues)
    assert "expired" in issues.lower()