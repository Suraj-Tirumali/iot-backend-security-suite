"""
Unit tests for framework/analyzers/cookie_analyzer.py
Tests cookie security flag analysis in isolation.
"""

import pytest
from framework.analyzers.cookie_analyzer import (
    analyze_cookie,
    analyze_response_cookies,
    summarize,
)


def test_secure_cookie_passes_all_checks():
    """A properly configured cookie should have no issues."""
    result = analyze_cookie(
        name="session",
        value="abc123",
        secure=True,
        http_only=True,
        same_site="Strict",
        max_age=3600,
    )
    assert result.is_secure
    assert len(result.issues) == 0


def test_missing_secure_flag_flagged():
    """Cookie without Secure flag must be flagged."""
    result = analyze_cookie(
        name="session",
        value="abc123",
        secure=False,
        http_only=True,
        same_site="Strict",
    )
    assert not result.is_secure
    issues = " ".join(result.issues)
    assert "secure" in issues.lower()


def test_missing_httponly_flag_flagged():
    """Cookie without HttpOnly flag must be flagged."""
    result = analyze_cookie(
        name="session",
        value="abc123",
        secure=True,
        http_only=False,
        same_site="Strict",
    )
    assert not result.is_secure
    issues = " ".join(result.issues)
    assert "httponly" in issues.lower()


def test_missing_samesite_flagged():
    """Cookie without SameSite attribute must be flagged."""
    result = analyze_cookie(
        name="session",
        value="abc123",
        secure=True,
        http_only=True,
        same_site=None,
    )
    assert not result.is_secure
    issues = " ".join(result.issues)
    assert "samesite" in issues.lower()


def test_samesite_none_without_secure_flagged():
    """SameSite=None without Secure flag is a critical misconfiguration."""
    result = analyze_cookie(
        name="session",
        value="abc123",
        secure=False,
        http_only=True,
        same_site="None",
    )
    assert not result.is_secure
    issues = " ".join(result.issues)
    assert "samesite=none requires secure" in issues.lower()


def test_long_max_age_flagged():
    """Cookie with max-age longer than 7 days must be flagged."""
    result = analyze_cookie(
        name="session",
        value="abc123",
        secure=True,
        http_only=True,
        same_site="Strict",
        max_age=86400 * 30,  # 30 days
    )
    assert not result.is_secure
    issues = " ".join(result.issues)
    assert "max-age" in issues.lower()


def test_analyze_response_cookies_parses_set_cookie_header():
    """analyze_response_cookies must parse Set-Cookie headers correctly."""
    headers = {
        "set-cookie": "session=abc123; HttpOnly; Secure; SameSite=Strict; Max-Age=3600"
    }
    results = analyze_response_cookies(headers)
    assert len(results) == 1
    assert results[0].name == "session"
    assert results[0].flags["secure"] is True
    assert results[0].flags["http_only"] is True


def test_summarize_returns_expected_keys():
    """summarize() must return expected keys."""
    result = analyze_cookie(
        name="test",
        value="val",
        secure=True,
        http_only=True,
        same_site="Lax",
    )
    summary = summarize(result)
    assert "name" in summary
    assert "secure" in summary
    assert "flags" in summary
    assert "issues" in summary
    assert "passed" in summary