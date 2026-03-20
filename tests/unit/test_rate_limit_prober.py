"""
Unit tests for framework/runners/rate_limit_prober.py
Tests the prober logic and result structure in isolation.
"""

import pytest
from framework.runners.rate_limit_prober import ProbeResult, summarize
from framework.runners.brute_force import common_passwords, sequential_passwords


def test_probe_result_is_protected_when_rate_limited():
    """ProbeResult.is_protected must return True when rate_limited is True."""
    result = ProbeResult(
        endpoint="http://example.com/login",
        total_requests=20,
        rate_limited=True,
        rate_limit_triggered_at=5,
    )
    assert result.is_protected is True


def test_probe_result_is_not_protected_when_no_rate_limit():
    """ProbeResult.is_protected must return False when no rate limiting detected."""
    result = ProbeResult(
        endpoint="http://example.com/login",
        total_requests=20,
        rate_limited=False,
    )
    assert result.is_protected is False


def test_summarize_returns_expected_keys():
    """summarize() must return a complete, JSON-serializable dict."""
    result = ProbeResult(
        endpoint="http://example.com/login",
        total_requests=10,
        status_counts={401: 10},
        rate_limited=False,
        response_times=[0.1] * 10,
        issues=["No rate limiting detected"],
        passed=[],
    )
    summary = summarize(result)
    assert "endpoint" in summary
    assert "protected" in summary
    assert "total_requests" in summary
    assert "status_counts" in summary
    assert "rate_limited" in summary
    assert "avg_response_time" in summary
    assert "issues" in summary
    assert "passed" in summary


def test_summarize_avg_response_time_calculated():
    """avg_response_time must be correctly calculated."""
    result = ProbeResult(
        endpoint="http://example.com",
        total_requests=4,
        response_times=[0.1, 0.2, 0.3, 0.4],
    )
    summary = summarize(result)
    assert abs(summary["avg_response_time"] - 0.25) < 0.001


def test_summarize_empty_response_times():
    """summarize() must handle empty response_times without crashing."""
    result = ProbeResult(
        endpoint="http://example.com",
        total_requests=0,
        response_times=[],
    )
    summary = summarize(result)
    assert summary["avg_response_time"] == 0


def test_common_passwords_returns_correct_count():
    """common_passwords(limit=N) must return exactly N passwords."""
    passwords = common_passwords(limit=10)
    assert len(passwords) == 10


def test_common_passwords_default_limit():
    """common_passwords() default must return 50 passwords."""
    passwords = common_passwords()
    assert len(passwords) == 50


def test_sequential_passwords_format():
    """sequential_passwords must return zero-padded sequential strings."""
    passwords = sequential_passwords(prefix="test", count=5)
    assert passwords == ["test0000", "test0001", "test0002", "test0003", "test0004"]


def test_sequential_passwords_custom_prefix():
    """sequential_passwords must respect custom prefix."""
    passwords = sequential_passwords(prefix="admin", count=3)
    assert all(p.startswith("admin") for p in passwords)
    assert len(passwords) == 3