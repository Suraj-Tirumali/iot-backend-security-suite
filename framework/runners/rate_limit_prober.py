"""
Rate Limit Prober
=================
Probes an endpoint to detect whether rate limiting is enforced.
Used by ISVS Section 2.1 and Section 4 tests.
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class ProbeResult:
    endpoint: str
    total_requests: int
    status_counts: dict[int, int] = field(default_factory=dict)
    rate_limited: bool = False
    rate_limit_triggered_at: int | None = None
    response_times: list[float] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    passed: list[str] = field(default_factory=list)

    @property
    def is_protected(self) -> bool:
        return self.rate_limited


async def probe_rate_limit(
    url: str,
    method: str = "GET",
    payload: dict | None = None,
    headers: dict | None = None,
    num_requests: int = 20,
    concurrency: int = 5,
    timeout: int = 10,
) -> ProbeResult:
    """
    Send multiple requests to an endpoint and check for rate limiting.

    Rate limiting is detected when:
    - HTTP 429 Too Many Requests is returned
    - HTTP 503 Service Unavailable is returned
    - Response times increase significantly (throttling)

    ISVS 2.1.2 — Brute force protection must be present on auth endpoints.
    ISVS 4.1   — API endpoints must implement rate limiting.
    """
    result = ProbeResult(endpoint=url, total_requests=num_requests)

    semaphore = asyncio.Semaphore(concurrency)

    async def single_request(client: httpx.AsyncClient, index: int) -> tuple[int, float]:
        async with semaphore:
            start = time.monotonic()
            try:
                if method.upper() == "POST":
                    response = await client.post(
                        url, json=payload, headers=headers, timeout=timeout
                    )
                else:
                    response = await client.get(
                        url, headers=headers, timeout=timeout
                    )
                elapsed = time.monotonic() - start
                return response.status_code, elapsed
            except httpx.TimeoutException:
                return 408, time.monotonic() - start
            except Exception:
                return 500, time.monotonic() - start

    async with httpx.AsyncClient() as client:
        tasks = [single_request(client, i) for i in range(num_requests)]
        responses = await asyncio.gather(*tasks)

    for index, (status_code, elapsed) in enumerate(responses):
        result.status_counts[status_code] = (
            result.status_counts.get(status_code, 0) + 1
        )
        result.response_times.append(elapsed)

        if status_code in (429, 503) and not result.rate_limited:
            result.rate_limited = True
            result.rate_limit_triggered_at = index + 1

    # Evaluate results
    if result.rate_limited:
        result.passed.append(
            f"Rate limiting detected after {result.rate_limit_triggered_at} requests "
            f"(HTTP {429 if 429 in result.status_counts else 503})"
        )
    else:
        result.issues.append(
            f"No rate limiting detected after {num_requests} requests — "
            f"ISVS 2.1.2 / 4.1 violated"
        )

    # Check for response time throttling (soft rate limiting)
    if len(result.response_times) > 5:
        avg_first_5 = sum(result.response_times[:5]) / 5
        avg_last_5 = sum(result.response_times[-5:]) / 5
        if avg_last_5 > avg_first_5 * 3:
            result.passed.append(
                "Response time throttling detected — server is slowing down requests"
            )

    return result


async def probe_brute_force(
    url: str,
    email: str,
    passwords: list[str],
    concurrency: int = 3,
    timeout: int = 10,
) -> ProbeResult:
    """
    Simulate a brute force attack against a login endpoint.
    Checks whether the endpoint locks out or rate limits after failures.

    ISVS 2.1.2 — Must lock or throttle after repeated failed attempts.
    """
    result = ProbeResult(endpoint=url, total_requests=len(passwords))

    semaphore = asyncio.Semaphore(concurrency)

    async def attempt(client: httpx.AsyncClient, password: str, index: int):
        async with semaphore:
            start = time.monotonic()
            try:
                response = await client.post(
                    url,
                    json={"email": email, "password": password},
                    timeout=timeout,
                )
                elapsed = time.monotonic() - start
                return response.status_code, elapsed
            except Exception:
                return 500, time.monotonic() - start

    async with httpx.AsyncClient() as client:
        tasks = [attempt(client, pw, i) for i, pw in enumerate(passwords)]
        responses = await asyncio.gather(*tasks)

    for index, (status_code, elapsed) in enumerate(responses):
        result.status_counts[status_code] = (
            result.status_counts.get(status_code, 0) + 1
        )
        result.response_times.append(elapsed)

        if status_code in (429, 423, 503) and not result.rate_limited:
            result.rate_limited = True
            result.rate_limit_triggered_at = index + 1

    if result.rate_limited:
        result.passed.append(
            f"Brute force protection triggered after "
            f"{result.rate_limit_triggered_at} attempts"
        )
    else:
        result.issues.append(
            f"No brute force protection detected after {len(passwords)} attempts — "
            f"ISVS 2.1.2 violated"
        )

    return result


def summarize(result: ProbeResult) -> dict[str, Any]:
    """Return a JSON-serializable summary."""
    return {
        "endpoint": result.endpoint,
        "protected": result.is_protected,
        "total_requests": result.total_requests,
        "status_counts": result.status_counts,
        "rate_limited": result.rate_limited,
        "rate_limit_triggered_at": result.rate_limit_triggered_at,
        "avg_response_time": (
            sum(result.response_times) / len(result.response_times)
            if result.response_times else 0
        ),
        "issues": result.issues,
        "passed": result.passed,
    }