"""
Cookie Analyzer
===============
Inspects HTTP response cookies for ISVS 2.1 and Section 6 compliance.
Checks Secure, HttpOnly, SameSite flags and cookie attributes.
"""

from dataclasses import dataclass, field
from http.cookiejar import CookieJar
from typing import Any


@dataclass
class CookieAnalysisResult:
    name: str
    value: str
    flags: dict = field(default_factory=dict)
    issues: list[str] = field(default_factory=list)
    passed: list[str] = field(default_factory=list)

    @property
    def is_secure(self) -> bool:
        return len(self.issues) == 0


def analyze_cookie(
    name: str,
    value: str,
    secure: bool = False,
    http_only: bool = False,
    same_site: str | None = None,
    domain: str | None = None,
    path: str | None = None,
    max_age: int | None = None,
) -> CookieAnalysisResult:
    """
    Analyze a single cookie for ISVS compliance.

    Checks performed:
    - Secure flag (ISVS 6.1 — must be set for HTTPS)
    - HttpOnly flag (ISVS 2.1 — prevents XSS token theft)
    - SameSite attribute (CSRF protection)
    - Max-Age / Expiry (session lifetime)
    """
    result = CookieAnalysisResult(
        name=name,
        value=value,
        flags={
            "secure": secure,
            "http_only": http_only,
            "same_site": same_site,
            "domain": domain,
            "path": path,
            "max_age": max_age,
        },
    )

    # Check Secure flag
    if not secure:
        result.issues.append(
            "CRITICAL [ISVS 6.1]: Secure flag not set — "
            "cookie transmitted over HTTP"
        )
    else:
        result.passed.append("Secure flag is set")

    # Check HttpOnly flag
    if not http_only:
        result.issues.append(
            "WARNING [ISVS 2.1]: HttpOnly flag not set — "
            "cookie accessible via JavaScript (XSS risk)"
        )
    else:
        result.passed.append("HttpOnly flag is set")

    # Check SameSite
    if not same_site:
        result.issues.append(
            "WARNING: SameSite attribute not set — "
            "CSRF protection may be insufficient"
        )
    elif same_site.lower() == "none" and not secure:
        result.issues.append(
            "CRITICAL: SameSite=None requires Secure flag"
        )
    elif same_site.lower() in ("strict", "lax"):
        result.passed.append(f"SameSite={same_site} is set")
    else:
        result.issues.append(
            f"WARNING: SameSite={same_site} — review if appropriate"
        )

    # Check session lifetime
    if max_age is not None and max_age > 86400 * 7:
        result.issues.append(
            f"WARNING [ISVS 2.1]: Cookie max-age is {max_age}s "
            f"({max_age // 86400} days) — consider shorter session lifetime"
        )
    elif max_age is not None:
        result.passed.append(f"Cookie max-age is reasonable: {max_age}s")

    return result


def analyze_response_cookies(headers: dict) -> list[CookieAnalysisResult]:
    """
    Parse and analyze all Set-Cookie headers from an HTTP response.
    Accepts a dict of response headers.
    """
    results = []
    set_cookie_headers = []

    for key, value in headers.items():
        if key.lower() == "set-cookie":
            if isinstance(value, list):
                set_cookie_headers.extend(value)
            else:
                set_cookie_headers.append(value)

    for cookie_str in set_cookie_headers:
        parts = [p.strip() for p in cookie_str.split(";")]
        if not parts:
            continue

        name_value = parts[0].split("=", 1)
        if len(name_value) != 2:
            continue

        name, value = name_value
        attrs = {p.split("=")[0].lower(): p.split("=")[1] if "=" in p else True
                 for p in parts[1:]}

        result = analyze_cookie(
            name=name,
            value=value,
            secure="secure" in attrs,
            http_only="httponly" in attrs,
            same_site=attrs.get("samesite") if isinstance(attrs.get("samesite"), str) else None,
            domain=attrs.get("domain") if isinstance(attrs.get("domain"), str) else None,
            path=attrs.get("path") if isinstance(attrs.get("path"), str) else None,
            max_age=int(attrs["max-age"]) if "max-age" in attrs and isinstance(attrs["max-age"], str) else None,
        )
        results.append(result)

    return results


def summarize(result: CookieAnalysisResult) -> dict[str, Any]:
    """Return a JSON-serializable summary."""
    return {
        "name": result.name,
        "secure": result.is_secure,
        "flags": result.flags,
        "issues": result.issues,
        "passed": result.passed,
    }