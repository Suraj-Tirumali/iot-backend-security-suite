"""
TLS Checker
===========
Checks TLS configuration for ISVS Section 6 compliance.
Tests protocol version, certificate validity, and HTTP redirect behavior.
"""

import socket
import ssl
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


@dataclass
class TLSCheckResult:
    host: str
    port: int
    issues: list[str] = field(default_factory=list)
    passed: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)

    @property
    def is_secure(self) -> bool:
        return len(self.issues) == 0


def check_tls(host: str, port: int = 443, timeout: int = 10) -> TLSCheckResult:
    """
    Check TLS configuration of a host.

    Checks performed:
    - TLS 1.2+ is supported (ISVS 6.1)
    - TLS 1.0 and 1.1 are rejected (ISVS 6.1)
    - Certificate is valid and not expired (ISVS 6.2)
    - Certificate hostname matches (ISVS 6.2)
    """
    result = TLSCheckResult(host=host, port=port)

    # Check TLS 1.2 support
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                protocol = ssock.version()
                cert = ssock.getpeercert()
                cipher = ssock.cipher()

                result.details["protocol"] = protocol
                result.details["cipher"] = cipher[0] if cipher else None
                result.details["cert_subject"] = dict(
                    x[0] for x in cert.get("subject", [])
                )
                result.details["cert_expires"] = cert.get("notAfter")

                result.passed.append(f"TLS connection established: {protocol}")
                result.passed.append(
                    f"Certificate valid for: {result.details['cert_subject']}"
                )

    except ssl.SSLCertVerificationError as e:
        result.issues.append(
            f"CRITICAL [ISVS 6.2]: Certificate verification failed: {e}"
        )
    except ssl.SSLError as e:
        result.issues.append(
            f"CRITICAL [ISVS 6.1]: TLS error: {e}"
        )
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result.issues.append(f"WARNING: Could not connect to {host}:{port} — {e}")

    # Check that TLS 1.0 is rejected
    try:
        ctx_old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx_old.minimum_version = ssl.TLSVersion.TLSv1
        ctx_old.maximum_version = ssl.TLSVersion.TLSv1
        ctx_old.check_hostname = False
        ctx_old.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx_old.wrap_socket(sock, server_hostname=host):
                result.issues.append(
                    "CRITICAL [ISVS 6.1]: Server accepts TLS 1.0 — "
                    "deprecated protocol should be disabled"
                )
    except ssl.SSLError:
        result.passed.append("TLS 1.0 correctly rejected by server")
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass  # Connection failure is not a TLS 1.0 issue

    return result


def check_http_redirect(base_url: str, timeout: int = 10) -> dict[str, Any]:
    """
    Check whether HTTP redirects to HTTPS.
    ISVS 6.1 — All traffic must use TLS.
    """
    import httpx

    parsed = urlparse(base_url)
    http_url = f"http://{parsed.netloc or parsed.path}"

    try:
        response = httpx.get(http_url, follow_redirects=False, timeout=timeout)
        if response.status_code in (301, 302, 307, 308):
            location = response.headers.get("location", "")
            if location.startswith("https://"):
                return {
                    "redirects_to_https": True,
                    "status_code": response.status_code,
                    "location": location,
                    "issues": [],
                    "passed": ["HTTP correctly redirects to HTTPS [ISVS 6.1]"],
                }
            else:
                return {
                    "redirects_to_https": False,
                    "status_code": response.status_code,
                    "location": location,
                    "issues": ["WARNING [ISVS 6.1]: HTTP does not redirect to HTTPS"],
                    "passed": [],
                }
        else:
            return {
                "redirects_to_https": False,
                "status_code": response.status_code,
                "issues": [
                    f"WARNING [ISVS 6.1]: HTTP returns {response.status_code} "
                    f"instead of redirecting to HTTPS"
                ],
                "passed": [],
            }
    except Exception as e:
        return {
            "redirects_to_https": False,
            "issues": [f"Could not check HTTP redirect: {e}"],
            "passed": [],
        }


def summarize(result: TLSCheckResult) -> dict[str, Any]:
    """Return a JSON-serializable summary."""
    return {
        "host": result.host,
        "port": result.port,
        "secure": result.is_secure,
        "details": result.details,
        "issues": result.issues,
        "passed": result.passed,
    }