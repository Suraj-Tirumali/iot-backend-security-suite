"""
JSON Reporter
=============
Generates structured JSON test output for ISVS security test runs.
Output files are saved to reports/json/ and committed as artifacts.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPORTS_DIR = Path(__file__).parent.parent.parent / "reports" / "json"


def build_report(
    test_suite: str,
    isvs_section: str,
    results: list[dict[str, Any]],
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Build a structured report dict from test results.

    Args:
        test_suite: Name of the test suite (e.g. "ISVS 2.1 Authentication")
        isvs_section: Section reference (e.g. "2.1")
        results: List of individual test result dicts
        metadata: Optional additional context
    """
    total = len(results)
    passed = sum(1 for r in results if r.get("passed", False))
    failed = total - passed

    return {
        "report": {
            "test_suite": test_suite,
            "isvs_section": isvs_section,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total": total,
                "passed": passed,
                "failed": failed,
                "pass_rate": f"{(passed / total * 100):.1f}%" if total > 0 else "0%",
            },
            "metadata": metadata or {},
            "results": results,
        }
    }


def save_report(report: dict[str, Any], filename: str) -> Path:
    """
    Save a report dict to reports/json/<filename>.
    Creates the directory if it doesn't exist.
    Returns the path to the saved file.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    output_path = REPORTS_DIR / filename

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    return output_path


def load_report(filename: str) -> dict[str, Any]:
    """Load a previously saved report."""
    path = REPORTS_DIR / filename
    with open(path) as f:
        return json.load(f)


def print_summary(report: dict[str, Any]) -> None:
    """Print a human-readable summary to stdout."""
    r = report["report"]
    summary = r["summary"]
    print(f"\n{'=' * 60}")
    print(f"Test Suite : {r['test_suite']}")
    print(f"ISVS       : Section {r['isvs_section']}")
    print(f"Generated  : {r['generated_at']}")
    print(f"{'─' * 60}")
    print(f"Total      : {summary['total']}")
    print(f"Passed     : {summary['passed']}")
    print(f"Failed     : {summary['failed']}")
    print(f"Pass Rate  : {summary['pass_rate']}")
    print(f"{'=' * 60}\n")

    for result in r["results"]:
        status = "✓ PASS" if result.get("passed") else "✗ FAIL"
        print(f"  {status}  {result.get('test_name', 'unnamed')}")
        if not result.get("passed") and result.get("issues"):
            for issue in result["issues"]:
                print(f"           ↳ {issue}")
    print()