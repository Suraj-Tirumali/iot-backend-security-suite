"""
HTML Reporter
=============
Generates a human-readable HTML summary from a JSON report.
"""

from pathlib import Path
from typing import Any

REPORTS_DIR = Path(__file__).parent.parent.parent / "reports" / "json"


def generate_html(report: dict[str, Any]) -> str:
    """Generate an HTML string from a report dict."""
    r = report["report"]
    summary = r["summary"]

    rows = ""
    for result in r["results"]:
        status_class = "pass" if result.get("passed") else "fail"
        status_label = "PASS" if result.get("passed") else "FAIL"
        issues_html = ""
        if result.get("issues"):
            issues_html = "<ul>" + "".join(
                f"<li>{i}</li>" for i in result["issues"]
            ) + "</ul>"

        rows += f"""
        <tr class="{status_class}">
            <td>{result.get("test_name", "—")}</td>
            <td class="status">{status_label}</td>
            <td>{issues_html or "—"}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ISVS Report — {r['test_suite']}</title>
    <style>
        body {{ font-family: monospace; padding: 2rem; background: #0d1117; color: #c9d1d9; }}
        h1 {{ color: #58a6ff; }}
        .summary {{ background: #161b22; padding: 1rem; border-radius: 6px; margin-bottom: 2rem; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: #21262d; padding: 0.75rem; text-align: left; }}
        td {{ padding: 0.75rem; border-bottom: 1px solid #21262d; }}
        .pass td {{ border-left: 3px solid #3fb950; }}
        .fail td {{ border-left: 3px solid #f85149; }}
        .status {{ font-weight: bold; }}
        .pass .status {{ color: #3fb950; }}
        .fail .status {{ color: #f85149; }}
        ul {{ margin: 0; padding-left: 1.2rem; }}
    </style>
</head>
<body>
    <h1>ISVS Security Test Report</h1>
    <div class="summary">
        <p><strong>Suite:</strong> {r['test_suite']}</p>
        <p><strong>Section:</strong> ISVS {r['isvs_section']}</p>
        <p><strong>Generated:</strong> {r['generated_at']}</p>
        <p><strong>Results:</strong>
            {summary['passed']} passed /
            {summary['failed']} failed /
            {summary['total']} total
            ({summary['pass_rate']})
        </p>
    </div>
    <table>
        <thead>
            <tr><th>Test</th><th>Result</th><th>Issues</th></tr>
        </thead>
        <tbody>{rows}</tbody>
    </table>
</body>
</html>"""


def save_html(report: dict[str, Any], filename: str) -> Path:
    """Save HTML report to reports/json/<filename>."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    output_path = REPORTS_DIR / filename
    output_path.write_text(generate_html(report))
    return output_path