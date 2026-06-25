import json
import os

REPORT_PATH = os.path.join(os.path.dirname(__file__), "..", "reports", "scan_report.json")

def load_violations(report_path: str = REPORT_PATH) -> list[dict]:
    """
    Reads the Checkov JSON report and returns a list of failed checks.
    Each entry contains only the fields the LLM needs to remediate.
    """
    with open(report_path, "r", encoding="utf-8-sig") as f:
        report = json.load(f)

    failed_checks = report["results"]["failed_checks"]

    violations = []
    for check in failed_checks:
        violations.append({
            "check_id":   check["check_id"],
            "check_name": check["check_name"],
            "resource":   check["resource"],
            "file_path":  check["repo_file_path"],
            "guideline":  check.get("guideline", "No guideline available"),
        })

    return violations


if __name__ == "__main__":
    violations = load_violations()
    print(f"\n[scanner] {len(violations)} violation(s) found:\n")
    for v in violations:
        print(f"  ❌ {v['check_id']} | {v['resource']}")
        print(f"     {v['check_name']}")
        print(f"     File: {v['file_path']}")
        print(f"     Guideline: {v['guideline']}\n")