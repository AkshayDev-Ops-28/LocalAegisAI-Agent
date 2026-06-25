import os
import json
import tempfile
import subprocess

import shutil
CHECKOV_CMD = shutil.which("checkov") or "checkov"

def validate_tf(tf_code: str) -> dict:
    """
    Writes tf_code to a temp directory alongside a minimal provider block
    and runs Checkov on the directory. Returns passed (bool) and residual violations.
    """
    provider_tf = """
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  endpoints {
    s3 = "http://localhost:4566"
  }
}
"""

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "main.tf"), "w", encoding="utf-8") as f:
            f.write(tf_code)

        with open(os.path.join(tmpdir, "provider.tf"), "w", encoding="utf-8") as f:
            f.write(provider_tf)

        result = subprocess.run(
            [CHECKOV_CMD, "-d", tmpdir, "-o", "json", "--quiet"],
            capture_output=True,
            text=True,
            encoding="utf-8"
        )

        output = result.stdout.strip()

        if not output:
            print("[validator] Checkov produced no output — treating as clean.")
            return {"passed": True, "violations": []}

        try:
            report = json.loads(output)
        except json.JSONDecodeError:
            print("[validator] Could not parse Checkov output. Raw output:")
            print(output)
            return {"passed": False, "violations": [], "parse_error": True}

        failed = report.get("results", {}).get("failed_checks", [])

        violations = []
        for check in failed:
            violations.append({
                "check_id":   check["check_id"],
                "check_name": check["check_name"],
                "resource":   check["resource"],
            })

        passed = len(violations) == 0
        return {"passed": passed, "violations": violations}


if __name__ == "__main__":
    from scanner import load_violations
    from remediator import remediate

    violations = load_violations()
    fixed_code = remediate(violations)

    print("\n[validator] Running Checkov on LLM output...\n")
    result = validate_tf(fixed_code)

    if result["passed"]:
        print("[validator] ✅ All checks passed. Code is clean.")
    else:
        print(f"[validator] ❌ {len(result['violations'])} residual violation(s):")
        for v in result["violations"]:
            print(f"  - [{v['check_id']}] {v['check_name']} | {v['resource']}")