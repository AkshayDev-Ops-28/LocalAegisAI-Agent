import os
import sys
import tempfile
from checkov.runner_filter import RunnerFilter
from checkov.terraform.runner import Runner as TerraformRunner

# ── Ensure project root is on path for policy registration ───────────────────
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

# ── Register custom policy so CKV_LOCAL_1 is active in this runner ────────────
import importlib.util
_policy_path = os.path.join(_BASE_DIR, "policies", "check_s3_mandatory_tags.py")
_spec = importlib.util.spec_from_file_location("check_s3_mandatory_tags", _policy_path)
_mod  = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


def validate_tf(tf_code: str) -> dict:
    """
    Writes tf_code to a temp directory alongside a minimal provider block
    and runs Checkov in-process. Returns passed (bool) and residual violations.
    CKV_LOCAL_1 is active because the policy was registered at module load.
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

        runner_filter = RunnerFilter(
            checks=None,
            skip_checks=["CKV_AWS_144", "CKV_AWS_145"],
        )

        runner = TerraformRunner()
        report = runner.run(
            root_folder=None,
            files=[
                os.path.join(tmpdir, "main.tf"),
                os.path.join(tmpdir, "provider.tf"),
            ],
            runner_filter=runner_filter,
        )

        violations = []
        for r in report.failed_checks:
            check_obj = getattr(r, "check", None)
            check_name = (
                check_obj.name
                if check_obj and hasattr(check_obj, "name")
                else r.check_id
            )
            violations.append({
                "check_id":   r.check_id,
                "check_name": check_name,
                "resource":   r.resource,
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