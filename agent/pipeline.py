import os
import sys
import time
import shutil
import subprocess
import tempfile
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

import boto3
from dotenv import load_dotenv
from prometheus_client import CollectorRegistry, Gauge, push_to_gateway

# ── Path bootstrap — MUST be unconditional and first ─────────────────────────
_BASE_DIR_EARLY = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BASE_DIR_EARLY not in sys.path:
    sys.path.insert(0, _BASE_DIR_EARLY)

# ── Register custom Checkov policy BEFORE any runner is invoked ───────────────
import importlib.util
_policy_path = os.path.join(_BASE_DIR_EARLY, "policies", "check_s3_mandatory_tags.py")
_spec = importlib.util.spec_from_file_location("check_s3_mandatory_tags", _policy_path)
_mod  = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

# ── Checkov in-process runner ─────────────────────────────────────────────────
from checkov.terraform.runner import Runner as TerraformRunner
from checkov.runner_filter import RunnerFilter
from checkov.common.output.record import Record

from scanner import load_violations
from remediator import remediate
from validator import validate_tf

load_dotenv()

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR               = _BASE_DIR_EARLY
TERRAFORM_DIR          = os.path.join(BASE_DIR, "terraform")
DEPLOY_DIR             = os.path.join(TERRAFORM_DIR, "deploy")
REPORT_PATH            = os.path.join(BASE_DIR, "reports", "scan_report.json")
VALIDATION_REPORT_PATH = os.path.join(BASE_DIR, "reports", "validation_report.json")
LOG_PATH               = os.path.join(BASE_DIR, "logs", "pipeline.log")
CHECKOV_CMD            = shutil.which("checkov") or "checkov"
PUSHGATEWAY            = "localhost:9091"
JOB_NAME               = "localaegis_pipeline"

# ── Directory bootstrap ───────────────────────────────────────────────────────
os.makedirs(os.path.join(BASE_DIR, "logs"),    exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, "reports"), exist_ok=True)

# ── Dashboard — local runs only ───────────────────────────────────────────────
_IS_CI = os.getenv("CI") == "true"

if not _IS_CI:
    _dashboard_dir = str(Path(BASE_DIR) / "dashboard")
    if _dashboard_dir not in sys.path:
        sys.path.insert(0, _dashboard_dir)
    import serve
    import status_writer

# ── Logger ────────────────────────────────────────────────────────────────────
_handler = RotatingFileHandler(
    LOG_PATH,
    maxBytes=500_000,
    backupCount=3,
    encoding="utf-8"
)
_handler.setFormatter(logging.Formatter("%(message)s"))

_logger = logging.getLogger("localaegis")
_logger.setLevel(logging.INFO)
_logger.addHandler(_handler)

def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    _logger.info(line)
    if not _IS_CI:
        status_writer.log(line)

# ── Metrics push ──────────────────────────────────────────────────────────────
def push_metrics(violations, remediation_ok, deploy_ok, duration):
    registry = CollectorRegistry()
    Gauge("localaegis_violations_found",
          "Number of Checkov violations detected",
          registry=registry).set(violations)
    Gauge("localaegis_remediation_success",
          "1 if LLM remediation passed validation, 0 otherwise",
          registry=registry).set(1 if remediation_ok else 0)
    Gauge("localaegis_deploy_success",
          "1 if deployment to LocalStack succeeded, 0 otherwise",
          registry=registry).set(1 if deploy_ok else 0)
    Gauge("localaegis_pipeline_duration_seconds",
          "Total pipeline wall-clock time in seconds",
          registry=registry).set(duration)
    try:
        push_to_gateway(PUSHGATEWAY, job=JOB_NAME, registry=registry)
        log("✅ Metrics pushed to Pushgateway")
    except Exception as e:
        log(f"⚠️  Metrics push failed (expected in CI — no Pushgateway): {e}")

# ── Checkov in-process scan ───────────────────────────────────────────────────
def run_checkov_scan():
    log("📋 Running Checkov scan (in-process)...")

    target_file = os.path.join(TERRAFORM_DIR, "main.tf")

    runner_filter = RunnerFilter(
        checks=None,
        skip_checks=["CKV_AWS_144", "CKV_AWS_145"],
    )

    runner = TerraformRunner()
    report = runner.run(
        root_folder=None,
        files=[target_file],
        runner_filter=runner_filter,
    )

    def get_check_name(r: Record) -> str:
        check_obj = getattr(r, "check", None)
        if check_obj and hasattr(check_obj, "name"):
            return check_obj.name
        return r.check_id

    def record_to_dict(r: Record, passed: bool) -> dict:
        return {
            "check_id":       r.check_id,
            "check_name":     get_check_name(r),
            "resource":       r.resource,
            "repo_file_path": r.repo_file_path,
            "file_path":      r.file_path,
            "guideline":      getattr(r, "guideline", "No guideline available"),
            "check_result":   {"result": "passed" if passed else "failed"},
        }

    output = {
        "results": {
            "passed_checks": [record_to_dict(r, True)  for r in report.passed_checks],
            "failed_checks": [record_to_dict(r, False) for r in report.failed_checks],
        }
    }

    if os.path.isdir(REPORT_PATH):
        shutil.rmtree(REPORT_PATH)
    elif os.path.isfile(REPORT_PATH):
        os.remove(REPORT_PATH)

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    log(f"✅ Checkov scan complete — report written to {REPORT_PATH}")

# ── Strip unsupported LocalStack community resources ──────────────────────────
def strip_unsupported_resources(hcl: str) -> str:
    skip_types = {"aws_s3_bucket_lifecycle_configuration"}
    lines  = hcl.splitlines()
    result = []
    skip   = False
    depth  = 0

    for line in lines:
        stripped = line.strip()
        if not skip:
            is_skip_block = any(
                stripped.startswith(f'resource "{rt}"') for rt in skip_types
            )
            if is_skip_block:
                skip  = True
                depth = stripped.count("{") - stripped.count("}")
            else:
                result.append(line)
        else:
            depth += stripped.count("{") - stripped.count("}")
            if depth <= 0:
                skip  = False
                depth = 0

    return "\n".join(result).strip()

# ── Wipe ──────────────────────────────────────────────────────────────────────
def wipe_localstack_buckets():
    s3 = boto3.client(
        "s3",
        endpoint_url="http://localhost:4566",
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1"
    )
    buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    for bucket in buckets:
        objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objects:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
        log(f"🗑️  Wiped bucket: {bucket}")

# ── Deploy ────────────────────────────────────────────────────────────────────
def deploy_to_localstack(hcl: str) -> bool:
    provider_src = os.path.join(DEPLOY_DIR, "provider.tf")
    tmp = tempfile.mkdtemp()
    try:
        shutil.copy(provider_src, os.path.join(tmp, "provider.tf"))
        with open(os.path.join(tmp, "main.tf"), "w", encoding="utf-8") as f:
            f.write(hcl)
        for cmd in [["terraform", "init", "-no-color"],
                    ["terraform", "apply", "-auto-approve", "-no-color"]]:
            result = subprocess.run(cmd, cwd=tmp, capture_output=True, text=True)
            log(result.stdout)
            if result.returncode != 0:
                log(f"❌ Terraform error:\n{result.stderr}")
                return False
        return True
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

# ── Verify ────────────────────────────────────────────────────────────────────
def verify_localstack():
    s3 = boto3.client(
        "s3",
        endpoint_url="http://localhost:4566",
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1"
    )
    buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    log(f"✅ S3 buckets live on LocalStack: {buckets}")

# ── Main pipeline ─────────────────────────────────────────────────────────────
def main():
    start            = time.time()
    violations_count = 0
    remediation_ok   = False
    deploy_ok        = False
    violations_after = 0

    validation_report = {
        "passed": False,
        "violations": [],
        "error": None,
        "remediation_attempted": False
    }

    if not _IS_CI:
        status_writer.init()
        url = serve.launch()
        log(f"🖥️  Dashboard: {url}")
        time.sleep(0.8)

    try:
        log("═" * 60)
        log("🚀 LocalAegis-AI Pipeline — START")
        log("═" * 60)

        # PHASE 1 — Scan
        if not _IS_CI:
            status_writer.stage_scan()

        run_checkov_scan()
        violations       = load_violations(REPORT_PATH)
        violations_count = len(violations)
        log(f"🔍 {violations_count} violation(s) found")

        if not _IS_CI:
            status_writer.stage_scan_done(violations_count)

        if violations_count == 0:
            log("✅ No violations — skipping remediation")
            validation_report["passed"] = True
            deploy_ok = True

        else:
            for v in violations:
                log(f"  ⚠️  {v['check_id']} — {v['check_name']}")

            try:
                # PHASE 2 — Remediate
                log("🤖 PHASE 2: Sending to Groq LLM for remediation...")
                if not _IS_CI:
                    status_writer.stage_remediate()

                hcl = remediate(violations)
                log("✅ LLM returned remediated HCL")
                validation_report["remediation_attempted"] = True

                if not _IS_CI:
                    status_writer.stage_remediate_done()

                # PHASE 3 — Validate
                log("🔎 PHASE 3: Validating LLM output with Checkov...")
                if not _IS_CI:
                    status_writer.stage_validate()

                result = validate_tf(hcl)
                validation_report.update(result)
                violations_after = len(result.get("violations", []))

                if not _IS_CI:
                    status_writer.stage_validate_done(violations_after)

                if result["passed"]:
                    log("✅ Validation passed — 0 violations in LLM output")
                    remediation_ok = True
                else:
                    log(f"❌ Validation failed — {violations_after} violation(s) remain")
                    for v in result["violations"]:
                        log(f"  ⚠️  {v['check_id']} — {v['check_name']}")
                    log("🛑 Halting pipeline — unsafe to deploy")

                # PHASE 4 — Deploy
                if remediation_ok:
                    log("🚀 PHASE 4: Deploying to LocalStack...")
                    if not _IS_CI:
                        status_writer.stage_deploy()

                    wipe_localstack_buckets()
                    deploy_hcl = strip_unsupported_resources(hcl)
                    log("⚠️  Lifecycle configuration stripped for LocalStack community compatibility")
                    deploy_ok = deploy_to_localstack(deploy_hcl)

                    if not _IS_CI:
                        status_writer.stage_deploy_done(deploy_ok)

                    if deploy_ok:
                        log("✅ Deployment successful")
                        verify_localstack()
                    else:
                        log("❌ Deployment failed")

            except Exception as remediation_error:
                log(f"💥 Remediation phase failed: {remediation_error}")
                validation_report["error"] = str(remediation_error)
                validation_report["violations"] = violations
                if not _IS_CI:
                    status_writer.failed(str(remediation_error))

    except Exception as e:
        log(f"💥 Unhandled exception: {e}")
        validation_report["error"] = str(e)
        if not _IS_CI:
            status_writer.failed(str(e))

    finally:
        with open(VALIDATION_REPORT_PATH, "w", encoding="utf-8") as f:
            json.dump(validation_report, f, indent=2)
        log(f"📄 Validation report written to {VALIDATION_REPORT_PATH}")

        duration = round(time.time() - start, 2)
        log(f"⏱️  Pipeline completed in {duration}s")
        log("═" * 60)

        if not _IS_CI:
            status_writer.stage_metrics()

        push_metrics(violations_count, remediation_ok, deploy_ok, duration)

        if not _IS_CI:
            status_writer.stage_metrics_done()
            status_writer.complete(violations_count, violations_after, deploy_ok)
            log("🖥️  Dashboard will close when you press Ctrl+C")
            time.sleep(5)

if __name__ == "__main__":
    main()