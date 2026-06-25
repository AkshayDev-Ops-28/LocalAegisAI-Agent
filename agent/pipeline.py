import os
import time
import subprocess
import json
import logging
from logging.handlers import RotatingFileHandler

import boto3
from dotenv import load_dotenv
from prometheus_client import CollectorRegistry, Gauge, push_to_gateway

from scanner import load_violations
from remediator import remediate
from validator import validate_tf

load_dotenv()

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TERRAFORM_DIR = os.path.join(BASE_DIR, "terraform")
DEPLOY_DIR    = os.path.join(TERRAFORM_DIR, "deploy")
REPORT_PATH   = os.path.join(BASE_DIR, "reports", "scan_report.json")
LOG_PATH      = os.path.join(BASE_DIR, "logs", "pipeline.log")
CHECKOV_CMD   = "C:\\Users\\Akshay\\AppData\\Local\\Programs\\Python\\Python313\\Scripts\\checkov.cmd"
PUSHGATEWAY   = "localhost:9091"
JOB_NAME      = "localaegis_pipeline"

# ── Logger ────────────────────────────────────────────────────────────────────
import logging
from logging.handlers import RotatingFileHandler

# ── Logger ────────────────────────────────────────────────────────────────────
_handler = RotatingFileHandler(
    LOG_PATH,
    maxBytes=500_000,   # 500 KB per file
    backupCount=3,      # keep pipeline.log, pipeline.log.1, pipeline.log.2, pipeline.log.3
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
        log(f"⚠️  Metrics push failed: {e}")

# ── Checkov scan ──────────────────────────────────────────────────────────────
def run_checkov_scan():
    log("📋 Running Checkov scan...")
    result = subprocess.run(
        [CHECKOV_CMD, "-d", TERRAFORM_DIR, "-o", "json",
         "--quiet", "--output-file", REPORT_PATH],
        capture_output=True,
        text=True,
        encoding="utf-8"
    )
    # Checkov returns non-zero exit code when violations found — that's expected
    if not os.path.exists(REPORT_PATH):
        raise RuntimeError(f"Checkov did not produce a report at {REPORT_PATH}")
    log(f"✅ Checkov scan complete — report written to {REPORT_PATH}")

import re

def strip_unsupported_resources(hcl: str) -> str:
    """
    Removes resource blocks that LocalStack community does not support.
    Uses a brace-depth parser instead of regex to handle nested blocks correctly.
    """
    skip_types = {"aws_s3_bucket_lifecycle_configuration"}
    lines = hcl.splitlines()
    result = []
    skip = False
    depth = 0

    for line in lines:
        stripped = line.strip()

        if not skip:
            # Check if this line opens a resource block we want to skip
            is_skip_block = False
            for rt in skip_types:
                if stripped.startswith(f'resource "{rt}"'):
                    is_skip_block = True
                    break

            if is_skip_block:
                skip = True
                depth = 0
                # Count any opening braces on this line
                depth += stripped.count("{") - stripped.count("}")
            else:
                result.append(line)
                continue
        else:
            # We are inside a block being skipped — track brace depth
            depth += stripped.count("{") - stripped.count("}")
            if depth <= 0:
                # Block is fully closed — stop skipping
                skip = False
                depth = 0

    return "\n".join(result).strip()


# ── Deploy ────────────────────────────────────────────────────────────────────
def deploy_to_localstack(hcl: str) -> bool:
    import tempfile
    import shutil

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
        # Must delete all objects before deleting bucket
        objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objects:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
        log(f"🗑️  Wiped bucket: {bucket}")


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

    try:
        log("═" * 60)
        log("🚀 LocalAegis-AI Pipeline — START")
        log("═" * 60)

        # PHASE 1 — Scan
        run_checkov_scan()
        violations = load_violations(REPORT_PATH)
        violations_count = len(violations)
        log(f"🔍 {violations_count} violation(s) found")

        if violations_count == 0:
            log("✅ No violations — skipping remediation")
            deploy_ok = True

        else:
            for v in violations:
                log(f"  ⚠️  {v['check_id']} — {v['check_name']}")

            # PHASE 2 — Remediate
            log("🤖 PHASE 2: Sending to Groq LLM for remediation...")
            hcl = remediate(violations)
            log("✅ LLM returned remediated HCL")

            # PHASE 3 — Validate
            log("🔎 PHASE 3: Validating LLM output with Checkov...")
            result = validate_tf(hcl)

            import json, os

            validation_report_path = os.path.join(os.path.dirname(__file__), "..", "reports", "validation_report.json")
            with open(validation_report_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
            print(f"[PIPELINE] Validation report written to reports/validation_report.json")

            if result["passed"]:
                log("✅ Validation passed — 0 violations in LLM output")
                remediation_ok = True
            else:
                log(f"❌ Validation failed — {len(result['violations'])} violation(s) remain")
                for v in result["violations"]:
                    log(f"  ⚠️  {v['check_id']} — {v['check_name']}")
                log("🛑 Halting pipeline — unsafe to deploy")

            # PHASE 4 — Deploy
            if remediation_ok:
                log("🚀 PHASE 4: Deploying to LocalStack...")
                wipe_localstack_buckets()   
                deploy_hcl = strip_unsupported_resources(hcl)
                log("⚠️  Lifecycle configuration stripped for LocalStack community compatibility")
                deploy_ok = deploy_to_localstack(deploy_hcl)
                if deploy_ok:
                    log("✅ Deployment successful")
                    verify_localstack()
                else:
                    log("❌ Deployment failed")

    except Exception as e:
        log(f"💥 Unhandled exception: {e}")

    finally:
        duration = round(time.time() - start, 2)
        log(f"⏱️  Pipeline completed in {duration}s")
        log("═" * 60)
        push_metrics(violations_count, remediation_ok, deploy_ok, duration)

if __name__ == "__main__":
    main()