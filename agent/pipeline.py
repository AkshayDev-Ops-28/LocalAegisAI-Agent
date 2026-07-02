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

# ── Path bootstrap — always runs, required for BASE_DIR ──────────────────────
_BASE_DIR_EARLY = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BASE_DIR_EARLY not in sys.path:
    sys.path.insert(0, _BASE_DIR_EARLY)

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
from waiver_manager import save_waivers, load_waivers, WaiverValidationError

load_dotenv()

# ── CI detection ──────────────────────────────────────────────────────────────
_IS_CI = os.getenv("CI") == "true"

# ── Resume-mode detection ─────────────────────────────────────────────────────
# When serve.py's /api/approve handler spawns this script with
# `--resume <run_id>`, the process is a short-lived worker: it does NOT
# launch the dashboard server (one is already running in the original
# scan-phase process) and it does NOT block waiting for anything — it does
# remediate -> validate -> deploy -> metrics, then exits.
_IS_RESUME  = "--resume" in sys.argv
_RESUME_RUN_ID = None
if _IS_RESUME:
    _resume_idx = sys.argv.index("--resume")
    if len(sys.argv) > _resume_idx + 1:
        _RESUME_RUN_ID = sys.argv[_resume_idx + 1]

# ── Dashboard imports (local runs only) ───────────────────────────────────────
if not _IS_CI:
    _dashboard_dir = str(Path(_BASE_DIR_EARLY) / "dashboard")
    if _dashboard_dir not in sys.path:
        sys.path.insert(0, _dashboard_dir)
    import serve
    import status_writer

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR                  = _BASE_DIR_EARLY
TERRAFORM_DIR              = os.path.join(BASE_DIR, "terraform")
DEPLOY_DIR                 = os.path.join(TERRAFORM_DIR, "deploy")
REPORT_PATH                = os.path.join(BASE_DIR, "reports", "scan_report.json")
VALIDATION_REPORT_PATH     = os.path.join(BASE_DIR, "reports", "validation_report.json")
PENDING_REVIEW_PATH        = os.path.join(BASE_DIR, "reports", "pending_review.json")
APPROVED_SELECTION_PATH    = os.path.join(BASE_DIR, "reports", "approved_selection.json")
LOG_PATH                   = os.path.join(BASE_DIR, "logs", "pipeline.log")
CHECKOV_CMD                = shutil.which("checkov") or "checkov"
PUSHGATEWAY                = "localhost:9091"
JOB_NAME                   = "localaegis_pipeline"

# ── Directory bootstrap ───────────────────────────────────────────────────────
os.makedirs(os.path.join(BASE_DIR, "logs"),    exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, "reports"), exist_ok=True)

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
    ts   = time.strftime("%Y-%m-%d %H:%M:%S")
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

# ── Review-item / waiver helpers ──────────────────────────────────────────────
def _build_review_items(violations: list) -> list:
    """
    Assigns stable v1..vN ids to a violations list, in load order.
    Both the scan phase (writing pending_review.json) and the resume phase
    (mapping dashboard-submitted ids back to real violations) call this on
    the SAME REPORT_PATH file, so ordering must stay deterministic — this
    relies on load_violations() returning a stable order for a given
    scan_report.json, which it does today since it walks the file linearly.

    NOTE: scanner.py's violation dicts (per Day-8 interface reference) carry
    check_id / check_name / resource / file_path / guideline — no severity
    field. Until scanner.py surfaces Checkov's real severity, this defaults
    every item to "MEDIUM" so the dashboard badge has something to render.
    Flagging this rather than inventing a fake severity scale.
    """
    items = []
    for i, v in enumerate(violations, start=1):
        items.append({
            "id":         f"v{i}",
            "check_id":   v["check_id"],
            "check_name": v.get("check_name", v["check_id"]),
            "resource":   v.get("resource", "unknown"),
            "severity":   v.get("severity", "MEDIUM"),
        })
    return items


def _write_pending_review(run_id: str, violations: list):
    review_items = _build_review_items(violations)
    payload = {
        "run_id": run_id,
        "status": "awaiting_approval",
        "violations": review_items,
    }
    with open(PENDING_REVIEW_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    log(f"📝 {len(review_items)} violation(s) awaiting your decision on the dashboard")


def _clear_pending_review():
    if os.path.isfile(PENDING_REVIEW_PATH):
        os.remove(PENDING_REVIEW_PATH)


def _load_approved_selection(run_id: str) -> dict:
    if not os.path.isfile(APPROVED_SELECTION_PATH):
        raise FileNotFoundError(
            f"--resume was called for run {run_id} but "
            f"{APPROVED_SELECTION_PATH} does not exist. serve.py should "
            f"write this file before spawning the resume subprocess."
        )
    with open(APPROVED_SELECTION_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    if data.get("run_id") != run_id:
        raise ValueError(
            f"approved_selection.json is for run {data.get('run_id')}, "
            f"but --resume was called with {run_id}. Refusing to proceed "
            f"with a mismatched approval file."
        )
    return data

# ── Shared finalization (used by zero-violation path, resume path, and CI) ───
def _finalize(start, violations_count, violations_after, violations_waived,
              remediation_ok, deploy_ok, validation_report):
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
        status_writer.complete(violations_count, violations_after, deploy_ok, violations_waived)

    _clear_pending_review()

# ── Resume phase — remediate -> validate -> deploy -> metrics ────────────────
def run_resume_phase(run_id: str, approved_ids: list, waivers: list):
    """
    Runs the remediate/validate/deploy legs for ONLY the violations the
    human approved. Anything in `waivers` is left untouched in the
    Terraform and excluded from the pass/fail gate — a waived violation
    still showing up post-validation is EXPECTED, not a failure.
    """
    start             = time.time()
    violations_after  = 0
    remediation_ok    = False
    deploy_ok         = False

    validation_report = {
        "passed": False,
        "violations": [],
        "waived": waivers,
        "error": None,
        "remediation_attempted": False
    }

    # run_resume_phase() is only ever reached two ways:
    #   1. CI, called in-process from run_scan_phase() — CI never touches
    #      status_writer at all, so nothing to do here.
    #   2. The --resume subprocess spawned by serve.py — a brand new Python
    #      process with no status_writer session of its own yet.
    if _IS_RESUME:
        status_writer.init()
        # Re-populate the violations_found metric immediately — this is a
        # fresh process, so without this the dashboard would flash the
        # metric back to 0 for a moment before remediation catches up.
        all_violations = load_violations(REPORT_PATH)
        status_writer.stage_scan_done(len(all_violations))

    try:
        all_violations = load_violations(REPORT_PATH)
        review_items   = _build_review_items(all_violations)
        by_id          = {item["id"]: v for item, v in zip(review_items, all_violations)}

        approved_violations = [by_id[vid] for vid in approved_ids if vid in by_id]
        waived_keys = {(w["check_id"], w["resource"]) for w in waivers}

        log(f"▶️  Resuming run {run_id} — {len(approved_violations)} approved, "
            f"{len(waivers)} waived")

        if len(approved_violations) == 0:
            log("✅ Nothing approved for remediation — treating as pass (all waived)")
            validation_report["passed"] = True
            remediation_ok = True
            deploy_ok      = True
        else:
            try:
                log("🤖 PHASE 2: Sending approved violations to Groq LLM for remediation...")
                if not _IS_CI:
                    status_writer.stage_remediate()

                hcl = remediate(approved_violations)
                log("✅ LLM returned remediated HCL")
                validation_report["remediation_attempted"] = True

                if not _IS_CI:
                    status_writer.stage_remediate_done()

                log("🔎 PHASE 3: Validating LLM output with Checkov...")
                if not _IS_CI:
                    status_writer.stage_validate()

                result = validate_tf(hcl)
                remaining = result.get("violations", [])
                violations_after = len(remaining)

                # A remaining violation only blocks the deploy if it wasn't
                # explicitly waived. Match on (check_id, resource) — matching
                # on check_id alone would treat every bucket as waived just
                # because ONE bucket's instance of that check was waived.
                blocking = [
                    v for v in remaining
                    if (v.get("check_id"), v.get("resource")) not in waived_keys
                ]

                validation_report["violations"] = remaining
                validation_report["blocking_violations"] = blocking

                if not _IS_CI:
                    status_writer.stage_validate_done(violations_after)

                if len(blocking) == 0:
                    if violations_after > 0:
                        log(f"✅ Validation passed — {violations_after} remaining "
                            f"violation(s) all explicitly waived")
                    else:
                        log("✅ Validation passed — 0 violations in LLM output")
                    validation_report["passed"] = True
                    remediation_ok = True
                else:
                    log(f"❌ Validation failed — {len(blocking)} approved violation(s) "
                        f"still present after remediation")
                    for v in blocking:
                        log(f"  ⚠️  {v.get('check_id')} — {v.get('check_name', '')}")
                    log("🛑 Halting pipeline — unsafe to deploy")

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
                validation_report["error"]      = str(remediation_error)
                validation_report["violations"] = approved_violations
                if not _IS_CI:
                    status_writer.failed(str(remediation_error))

    except Exception as e:
        log(f"💥 Unhandled exception in resume phase: {e}")
        validation_report["error"] = str(e)
        if not _IS_CI:
            status_writer.failed(str(e))

    finally:
        total_found = len(load_violations(REPORT_PATH)) if os.path.isfile(REPORT_PATH) else 0
        _finalize(start, total_found, violations_after, len(waivers),
                  remediation_ok, deploy_ok, validation_report)

# ── Scan phase — scan only, then gate on human decision (or CI auto-approve) ─
def run_scan_phase(run_id: str):
    start = time.time()

    if not _IS_CI:
        status_writer.init()
        url = serve.launch()
        log(f"🖥️  Dashboard: {url}")
        time.sleep(0.8)

    log("═" * 60)
    log("🚀 LocalAegis-AI Pipeline — START")
    log(f"🆔 Run ID: {run_id}")
    log("═" * 60)

    if not _IS_CI:
        status_writer.stage_scan()

    run_checkov_scan()
    violations       = load_violations(REPORT_PATH)
    violations_count = len(violations)
    log(f"🔍 {violations_count} violation(s) found")

    if not _IS_CI:
        status_writer.stage_scan_done(violations_count)

    if violations_count == 0:
        log("✅ No violations — skipping remediation and the approval gate entirely")
        validation_report = {
            "passed": True, "violations": [], "waived": [],
            "error": None, "remediation_attempted": False
        }
        _finalize(start, 0, 0, 0, True, True, validation_report)
        if not _IS_CI:
            log("🖥️  Dashboard will close when you press Ctrl+C")
            time.sleep(5)
        return

    for v in violations:
        log(f"  ⚠️  {v['check_id']} — {v['check_name']}")

    if _IS_CI:
        # No human in CI — auto-approve everything, exactly matching the
        # pre-Day-9 fully-autonomous behavior. Runs in-process, no subprocess,
        # no pending_review.json, no wait.
        review_items = _build_review_items(violations)
        approved_ids = [item["id"] for item in review_items]
        run_resume_phase(run_id, approved_ids, waivers=[])
        return

    # Local, non-CI: pause and hand the decision to the dashboard.
    _write_pending_review(run_id, violations)
    status_writer.stage_awaiting_approval(run_id)
    log("⏸️  Pipeline paused — open the dashboard and submit your checklist decision")
    log("🖥️  This process stays alive to keep serving the dashboard. Ctrl+C to stop.")

    # Block here. The actual remediate/validate/deploy work happens in a
    # SEPARATE subprocess that serve.py spawns (`--resume <run_id>`) once
    # you submit the checklist — that subprocess writes directly to
    # status.json on disk, which this process's HTTP server keeps serving
    # fresh on every request, so the dashboard updates live without this
    # process doing anything further.
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log("👋 Dashboard stopped by user")

# ── Entry point ────────────────────────────────────────────────────────────
def main():
    if _IS_RESUME:
        if not _RESUME_RUN_ID:
            log("💥 --resume was passed without a run_id — aborting")
            sys.exit(1)
        try:
            selection = _load_approved_selection(_RESUME_RUN_ID)
        except (FileNotFoundError, ValueError) as e:
            log(f"💥 {e}")
            sys.exit(1)
        # approved_selection.json only carries waived_ids (v1, v2...); the
        # full waiver records — check_id, resource, reason — live in
        # reports/waivers/<run_id>.json, written by serve.py's /api/approve
        # handler via save_waivers() BEFORE approved_selection.json is
        # written. Load from there rather than assuming a field that
        # approved_selection.json's schema never actually defines.
        waiver_data = load_waivers(_RESUME_RUN_ID)
        run_resume_phase(
            _RESUME_RUN_ID,
            selection.get("approved_ids", []),
            waiver_data.get("waivers", []),
        )
        return

    run_id = time.strftime("%Y%m%d-%H%M%S")
    run_scan_phase(run_id)

if __name__ == "__main__":
    main()