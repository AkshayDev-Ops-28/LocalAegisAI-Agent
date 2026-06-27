"""
LocalAegis-AI · Pipeline status writer
Writes status.json to the project root at each pipeline stage.
The dashboard polls this file every second.
"""

import json
import os
import time
from pathlib import Path

BASE_DIR   = Path(__file__).resolve().parent.parent
STATUS_PATH = BASE_DIR / "status.json"

_start_time = None
_logs: list[str] = []


def _elapsed() -> float:
    if _start_time is None:
        return 0.0
    return round(time.time() - _start_time, 1)


def _write(stage: str, metrics: dict | None = None):
    payload = {
        "stage":   stage,
        "logs":    list(_logs),
        "metrics": metrics or {},
    }
    STATUS_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def init():
    """Call at the very start of pipeline.py main()."""
    global _start_time, _logs
    _start_time = time.time()
    _logs = []
    _write("idle")


def log(msg: str):
    """Append a log line and flush to status.json (preserves current stage)."""
    _logs.append(msg)
    # re-read current stage so we don't overwrite it
    try:
        current = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
        stage   = current.get("stage", "idle")
        metrics = current.get("metrics", {})
    except Exception:
        stage   = "idle"
        metrics = {}
    _write(stage, metrics)


def stage_scan():
    _logs.append(f"[{_elapsed()}s] Checkov scan started on terraform/")
    _write("scan")


def stage_scan_done(violations_found: int):
    _logs.append(f"[{_elapsed()}s] Scan complete — {violations_found} violation(s) found")
    _write("scan", {"violations_found": violations_found})


def stage_remediate():
    _logs.append(f"[{_elapsed()}s] Sending violations to LLM for remediation")
    _write("remediate")


def stage_remediate_done():
    _logs.append(f"[{_elapsed()}s] HCL remediation received")
    _write("remediate")


def stage_validate():
    _logs.append(f"[{_elapsed()}s] Re-validation started on remediated HCL")
    _write("validate")


def stage_validate_done(violations_after: int):
    status = "passed" if violations_after == 0 else "FAILED"
    _logs.append(f"[{_elapsed()}s] Re-validation {status} — {violations_after} violation(s) remaining")
    _write("validate", {"violations_after": violations_after})


def stage_deploy():
    _logs.append(f"[{_elapsed()}s] Deploying remediated infrastructure to LocalStack")
    _write("deploy")


def stage_deploy_done(success: bool):
    result = "S3 buckets confirmed live" if success else "Deploy FAILED"
    _logs.append(f"[{_elapsed()}s] {result}")
    _write("deploy", {"deploy_ok": success})


def stage_metrics():
    _logs.append(f"[{_elapsed()}s] Pushing metrics to Prometheus Pushgateway")
    _write("metrics")


def stage_metrics_done():
    _logs.append(f"[{_elapsed()}s] Metrics pushed")
    _write("metrics")


def complete(violations_found: int, violations_after: int, deploy_ok: bool):
    dur = _elapsed()
    _logs.append(f"[{dur}s] Pipeline complete — all checks passed")
    _write("complete", {
        "violations_found": violations_found,
        "violations_after": violations_after,
        "deploy_ok":        deploy_ok,
        "duration":         dur,
    })


def failed(reason: str):
    _logs.append(f"[{_elapsed()}s] ERROR — {reason}")
    _write("failed")
