"""
waiver_manager.py
Handles persistent storage of manually waived Checkov violations.
Retention policy: keeps only the 2 most recent run's waiver files.
Every waiver MUST include a non-empty human-written reason.
"""

import json
import os
from pathlib import Path
from datetime import datetime, timezone

_BASE_DIR = Path(__file__).resolve().parent.parent
WAIVERS_DIR = _BASE_DIR / "reports" / "waivers"
MAX_RETAINED_RUNS = 2


class WaiverValidationError(Exception):
    """Raised when a waiver is submitted without a valid reason."""
    pass


def _ensure_waivers_dir():
    WAIVERS_DIR.mkdir(parents=True, exist_ok=True)


def _waiver_file_path(run_id: str) -> Path:
    return WAIVERS_DIR / f"{run_id}.json"


def save_waivers(run_id: str, waivers: list[dict], waived_by: str = "Akshay") -> Path:
    """
    Persists a list of waiver dicts for a given run_id.
    Each waiver dict must contain: id, check_id, check_name, resource, severity, reason.
    Rejects any waiver with a missing or empty 'reason'.
    Automatically prunes older run files beyond MAX_RETAINED_RUNS.
    """
    _ensure_waivers_dir()

    validated = []
    now_iso = datetime.now(timezone.utc).isoformat()

    for w in waivers:
        reason = (w.get("reason") or "").strip()
        if not reason:
            raise WaiverValidationError(
                f"Waiver for check_id={w.get('check_id')} on "
                f"resource={w.get('resource')} is missing a reason. "
                f"A justification note is mandatory before a violation "
                f"can be waived."
            )
        validated.append({
            "id": w["id"],
            "check_id": w["check_id"],
            "check_name": w.get("check_name", ""),
            "resource": w.get("resource", ""),
            "severity": w.get("severity", "UNKNOWN"),
            "reason": reason,
            "waived_by": waived_by,
            "waived_at": now_iso,
        })

    payload = {
        "run_id": run_id,
        "created_at": now_iso,
        "waivers": validated,
    }

    file_path = _waiver_file_path(run_id)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    _prune_old_runs()
    return file_path


def _prune_old_runs():
    """Keeps only the MAX_RETAINED_RUNS most recently modified waiver files."""
    _ensure_waivers_dir()
    files = sorted(
        WAIVERS_DIR.glob("*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for stale_file in files[MAX_RETAINED_RUNS:]:
        stale_file.unlink()


def list_available_runs() -> list[dict]:
    """
    Returns metadata for the retained runs, newest first.
    Used to populate the dashboard's dropdown.
    """
    _ensure_waivers_dir()
    files = sorted(
        WAIVERS_DIR.glob("*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    result = []
    for f in files:
        try:
            with open(f, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            result.append({
                "run_id": data["run_id"],
                "created_at": data["created_at"],
                "waiver_count": len(data.get("waivers", [])),
            })
        except (json.JSONDecodeError, KeyError):
            continue
    return result


def load_waivers(run_id: str) -> dict:
    """Returns the full waiver payload for a given run_id, or empty structure if not found."""
    file_path = _waiver_file_path(run_id)
    if not file_path.exists():
        return {"run_id": run_id, "created_at": None, "waivers": []}
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def update_waiver_reason(run_id: str, waiver_id: str, new_reason: str) -> bool:
    """Edits the reason text of an existing waiver. Returns False if not found."""
    new_reason = (new_reason or "").strip()
    if not new_reason:
        raise WaiverValidationError("Updated reason cannot be empty.")

    data = load_waivers(run_id)
    found = False
    for w in data["waivers"]:
        if w["id"] == waiver_id:
            w["reason"] = new_reason
            w["waived_at"] = datetime.now(timezone.utc).isoformat()
            found = True
            break

    if found:
        with open(_waiver_file_path(run_id), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    return found


def delete_waiver(run_id: str, waiver_id: str) -> bool:
    """Removes a single waiver entry from a run's file. Returns False if not found."""
    data = load_waivers(run_id)
    before = len(data["waivers"])
    data["waivers"] = [w for w in data["waivers"] if w["id"] != waiver_id]
    changed = len(data["waivers"]) != before

    if changed:
        with open(_waiver_file_path(run_id), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    return changed