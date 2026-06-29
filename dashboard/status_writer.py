"""
LocalAegis-AI · Pipeline status writer
Buffered writes — flushes status.json every 500ms via background thread.
Writes last_run.json on every terminal state for post-exit dashboard review.
"""

import json
import os
import threading
import time

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATUS_PATH   = os.path.join(BASE_DIR, "status.json")
LAST_RUN_PATH = os.path.join(BASE_DIR, "last_run.json")

# ── Internal state ────────────────────────────────────────────────────────────
_lock       = threading.Lock()
_flush_stop = threading.Event()
_state      = {}
_dirty      = False


# ── Flush thread ──────────────────────────────────────────────────────────────
def _flush_loop():
    global _dirty
    while not _flush_stop.is_set():
        with _lock:
            if _dirty:
                _write_now()
                _dirty = False
        time.sleep(0.5)


def _write_now():
    """Write current _state to status.json. Must be called with _lock held."""
    with open(STATUS_PATH, "w", encoding="utf-8") as f:
        json.dump(_state, f, indent=2)


def _mark_dirty():
    """Signal that state has changed. Must be called with _lock held."""
    global _dirty
    _dirty = True


def _write_last_run(outcome: str):
    """Write last_run.json with outcome tag. Must be called with _lock held."""
    with open(LAST_RUN_PATH, "w", encoding="utf-8") as f:
        json.dump({**_state, "outcome": outcome}, f, indent=2)


def _start_flush_thread():
    t = threading.Thread(target=_flush_loop, daemon=True)
    t.start()


# ── Public API ────────────────────────────────────────────────────────────────
def init():
    """Reset all state and start the flush thread."""
    global _state, _dirty
    with _lock:
        _state = {
            "stage":   "idle",
            "started": time.time(),
            "elapsed": 0,
            "logs":    [],
            "metrics": {
                "violations_found": 0,
                "violations_after": 0,
                "deploy_ok":        False,
                "duration":         0
            }
        }
        _dirty = True
    _start_flush_thread()


def log(msg: str):
    ts = time.strftime("%H:%M:%S")
    with _lock:
        _state.setdefault("logs", []).append({"ts": ts, "msg": msg})
        _state["elapsed"] = round(time.time() - _state.get("started", time.time()), 1)
        _mark_dirty()


def _set_stage(stage: str):
    with _lock:
        _state["stage"] = stage
        _mark_dirty()


def stage_scan():               _set_stage("scan")
def stage_remediate():          _set_stage("remediate")
def stage_validate():           _set_stage("validate")
def stage_deploy():             _set_stage("deploy")
def stage_metrics():            _set_stage("metrics")


def stage_scan_done(violations_found: int):
    with _lock:
        _state["metrics"]["violations_found"] = violations_found
        _mark_dirty()


def stage_remediate_done():
    with _lock:
        _mark_dirty()


def stage_validate_done(violations_after: int):
    with _lock:
        _state["metrics"]["violations_after"] = violations_after
        _mark_dirty()


def stage_deploy_done(success: bool):
    with _lock:
        _state["metrics"]["deploy_ok"] = success
        _mark_dirty()


def stage_metrics_done():
    with _lock:
        _mark_dirty()


def complete(violations_found: int, violations_after: int, deploy_ok: bool):
    with _lock:
        _state["stage"]   = "complete"
        _state["elapsed"] = round(time.time() - _state.get("started", time.time()), 1)
        _state["metrics"].update({
            "violations_found": violations_found,
            "violations_after": violations_after,
            "deploy_ok":        deploy_ok,
            "duration":         _state["elapsed"]
        })
        _write_now()
        _write_last_run("complete")
        _dirty = False


def failed(reason: str):
    ts = time.strftime("%H:%M:%S")
    with _lock:
        _state["stage"]   = "failed"
        _state["elapsed"] = round(time.time() - _state.get("started", time.time()), 1)
        _state.setdefault("logs", []).append({"ts": ts, "msg": f"💥 {reason}"})
        _write_now()
        _write_last_run("failed")
        _dirty = False