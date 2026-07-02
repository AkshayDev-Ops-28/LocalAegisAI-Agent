"""
LocalAegis-AI · Dashboard server
Serves the project root on localhost:8765.
Called from pipeline.py when not running in CI.

Static GET routes (unchanged, inherited from SimpleHTTPRequestHandler):
  /status.json, /last_run.json, /reports/pending_review.json,
  /reports/waivers/<run_id>.json  — all served directly off disk.

New API routes (this file):
  GET    /api/waivers/runs                     -> last N retained run summaries
  POST   /api/approve                           -> submit checklist decision
  PUT    /api/waivers/<run_id>/<waiver_id>       -> edit a waiver reason
  DELETE /api/waivers/<run_id>/<waiver_id>       -> remove a waiver
"""

import os
import sys
import json
import threading
import webbrowser
import http.server
import socketserver
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

PORT     = 8765
BASE_DIR = Path(__file__).resolve().parent.parent  # project root

# agent/ needs to be importable for waiver_manager
sys.path.insert(0, str(BASE_DIR))

from agent.waiver_manager import (
    save_waivers,
    list_available_runs,
    update_waiver_reason,
    delete_waiver,
    WaiverValidationError,
)


def _json_response(handler, status: int, payload: dict):
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _read_json_body(handler) -> dict:
    length = int(handler.headers.get("Content-Length", 0))
    if length == 0:
        return {}
    raw = handler.rfile.read(length)
    return json.loads(raw.decode("utf-8"))


def _trigger_resume_phase(run_id: str):
    """
    Spawns the resume phase of the pipeline as a background subprocess.
    Non-blocking — the HTTP response to the dashboard returns immediately;
    the pipeline resumes remediation and the dashboard picks up progress
    via its existing status.json polling loop, unchanged.
    """
    pipeline_script = BASE_DIR / "agent" / "pipeline.py"

    def _run():
        try:
            subprocess.run(
                [sys.executable, str(pipeline_script), "--resume", run_id],
                cwd=str(BASE_DIR),
                check=False,
            )
        except Exception as e:
            print(f"[Dashboard] Failed to launch resume phase: {e}")

    threading.Thread(target=_run, daemon=True).start()


class LocalAegisHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    def log_message(self, format, *args):
        pass  # silence access logs

    # ── GET ─────────────────────────────────────────────────────────
    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/api/waivers/runs":
            try:
                runs = list_available_runs()
                _json_response(self, 200, {"runs": runs})
            except Exception as e:
                _json_response(self, 500, {"error": str(e)})
            return

        # everything else: normal static file serving, unchanged
        super().do_GET()

    # ── POST ────────────────────────────────────────────────────────
    def do_POST(self):
        parsed = urlparse(self.path)

        if parsed.path == "/api/approve":
            try:
                payload = _read_json_body(self)
                run_id       = payload["run_id"]
                approved_ids = payload.get("approved_ids", [])
                waivers      = payload.get("waivers", [])

                # Persist waivers first — this is the step that hard-fails
                # if any waiver is missing its mandatory reason.
                if waivers:
                    save_waivers(run_id, waivers, waived_by=payload.get("waived_by", "Akshay"))

                approved_selection = {
                    "run_id": run_id,
                    "approved_ids": approved_ids,
                    "waived_ids": [w["id"] for w in waivers],
                    "approved_at": __import__("datetime").datetime.now(
                        __import__("datetime").timezone.utc
                    ).isoformat(),
                }
                reports_dir = BASE_DIR / "reports"
                reports_dir.mkdir(parents=True, exist_ok=True)
                with open(reports_dir / "approved_selection.json", "w", encoding="utf-8") as f:
                    json.dump(approved_selection, f, indent=2)

                _trigger_resume_phase(run_id)
                _json_response(self, 200, {"ok": True, "run_id": run_id})

            except WaiverValidationError as e:
                _json_response(self, 400, {"error": str(e)})
            except KeyError as e:
                _json_response(self, 400, {"error": f"Missing required field: {e}"})
            except Exception as e:
                _json_response(self, 500, {"error": str(e)})
            return

        self.send_response(404)
        self.end_headers()

    # ── PUT ─────────────────────────────────────────────────────────
    def do_PUT(self):
        parsed = urlparse(self.path)
        parts = parsed.path.strip("/").split("/")
        # expects: api / waivers / <run_id> / <waiver_id>
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "waivers":
            run_id, waiver_id = parts[2], parts[3]
            try:
                payload = _read_json_body(self)
                new_reason = payload.get("reason", "")
                found = update_waiver_reason(run_id, waiver_id, new_reason)
                if found:
                    _json_response(self, 200, {"ok": True})
                else:
                    _json_response(self, 404, {"error": "Waiver not found"})
            except WaiverValidationError as e:
                _json_response(self, 400, {"error": str(e)})
            except Exception as e:
                _json_response(self, 500, {"error": str(e)})
            return

        self.send_response(404)
        self.end_headers()

    # ── DELETE ──────────────────────────────────────────────────────
    def do_DELETE(self):
        parsed = urlparse(self.path)
        parts = parsed.path.strip("/").split("/")
        if len(parts) == 4 and parts[0] == "api" and parts[1] == "waivers":
            run_id, waiver_id = parts[2], parts[3]
            try:
                found = delete_waiver(run_id, waiver_id)
                if found:
                    _json_response(self, 200, {"ok": True})
                else:
                    _json_response(self, 404, {"error": "Waiver not found"})
            except Exception as e:
                _json_response(self, 500, {"error": str(e)})
            return

        self.send_response(404)
        self.end_headers()


_server_ready = threading.Event()


def _run_server():
    global _httpd
    try:
        socketserver.TCPServer.allow_reuse_address = True
        _httpd = socketserver.TCPServer(("127.0.0.1", PORT), LocalAegisHandler)
        _server_ready.set()
        _httpd.serve_forever()
    except Exception as e:
        print(f"[Dashboard] Server failed to start: {e}")
        _server_ready.set()  # unblock launch() so pipeline doesn't hang


def launch() -> str:
    thread = threading.Thread(target=_run_server, daemon=True)
    thread.start()

    # Wait up to 3 seconds for server to confirm it's listening
    ready = _server_ready.wait(timeout=3)
    if not ready:
        print("[Dashboard] Server did not start in time — continuing without dashboard")
        return ""

    url = f"http://127.0.0.1:{PORT}/dashboard/dashboard.html"
    webbrowser.open(url)
    time.sleep(0.5)  # small pause so browser tab opens before pipeline logs start
    return url