<<<<<<< HEAD
"""
LocalAegis-AI · Dashboard server
Serves the project root on localhost:8765.
Called from pipeline.py when not running in CI.
"""

import os
import threading
import webbrowser
import http.server
import socketserver
import time
from pathlib import Path

PORT     = 8765
BASE_DIR = Path(__file__).resolve().parent.parent  # project root


class LocalAegisHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    def log_message(self, format, *args):
        pass  # silence access logs

=======
import os
import threading
import webbrowser
from http.server import HTTPServer, SimpleHTTPRequestHandler

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST     = "127.0.0.1"
PORT     = 8765
>>>>>>> c3b46f1 (feat: rebuild dashboard files, integrate status_writer, buffered writes (Day 6))

_server_ready = threading.Event()


<<<<<<< HEAD
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
=======
class _QuietHandler(SimpleHTTPRequestHandler):
    """Suppress request logs so pipeline output stays clean."""
    def log_message(self, format, *args):
        pass

    def translate_path(self, path):
        # Serve from project root so /status.json resolves correctly
        self.directory = BASE_DIR
        return super().translate_path(path)


def _serve():
    server = HTTPServer((HOST, PORT), _QuietHandler)
    server.allow_reuse_address = True
    _server_ready.set()
    server.serve_forever()


def launch() -> str:
    """Start the dashboard server in a daemon thread. Returns the URL."""
    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    _server_ready.wait(timeout=5)
    url = f"http://{HOST}:{PORT}/dashboard/dashboard.html"
    webbrowser.open(url)
>>>>>>> c3b46f1 (feat: rebuild dashboard files, integrate status_writer, buffered writes (Day 6))
    return url