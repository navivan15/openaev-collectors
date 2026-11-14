"""
Local runner for the sandbox demo page.

Serves harness/demo/index.html and runs harness scenarios on request. Each run
is the real collector code against the mock Splunk and mock OpenAEV from
mock_e2e_harness.py; the page shows the structured events that run produced.

  python harness/demo_server.py [port]      # default 8140, bound to 127.0.0.1 only

Nothing here talks to a real Splunk, a real OpenAEV or any real host.
"""

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
HARNESS = HERE / "mock_e2e_harness.py"
PAGE = HERE / "demo" / "index.html"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8140

RUN_LOCK = threading.Lock()   # the harness uses fixed mock ports: one run at a time
LAST = {}                     # scenario id -> summary of its last run in this session


def load_catalogue():
    out = subprocess.run([sys.executable, str(HARNESS), "catalogue"],
                         capture_output=True, text=True, timeout=60)
    return json.loads(out.stdout)


CATALOGUE = load_catalogue()
KNOWN = {test["id"] for group in CATALOGUE for test in group["tests"]}


def run_scenario(scenario):
    """Run one harness scenario in its own process and return what happened."""
    fd, events_path = tempfile.mkstemp(prefix="oaev-demo-", suffix=".json")
    os.close(fd)
    env = dict(os.environ, HARNESS_EVENTS_FILE=events_path, PYTHONIOENCODING="utf-8")
    started = time.time()
    try:
        with RUN_LOCK:
            proc = subprocess.run([sys.executable, str(HARNESS), scenario],
                                  capture_output=True, text=True, timeout=240, env=env,
                                  encoding="utf-8", errors="replace")
        try:
            events = json.loads(Path(events_path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            events = []
    finally:
        try:
            os.remove(events_path)
        except OSError:
            pass
    verdict = next((e for e in events if e.get("type") == "harness"), None)
    cycles = [e for e in events if e.get("type") == "cycle_end"]
    result = {
        "id": scenario,
        "ok": proc.returncode == 0 and bool(verdict and verdict.get("ok")),
        "note": (verdict or {}).get("note", ""),
        "fails": (verdict or {}).get("fails", []),
        "seconds": round(time.time() - started, 1),
        "events": events,
        "log": (proc.stdout or "")[-60000:] + (("\n" + proc.stderr[-4000:]) if proc.stderr else ""),
    }
    LAST[scenario] = {
        "ok": result["ok"],
        "outcomes": [r["outcome"] for c in cycles for r in c.get("results", [])],
        "searches": [len(c.get("searches", [])) for c in cycles],
        "at": time.strftime("%H:%M:%S"),
    }
    result["last"] = LAST[scenario]
    return result


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, content_type="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
        elif path == "/api/catalogue":
            self._send(200, {"groups": CATALOGUE, "last": LAST})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path.split("?", 1)[0] != "/api/run":
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            scenario = json.loads(self.rfile.read(length).decode("utf-8")).get("id")
        except (ValueError, AttributeError):
            scenario = None
        if scenario not in KNOWN:      # only catalogue ids ever reach the command line
            self._send(400, {"error": "unknown scenario"})
            return
        try:
            self._send(200, run_scenario(scenario))
        except subprocess.TimeoutExpired:
            self._send(504, {"error": "the run timed out"})


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"Sandbox demo on http://127.0.0.1:{PORT}  (mock only)")
    server.serve_forever()
