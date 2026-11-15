"""
Local runner for the sandbox demo page.

Serves harness/demo/index.html and runs sandbox jobs on request. A job is one
scenario from the catalogue, or a set of attack types picked in the attack
library. Each job is the real collector and ant code in its own process,
against its own mock Splunk, mock Falcon, mock OpenCTI and mock OpenAEV. Up to
four jobs run at the same time; the rest wait in a queue. The page follows each
job step by step while it runs.

  python harness/demo_server.py [port]      # default 8140, bound to 127.0.0.1 only

  GET  /api/catalogue    scenarios, by group
  GET  /api/library      attack library: actions and refused families, by ATT&CK tactic
  POST /api/jobs         {"ids": [...]} or {"custom": {"name", "techniques", "hosts"}}
  POST /api/poll         {"jobs": {id: [events seen, log characters seen]}} -> what is new
  POST /api/clear        forget the finished jobs

Nothing here talks to a real Splunk, a real Falcon, a real OpenAEV or any real host.
"""

import json
import os
import queue
import re
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
ANTS_SANDBOX = HERE.parents[1] / "validation-ants" / "sandbox.py"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8140

SLOTS = 4                 # jobs that run at the same time
MOCK_PORT_BASE = 18300    # each slot gets its own block of ten mock ports
JOB_TIMEOUT = 240
MAX_WAITING = 200
MAX_LOG = 200_000
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def _json_from(script, command):
    out = subprocess.run([sys.executable, str(script), command],
                         capture_output=True, text=True, timeout=60)
    return json.loads(out.stdout)


def load_catalogue():
    """Collector scenarios, plus the full-pipeline scenarios when they are present."""
    groups = _json_from(HARNESS, "catalogue")
    scripts = {test["id"]: HARNESS for group in groups for test in group["tests"]}
    library = {"tactics": [], "attacks": [], "not_simulated": [], "hosts": []}
    if ANTS_SANDBOX.exists():
        tests = _json_from(ANTS_SANDBOX, "catalogue")
        groups.insert(0, {"group": "All ants: full pipeline", "tests": tests})
        scripts.update({test["id"]: ANTS_SANDBOX for test in tests})
        library = _json_from(ANTS_SANDBOX, "library")
    return groups, scripts, library


CATALOGUE, SCRIPTS, LIBRARY = load_catalogue()
TITLES = {t["id"]: t["title"] for g in CATALOGUE for t in g["tests"]}
GROUPS = {t["id"]: g["group"] for g in CATALOGUE for t in g["tests"]}
LIBRARY_TECHNIQUES = ({a["technique"] for a in LIBRARY["attacks"]}
                      | {r["technique"] for r in LIBRARY["not_simulated"]})
RUNNABLE = {a["technique"] for a in LIBRARY["attacks"]}

LOCK = threading.Lock()
JOBS = {}                 # job id -> job
ORDER = []                # job ids, oldest first
WAITING = queue.Queue()
COUNTER = [0]


def new_job(scenario, title, kind, group, custom=None):
    with LOCK:
        COUNTER[0] += 1
        job = {
            "id": f"job-{COUNTER[0]}", "n": COUNTER[0], "scenario": scenario, "title": title,
            "kind": kind, "group": group, "custom": custom, "status": "queued", "slot": None,
            "ok": None, "note": "", "fails": [], "queued_at": time.time(), "started_at": None,
            "seconds": None, "events": [], "log": "",
        }
        JOBS[job["id"]] = job
        ORDER.append(job["id"])
    WAITING.put(job["id"])
    return job


def summary(job):
    running = job["status"] == "running" and job["started_at"]
    return {
        "id": job["id"], "n": job["n"], "scenario": job["scenario"], "title": job["title"],
        "kind": job["kind"], "group": job["group"], "custom": job["custom"],
        "status": job["status"], "slot": job["slot"], "ok": job["ok"], "note": job["note"],
        "fails": job["fails"], "events": len(job["events"]), "log": len(job["log"]),
        "seconds": round(time.time() - job["started_at"], 1) if running else job["seconds"],
        "at": time.strftime("%H:%M:%S", time.localtime(job["queued_at"])),
    }


def _read_log(proc, job):
    for line in proc.stdout:
        with LOCK:
            if len(job["log"]) < MAX_LOG:
                job["log"] += line


def run_job(job, slot):
    """Run one job in its own process and follow its events while it runs."""
    fd, stream_path = tempfile.mkstemp(prefix="oaev-demo-", suffix=".jsonl")
    os.close(fd)
    base = MOCK_PORT_BASE + slot * 10
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1",
               HARNESS_EVENTS_STREAM=stream_path,
               SANDBOX_PORT_BASE=str(base),
               HARNESS_SPLUNK_PORT=str(base + 5), HARNESS_OPENAEV_PORT=str(base + 6))
    env.pop("HARNESS_EVENTS_FILE", None)
    env.pop("SANDBOX_CUSTOM", None)
    if job["custom"]:
        # The selection travels in the environment, never on the command line.
        env["SANDBOX_CUSTOM"] = json.dumps(job["custom"])
    script = ANTS_SANDBOX if job["kind"] == "custom" else SCRIPTS[job["scenario"]]
    with LOCK:
        job.update(status="running", slot=slot + 1, started_at=time.time())
    proc = subprocess.Popen([sys.executable, str(script), job["scenario"]],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env,
                            text=True, encoding="utf-8", errors="replace")
    reader = threading.Thread(target=_read_log, args=(proc, job), daemon=True)
    reader.start()
    position, pending, timed_out = 0, "", False

    def drain():
        nonlocal position, pending
        try:
            with open(stream_path, "r", encoding="utf-8") as stream:
                stream.seek(position)
                chunk = stream.read()
                position = stream.tell()
        except OSError:
            return
        pending += chunk
        *lines, pending = pending.split("\n")
        fresh = []
        for line in lines:
            try:
                fresh.append(json.loads(line))
            except ValueError:
                pass
        if fresh:
            with LOCK:
                job["events"].extend(fresh)

    try:
        while proc.poll() is None:
            drain()
            if time.time() - job["started_at"] > JOB_TIMEOUT:
                proc.kill()
                timed_out = True
                break
            time.sleep(0.05)
        proc.wait()
        reader.join(timeout=5)
        drain()
    finally:
        try:
            os.remove(stream_path)
        except OSError:
            pass
    verdict = next((e for e in job["events"] if e.get("type") == "harness"), None)
    with LOCK:
        job.update(
            status="done", seconds=round(time.time() - job["started_at"], 1),
            ok=proc.returncode == 0 and bool(verdict and verdict.get("ok")),
            note=(verdict or {}).get("note", ""),
            fails=(verdict or {}).get("fails", []) or (
                ["the run timed out"] if timed_out else
                [] if verdict else ["the run ended without a result; see the raw output"]))


def worker(slot):
    while True:
        job_id = WAITING.get()
        job = JOBS.get(job_id)
        if not job:          # cleared while it waited
            continue
        try:
            run_job(job, slot)
        except Exception as e:          # a job must never take its worker down
            with LOCK:
                job.update(status="done", ok=False, fails=[f"the runner failed: {e}"],
                           seconds=round(time.time() - (job["started_at"] or time.time()), 1))


def start_custom(spec):
    """Check a selection from the attack library and queue it. Returns a job or an error."""
    if not isinstance(spec, dict):
        return None, "the selection is not valid"
    techniques = [t for t in dict.fromkeys(spec.get("techniques") or [])
                  if isinstance(t, str) and TECHNIQUE_RE.match(t) and t in LIBRARY_TECHNIQUES]
    hosts = [h for h in LIBRARY["hosts"] if h in (spec.get("hosts") or [])]
    name = re.sub(r"[^A-Za-z0-9 _\-]", "", str(spec.get("name") or ""))[:48].strip()
    if not techniques or len(techniques) > 30:
        return None, "pick between 1 and 30 attack types from the library"
    if not any(t in RUNNABLE for t in techniques):
        return None, "none of the picked attack types has a harmless action to run"
    if not hosts:
        return None, "pick at least one sandbox host"
    name = name or "Library selection"
    custom = {"name": name, "techniques": techniques, "hosts": hosts}
    return new_job("custom", name, "custom", "From the attack library", custom), None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, content_type="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _local(self):
        """Only this machine's own page may talk to the runner."""
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ("127.0.0.1", "localhost")

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if not self._local():
            self._send(403, {"error": "local use only"})
        elif path in ("/", "/index.html"):
            self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
        elif path == "/api/catalogue":
            self._send(200, {"groups": CATALOGUE, "slots": SLOTS})
        elif path == "/api/library":
            self._send(200, LIBRARY)
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        # A JSON content type cannot be sent by another site's page without a
        # preflight this server never answers, so only this page can post here.
        if not self._local() or "application/json" not in (self.headers.get("Content-Type") or ""):
            self._send(403, {"error": "local use only"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
        except ValueError:
            body = None
        if not isinstance(body, dict):
            self._send(400, {"error": "the request is not valid"})
        elif path == "/api/jobs":
            self._start(body)
        elif path == "/api/poll":
            self._poll(body)
        elif path == "/api/clear":
            with LOCK:
                for job_id in [j for j in ORDER if JOBS[j]["status"] == "done"]:
                    ORDER.remove(job_id)
                    del JOBS[job_id]
            self._send(200, {"ok": True})
        else:
            self._send(404, {"error": "not found"})

    def _start(self, body):
        if WAITING.qsize() >= MAX_WAITING:
            self._send(429, {"error": "too many jobs are waiting"})
            return
        if "custom" in body:
            job, error = start_custom(body["custom"])
            if error:
                self._send(400, {"error": error})
            else:
                self._send(200, {"jobs": [summary(job)]})
            return
        ids = body.get("ids")
        # Only catalogue ids ever reach a command line.
        if not isinstance(ids, list) or not ids or any(i not in SCRIPTS for i in ids):
            self._send(400, {"error": "unknown scenario"})
            return
        jobs = [new_job(i, TITLES[i], "check", GROUPS[i]) for i in ids[:MAX_WAITING]]
        self._send(200, {"jobs": [summary(j) for j in jobs]})

    def _poll(self, body):
        seen = body.get("jobs") if isinstance(body.get("jobs"), dict) else {}
        with LOCK:
            jobs = [summary(JOBS[j]) for j in ORDER]
            updates = {}
            for job_id, marks in seen.items():
                job = JOBS.get(job_id)
                if not job or not isinstance(marks, list) or len(marks) != 2:
                    continue
                try:
                    events_from, log_from = max(0, int(marks[0])), max(0, int(marks[1]))
                except (TypeError, ValueError):
                    continue
                if events_from < len(job["events"]) or log_from < len(job["log"]):
                    updates[job_id] = {"events": job["events"][events_from:],
                                       "log": job["log"][log_from:]}
        self._send(200, {"jobs": jobs, "updates": updates})


if __name__ == "__main__":
    for n in range(SLOTS):
        threading.Thread(target=worker, args=(n,), daemon=True).start()
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"Sandbox demo on http://127.0.0.1:{PORT}  (mock only, {SLOTS} jobs at a time)")
    server.serve_forever()
