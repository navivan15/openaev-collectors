"""
End-to-end mock harness for the OpenAEV Splunk-ES collector.

Runs the REAL collector code (client_api, expectation_service, converter,
trace_service, expectation_manager) against two in-process mock HTTP servers:

  * Mock Splunk ES  -> answers POST /services/search/jobs (SPL search) and
                       GET /services/data/indexes/<name> (index check)
  * Mock OpenAEV    -> answers the expectation + trace REST endpoints

No Docker, no real Splunk, no real OpenAEV, no real hosts. Everything runs in
one process so we can watch the entire message flow.

Usage:
  python harness/mock_e2e_harness.py <scenario>   # one scenario, verbose wire trace
  python harness/mock_e2e_harness.py all          # every scenario, pass/fail table

Each scenario asserts the outcome (Detected / Missed / Could not check), what
was written back to OpenAEV, and where relevant the miss/could-not-check reason
and the match method. Exit code is non-zero when any assertion fails.
"""

import json
import logging
import os
import subprocess
import sys
import threading
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# make "src" importable exactly like the collector does
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

WIRE = []  # captured HTTP exchanges, in order


def log_wire(system, direction, summary, body=None):
    WIRE.append({"system": system, "dir": direction, "summary": summary, "body": body})
    arrow = "->" if direction == "req" else "<-"
    print(f"   [{system:8}] {arrow} {summary}")
    if body is not None:
        preview = json.dumps(body, default=str)
        if len(preview) > 600:
            preview = preview[:600] + " ...(truncated)"
        print(f"              {preview}")


# ----------------------------------------------------------------------------
# Expected results per scenario
#   outcome  : Detected | Missed | Could not check
#   reason   : outcome_reason (None = not asserted)
#   method   : match_method   (None = not asserted)
# The verdict written to OpenAEV follows from the outcome:
#   Detected -> 'Detected'/True, Missed -> 'Not Detected'/False,
#   Could not check -> nothing written (left pending).
# ----------------------------------------------------------------------------
SCENARIOS = {
    # --- original scenarios ---------------------------------------------------
    "detected":          {"outcome": "Detected", "method": "step_marker"},
    "not_detected":      {"outcome": "Missed", "reason": "marker_absent"},
    "prevention":        {"outcome": "Could not check", "reason": "expectation_not_supported"},
    "auth_fail":         {"outcome": "Could not check", "reason": "auth_failed"},
    "token":             {"outcome": "Detected"},
    "ip_only":           {"outcome": "Detected", "method": "legacy"},
    "ipv6":              {"outcome": "Detected", "method": "legacy"},
    "late_alert":        {"outcome": "Detected"},
    # Known limit: an agentless step with only IP signatures has no marker, so a
    # stale alert sharing the IP pair still counts (legacy fallback).
    "ip_bleed":          {"outcome": "Detected", "method": "legacy"},
    # --- step marker matching -------------------------------------------------
    "implant_url":       {"outcome": "Detected", "method": "legacy"},
    "marker_match":      {"outcome": "Detected", "method": "step_marker"},
    "marker_file":       {"outcome": "Detected", "method": "step_marker"},
    "marker_dns":        {"outcome": "Detected", "method": "step_marker"},
    "marker_absent":     {"outcome": "Missed", "reason": "marker_absent"},
    "time_window_miss":  {"outcome": "Missed", "reason": "outside_time_window"},
    "wrong_host":        {"outcome": "Missed", "reason": "wrong_host"},
    # --- could not check causes -----------------------------------------------
    "cnc_unreachable":   {"outcome": "Could not check", "reason": "source_unreachable"},
    "cnc_missing_index": {"outcome": "Could not check", "reason": "data_source_missing"},
    "cnc_search_error":  {"outcome": "Could not check", "reason": "search_failed"},
}

SCENARIO = sys.argv[1] if len(sys.argv) > 1 else "detected"

# ----------------------------------------------------------------------------
# Shared test fixture: one simulated step (inject) and its detection expectation
# ----------------------------------------------------------------------------
INJECT_UUID = "11111111-1111-1111-1111-111111111111"
AGENT_UUID = "22222222-2222-2222-2222-222222222222"
EXPECTATION_ID = str(uuid.uuid4())
SRC_IP = "10.0.0.5"
DST_IP = "10.0.0.9"
SRC_IP6 = "2001:db8::5"
DST_IP6 = "2001:db8::9"
STEP_HOST = "WS-TEST-01"          # host the simulated step ran on
OTHER_HOST = "WS-OTHER-99"
IS_V6 = SCENARIO == "ipv6"
# Parent-process signature the platform emits encodes inject+agent UUIDs
PARENT_PROCESS = f"oaev-implant-{INJECT_UUID}-agent-{AGENT_UUID}"
# The collector reconstructs the parent process from this exact URL-path form
IMPLANT_URL_PATH = f"/api/injects/{INJECT_UUID}/{AGENT_UUID}/executable-payload"
# Step marker forms a benign simulation can carry
MARKER_CMD = f"cmd.exe /c echo oaev-step-{INJECT_UUID}"
MARKER_FILE = f"C:\\Temp\\oaev-step-{INJECT_UUID.replace('-', '')}.txt"
MARKER_DNS = f"oaev-step-{INJECT_UUID}.sim.invalid"

_now = datetime.now(timezone.utc)
START_DATE = (_now - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%S")
END_DATE = (_now + timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%S")
NOW_STR = _now.strftime("%Y-%m-%dT%H:%M:%S")
LONG_AGO_STR = (_now - timedelta(minutes=40)).strftime("%Y-%m-%dT%H:%M:%S")

IP_ONLY_SCENARIOS = ("ip_only", "ipv6", "ip_bleed")
HOSTNAME_SCENARIOS = ("marker_match", "marker_file", "marker_dns", "marker_absent",
                      "time_window_miss", "wrong_host")


def build_expectation_payload(kind="DETECTION", include_parent=True, include_host=False):
    """The dict OpenAEV would return for a pending expectation.

    include_parent=False models a network / agentless inject whose expectation
    carries only IP signatures (no parent-process / implant signature).
    """
    if IS_V6:
        sigs = [
            {"type": "source_ipv6_address", "value": SRC_IP6},
            {"type": "target_ipv6_address", "value": DST_IP6},
        ]
    else:
        sigs = [
            {"type": "source_ipv4_address", "value": SRC_IP},
            {"type": "target_ipv4_address", "value": DST_IP},
        ]
    if include_parent:
        sigs.append({"type": "parent_process_name", "value": PARENT_PROCESS})
    if include_host:
        sigs.append({"type": "target_hostname_address", "value": STEP_HOST})
    sigs += [
        {"type": "start_date", "value": START_DATE},
        {"type": "end_date", "value": END_DATE},
    ]
    return {
        "inject_expectation_id": EXPECTATION_ID,
        "inject_expectation_type": kind,
        "inject_expectation_signatures": sigs,
    }


def splunk_alert_row(match=True):
    """A row as Splunk's search/jobs oneshot JSON would return it."""
    if match:
        return {
            "_time": NOW_STR,
            "src_ip": SRC_IP6 if IS_V6 else SRC_IP,
            "dst_ip": DST_IP6 if IS_V6 else DST_IP,
            "url_path": IMPLANT_URL_PATH,
            "parent_process_name": PARENT_PROCESS,
            "signature": "OpenAEV Implant Callback",
            "rule_name": "ES - Suspicious Beacon",
            "event_type": "notable",
            "severity": "high",
        }
    return {
        "_time": NOW_STR,
        "src_ip": "192.168.254.254",
        "dst_ip": "192.168.254.253",
        "parent_process_name": "explorer.exe",
        "signature": "Unrelated noise",
    }


def stale_ip_alert_row():
    """An alert that shares only the IP pair - e.g. a beacon from a PRIOR run of the
    same action, with NO per-execution implant marker (url_path)."""
    return {
        "_time": NOW_STR,
        "src_ip": SRC_IP,
        "dst_ip": DST_IP,
        "signature": "Prior-run beacon (no implant marker)",
        "event_type": "notable",
    }


def implant_url_row():
    """Proxy/web log of the implant callback: URL + IPs, no process fields."""
    return {
        "_time": NOW_STR,
        "src_ip": SRC_IP,
        "dst_ip": DST_IP,
        "url_path": IMPLANT_URL_PATH,
        "signature": "Proxy - implant download",
    }


def marker_row(host=STEP_HOST, when=None, **fields):
    """EDR-style alert: no IP fields, host name + a field carrying the marker."""
    row = {
        "_time": when or NOW_STR,
        "dest_host": f"{host.lower()}.lab.local",
        "signature": "EDR - suspicious command",
        "rule_name": "ES - Endpoint Suspicious Command",
        "event_type": "notable",
    }
    row.update(fields)
    return row


def splunk_rows():
    """Rows the mock Splunk returns for the current scenario."""
    if SCENARIO == "late_alert":
        return [] if SPLUNK_CALLS["n"] < 2 else [splunk_alert_row(match=True)]
    if SCENARIO == "ip_bleed":
        return [stale_ip_alert_row()]
    if SCENARIO == "not_detected":
        return [splunk_alert_row(match=False)]
    if SCENARIO == "implant_url":
        return [implant_url_row()]
    if SCENARIO == "marker_match":
        return [marker_row(process=MARKER_CMD)]
    if SCENARIO == "marker_file":
        return [marker_row(file_name=MARKER_FILE)]
    if SCENARIO == "marker_dns":
        return [marker_row(query=MARKER_DNS)]
    if SCENARIO == "marker_absent":
        # Right host, right IPs, right time - but nothing ties it to this step.
        row = marker_row(process="powershell.exe -nop -c Get-Process")
        row.update({"src_ip": SRC_IP, "dst_ip": DST_IP})
        return [row]
    if SCENARIO == "time_window_miss":
        return [marker_row(when=LONG_AGO_STR, process=MARKER_CMD)]
    if SCENARIO == "wrong_host":
        return [marker_row(host=OTHER_HOST, process=MARKER_CMD)]
    return [splunk_alert_row(match=True)]


# call counter so "late_alert" can return empty first, then a match on retry
SPLUNK_CALLS = {"n": 0}


# ----------------------------------------------------------------------------
# Mock Splunk ES
# ----------------------------------------------------------------------------
class SplunkHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _auth_ok(self):
        auth = self.headers.get("Authorization", "")
        ok = auth.startswith("Bearer ") if SCENARIO == "token" else auth.startswith("Basic ")
        if SCENARIO == "auth_fail" or not ok:
            log_wire("SPLUNK", "req", f"{self.command} {self.path} (auth={auth[:14] or 'none'})")
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"messages":[{"type":"WARN","text":"login failed"}]}')
            log_wire("SPLUNK", "res", "401 Unauthorized")
            return False
        return True

    def _send_json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.path.startswith("/services/data/indexes/"):
            self._send_json(404, {})
            return
        if not self._auth_ok():
            return
        name = self.path.split("/services/data/indexes/", 1)[1].split("?", 1)[0]
        log_wire("SPLUNK", "req", f"GET /services/data/indexes/{name}  (index check)")
        if SCENARIO == "cnc_missing_index":
            self._send_json(404, {"messages": [{"type": "ERROR",
                                                "text": f"Could not find object id={name}"}]})
            log_wire("SPLUNK", "res", "404 Not Found")
            return
        self._send_json(200, {"entry": [{"name": name}]})
        log_wire("SPLUNK", "res", "200 OK")

    def do_POST(self):
        if not self._auth_ok():
            return
        if SCENARIO == "token":
            print(f"              (authenticated via {self.headers.get('Authorization', '')[:20]}...)")
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode()

        # decode the SPL query that the collector actually built
        from urllib.parse import parse_qs
        spl = parse_qs(raw).get("search", [""])[0]
        log_wire("SPLUNK", "req", f"POST {self.path}  exec_mode=oneshot")
        print(f"              SPL: {spl}")

        SPLUNK_CALLS["n"] += 1
        if SCENARIO == "cnc_search_error":
            payload = {"results": [], "messages": [
                {"type": "ERROR", "text": "Error in 'search' command: search failed"}]}
            self._send_json(200, payload)
            log_wire("SPLUNK", "res", "200 OK (0 rows, ERROR message)", payload["messages"])
            return
        results = splunk_rows()
        payload = {"results": results,
                   "fields": [{"name": k} for k in results[0].keys()] if results else []}
        self._send_json(200, payload)
        log_wire("SPLUNK", "res", f"200 OK ({len(results)} row(s))", results)


# ----------------------------------------------------------------------------
# Mock OpenAEV
# ----------------------------------------------------------------------------
CAPTURED = {"bulk_update": None, "individual": [], "traces": None, "results": []}


class OpenAEVHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _read(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            return json.loads(self.rfile.read(length).decode())
        return None

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if "/injects/expectations/assets/" in self.path:
            kind = "PREVENTION" if SCENARIO == "prevention" else "DETECTION"
            payload = [build_expectation_payload(
                kind,
                include_parent=(SCENARIO not in IP_ONLY_SCENARIOS),
                include_host=(SCENARIO in HOSTNAME_SCENARIOS),
            )]
            log_wire("OPENAEV", "req", f"GET {self.path}")
            self._send(200, payload)
            log_wire("OPENAEV", "res", f"200 OK (1 pending {kind} expectation)", payload)
            return
        self._send(200, [])

    def do_PUT(self):
        body = self._read()
        if self.path.endswith("/expectations/bulk"):
            CAPTURED["bulk_update"] = body
            log_wire("OPENAEV", "req", f"PUT {self.path}  (collector writes verdict)", body)
        else:
            CAPTURED["individual"].append({"path": self.path, "body": body})
            log_wire("OPENAEV", "req", f"PUT {self.path}", body)
        self._send(200, {"status": "ok"})
        log_wire("OPENAEV", "res", "200 OK")

    def do_POST(self):
        body = self._read()
        if "inject-expectations-traces/bulk" in self.path:
            CAPTURED["traces"] = body
            log_wire("OPENAEV", "req", f"POST {self.path}  (collector attaches evidence)", body)
            self._send(200, {"status": "ok"})
            log_wire("OPENAEV", "res", "200 OK")
        else:
            self._send(200, {})


def start(server_cls, handler, port):
    srv = server_cls(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def check(expected, result, verdict):
    """Compare the observed run with the expected result. Returns failure list."""
    failures = []
    if result is None:
        return ["no ExpectationResult produced"]
    outcome = result.outcome.value if result.outcome else None
    if outcome != expected["outcome"]:
        failures.append(f"outcome={outcome!r}, expected {expected['outcome']!r}")
    if "reason" in expected and result.outcome_reason != expected["reason"]:
        failures.append(f"reason={result.outcome_reason!r}, expected {expected['reason']!r}")
    if "method" in expected and result.match_method != expected["method"]:
        failures.append(f"match_method={result.match_method!r}, expected {expected['method']!r}")
    want_verdict = {"Detected": ("Detected", True),
                    "Missed": ("Not Detected", False),
                    "Could not check": None}[expected["outcome"]]
    if verdict != want_verdict:
        failures.append(f"verdict written={verdict!r}, expected {want_verdict!r}")
    return failures


def run_all():
    """Run every scenario in its own process (fresh ports + module state)."""
    print(f"{'scenario':<20} {'result':<6} detail")
    print("-" * 78)
    failed = []
    for name in SCENARIOS:
        proc = subprocess.run(
            [sys.executable, __file__, name], capture_output=True, text=True, timeout=180
        )
        line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("HARNESS ")), "")
        ok = proc.returncode == 0 and line.startswith("HARNESS PASS")
        detail = line.split(" ", 2)[2] if line.count(" ") >= 2 else (proc.stderr.strip()[-200:])
        print(f"{name:<20} {'PASS' if ok else 'FAIL':<6} {detail}")
        if not ok:
            failed.append(name)
    print("-" * 78)
    print(f"{len(SCENARIOS) - len(failed)}/{len(SCENARIOS)} scenarios passed")
    return 1 if failed else 0


def main():
    if SCENARIO == "all":
        sys.exit(run_all())
    if SCENARIO not in SCENARIOS:
        print(f"unknown scenario {SCENARIO!r}; choose one of: all, {', '.join(SCENARIOS)}")
        sys.exit(2)

    logging.basicConfig(level=logging.WARNING, format="%(message)s")
    splunk = start(ThreadingHTTPServer, SplunkHandler, 18089)
    openaev = start(ThreadingHTTPServer, OpenAEVHandler, 18080)

    os.environ.update({
        "OPENAEV_URL": "http://127.0.0.1:18080",
        "OPENAEV_TOKEN": "test-token-1234",
        "COLLECTOR_ID": "splunkes--0b13e3f7-5c9e-46f5-acc4-33032e9b4921",
        "COLLECTOR_NAME": "SplunkES",
        "COLLECTOR_PERIOD": "PT1M",
        # cnc_unreachable points at a closed local port -> connection refused
        "SPLUNKES_BASE_URL": "http://127.0.0.1:18099" if SCENARIO == "cnc_unreachable"
                             else "http://127.0.0.1:18089",
        "SPLUNKES_USERNAME": "svc_openaev",
        "SPLUNKES_PASSWORD": "s3cr3t",
        "SPLUNKES_ALERTS_INDEX": "main",
        "SPLUNKES_TIME_WINDOW": "PT1H",
        # late_alert needs at least one retry so the collector re-polls after the
        # SIEM finishes indexing; other scenarios stay at 0 retries to run fast.
        "SPLUNKES_MAX_RETRY": "3" if SCENARIO == "late_alert" else "0",
        "SPLUNKES_OFFSET": "PT1S",
        "SPLUNKES_VERIFY_SSL": "false",  # mock server is plain HTTP
    })
    if SCENARIO == "token":
        # Prove bearer-token auth: drop basic creds, supply a token instead.
        os.environ.pop("SPLUNKES_USERNAME", None)
        os.environ.pop("SPLUNKES_PASSWORD", None)
        os.environ["SPLUNKES_TOKEN"] = "splunk-bearer-abc123"

    from pyoaev.client import OpenAEV
    from pyoaev.helpers import OpenAEVDetectionHelper
    # Prime package import order exactly like the real entrypoint (src/__main__.py)
    # to avoid the package's circular-import fragility.
    import src.collector.collector  # noqa: F401
    from src.services.utils import SplunkESConfig
    from src.services.expectation_service import SplunkESExpectationService
    from src.services.trace_service import SplunkESTraceService
    from src.collector.expectation_handler import GenericExpectationHandler
    from src.collector.expectation_manager import GenericExpectationManager

    print("=" * 78)
    print(f" SCENARIO: {SCENARIO}")
    print("=" * 78)
    print(" Simulated step (inject):")
    print(f"   inject={INJECT_UUID}  agent={AGENT_UUID}  host={STEP_HOST}")
    print(f"   src_ip={SRC_IP}  dst_ip={DST_IP}  window={START_DATE}..{END_DATE}")
    print(f"   expectation_id={EXPECTATION_ID}")
    print("-" * 78)
    print(" WIRE TRACE (real collector code <-> mock servers):")

    cfg = SplunkESConfig().load
    collector_id = cfg.collector.id

    api = OpenAEV(url=str(cfg.openaev.url), token=cfg.openaev.token, ssl_verify=False)
    exp_service = SplunkESExpectationService(cfg)
    trace_service = SplunkESTraceService(cfg)
    handler = GenericExpectationHandler(exp_service)

    # Capture the ExpectationResults the real handler produces.
    original_batch = handler.handle_batch_expectations

    def capturing_batch(*a, **kw):
        results = original_batch(*a, **kw)
        CAPTURED["results"] = list(results)
        return results

    handler.handle_batch_expectations = capturing_batch

    manager = GenericExpectationManager(
        oaev_api=api,
        collector_id=collector_id,
        expectation_handler=handler,
        trace_service=trace_service,
    )
    detection_helper = OpenAEVDetectionHelper(
        logger=logging.getLogger("dh"),
        relevant_signatures_types=exp_service.get_supported_signatures(),
    )

    summary = manager.process_expectations(detection_helper=detection_helper)

    print("-" * 78)
    print(" RESULT")
    print(f"   processing summary : processed={summary.processed} "
          f"valid={summary.valid} invalid={summary.invalid} skipped={summary.skipped} "
          f"outcomes={summary.outcomes}")
    result = CAPTURED["results"][0] if CAPTURED["results"] else None
    if result is not None:
        print(f"   outcome            : {result.outcome.value} "
              f"(reason={result.outcome_reason}, match_method={result.match_method})")
    verdict = None
    bu = CAPTURED["bulk_update"]
    if bu and bu.get("inputs"):
        for eid, upd in bu["inputs"].items():
            verdict = (upd.get("result"), upd.get("is_success"))
            print(f"   verdict written    : result='{verdict[0]}' is_success={verdict[1]}")
    elif CAPTURED["individual"]:
        upd = CAPTURED["individual"][0]["body"] or {}
        verdict = (upd.get("result"), upd.get("is_success"))
        print(f"   verdict written    : (individual) result='{verdict[0]}'")
    else:
        print("   verdict written    : NONE - expectation left PENDING "
              "(not mislabelled 'Not Detected')")
    tr = CAPTURED["traces"]
    if tr:
        n = len(tr.get("expectation_traces", []))
        print(f"   evidence traces    : {n} trace(s) pushed back to OpenAEV")
    else:
        print("   evidence traces    : none")

    expected = SCENARIOS[SCENARIO]
    failures = check(expected, result, verdict)
    print("=" * 78)
    observed = (f"{result.outcome.value} reason={result.outcome_reason} "
                f"method={result.match_method}") if result else "no result"
    if failures:
        print(f"HARNESS FAIL {observed} :: " + "; ".join(failures))
    else:
        print(f"HARNESS PASS {observed}")

    splunk.shutdown(); openaev.shutdown()
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
