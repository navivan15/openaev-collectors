"""
End-to-end mock harness for the OpenAEV Splunk-ES collector.

Runs the REAL collector code (client_api, expectation_service, converter,
trace_service, expectation_manager, query writer, location memory) against two
in-process mock HTTP servers:

  * Mock Splunk  -> POST /services/search/jobs (SPL search) and
                    GET /services/data/indexes/<name> (index check)
  * Mock OpenAEV -> the expectation + trace REST endpoints

No Docker, no real Splunk, no real OpenAEV, no real hosts. All data is synthetic.

Usage:
  python harness/mock_e2e_harness.py <scenario>        # one scenario, full wire trace
  python harness/mock_e2e_harness.py all               # every scenario, pass/fail table
  python harness/mock_e2e_harness.py prove_templates   # run the repo's query templates
                                                       # against the mock and stamp them
  python harness/mock_e2e_harness.py catalogue         # the scenario catalogue as JSON
  python harness/demo_server.py                        # sandbox demo page on 127.0.0.1:8140

When HARNESS_EVENTS_FILE is set, the run is also written there as structured
events (JSON) - that is what the demo page shows.

Every scenario asserts its result and the process exits non-zero on a mismatch.
"""

import json
import logging
import os
import subprocess
import sys
import tempfile
import threading
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

# make "src" importable exactly like the collector does
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

SCENARIO = sys.argv[1] if len(sys.argv) > 1 else "detected"

EVENTS = []   # structured record of the run, for the demo page


def event(type_, **data):
    EVENTS.append({"type": type_, **data})


def dump_events():
    path = os.environ.get("HARNESS_EVENTS_FILE")
    if path:
        Path(path).write_text(json.dumps(EVENTS, default=str), encoding="utf-8")


def log_wire(system, direction, summary, body=None):
    arrow = "->" if direction == "req" else "<-"
    print(f"   [{system:8}] {arrow} {summary}")
    if body is not None:
        preview = json.dumps(body, default=str)
        if len(preview) > 600:
            preview = preview[:600] + " ...(truncated)"
        print(f"              {preview}")


# ----------------------------------------------------------------------------
# Single-step scenarios: expected outcome, reason, match method.
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
    "late_alert":        {"outcome": "Detected", "searches": ["wide", "wide"]},
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
    # connection drops on the search itself (index check answered fine)
    "cnc_wide_conn":     {"outcome": "Could not check", "reason": "source_unreachable",
                          "path": "wide", "searches": ["wide"]},
    # a custom SPLUNKES_QUERY_TEMPLATE containing '| delete' is never sent
    "query_refused":     {"outcome": "Could not check", "reason": "query_refused",
                          "searches": []},
}

# ----------------------------------------------------------------------------
# Catalogue: what each scenario shows, in plain words (used by the demo page)
# ----------------------------------------------------------------------------
CATALOGUE = [
    ("Tying an alert to a step", [
        ("marker_match", "Marker in a command line",
         "An endpoint event carries the step's marker in its command line and names the right host."),
        ("marker_file", "Marker in a file name",
         "The marker (without dashes) is in the name of a file the step dropped."),
        ("marker_dns", "Marker in a DNS lookup",
         "The step looked up a hostname that contains its marker."),
        ("detected", "Implant process event",
         "An event names the step's implant as parent process. The implant name contains the marker."),
        ("implant_url", "Implant download in proxy logs",
         "Only the implant's download URL and the IP pair are logged. The older matching still ties it to the step."),
        ("ip_only", "Network step, IPs only",
         "A step without an agent has no marker. It is matched on its source and target IP."),
        ("ipv6", "Network step over IPv6",
         "The same IP-only match with IPv6 addresses."),
        ("token", "Token sign-in to Splunk",
         "Same detection, with the collector signing in by bearer token instead of user and password."),
    ]),
    ("Alerts that must not count", [
        ("marker_absent", "Right host, no marker",
         "An alert on the right host, at the right time, with the right IPs, but nothing ties it to this step."),
        ("wrong_host", "Marker on another host",
         "The marker is there, but the alert names a different endpoint."),
        ("time_window_miss", "Marker outside the time window",
         "The marker is there, but the alert is 40 minutes older than the step."),
        ("not_detected", "Unrelated noise",
         "Splunk returns an alert that has nothing to do with the step."),
        ("ip_bleed", "Known limit: stale alert, same IPs",
         "A network step has no marker, so an old alert with the same IP pair still counts. Shown on purpose."),
    ]),
    ("Could not check", [
        ("auth_fail", "Splunk rejects the sign-in",
         "Splunk answers 401. The step is not scored as missed."),
        ("cnc_unreachable", "Splunk is unreachable",
         "Nothing answers on the Splunk port."),
        ("cnc_missing_index", "The index does not exist",
         "The configured index is missing, so an empty search would prove nothing."),
        ("cnc_search_error", "Splunk reports a failed search",
         "Splunk returns no rows and an error message."),
        ("cnc_wide_conn", "Connection drops during the wide search",
         "The index check works, then the connection breaks on the search itself."),
        ("cnc_narrow_conn", "Connection drops during the narrow search",
         "The remembered place cannot be reached. The wide search is not attempted and the memory is kept."),
        ("prevention", "Prevention sent to a detection-only source",
         "Splunk cannot say whether something was blocked."),
    ]),
    ("Query writer", [
        ("batched_markers", "Three steps, one search",
         "Three steps in one cycle share a single search, on the first run and on the repeat run."),
        ("late_alert", "Alert arrives late",
         "The first search is empty; the collector polls again and finds the alert."),
        ("not_yet_due", "Step not due yet",
         "The step only just ended. It is not searched and gets no verdict yet."),
        ("query_refused", "Unsafe query refused",
         "A custom query ending in '| delete' is refused before anything is sent."),
        ("validator_rules", "What the validator refuses",
         "Fifteen searches that write, delete, send, call out, run scripts or lack an index, sourcetype or time window."),
        ("template_proving", "A template must be proven first",
         "A new query template can only be saved after it has been run against the mock."),
    ]),
    ("Location memory", [
        ("memory_narrow_hit", "Repeat run looks in the remembered place",
         "The first run searches wide and remembers where the detection was. The repeat run searches only there."),
        ("memory_late_first_run", "Fewer searches on the repeat run",
         "The first run has to poll twice. The repeat run needs one narrow search."),
        ("memory_wide_fallback", "Detection moved",
         "The remembered place is empty, so the wide search runs and finds it elsewhere. The new place is remembered."),
        ("memory_miss", "Gone from both places",
         "Missed only after the remembered place and the wide search are both empty."),
        ("memory_expired", "Old entry is not trusted",
         "A 60-day-old entry is skipped. The wide search runs and proves the place again."),
        ("memory_periodic_wide", "Every fifth run searches wide",
         "A valid entry exists, but it is time for a wide search so a moved or new detection is seen."),
        ("falcon_id", "Falcon alert forwarded into Splunk",
         "The Falcon alert id is kept in the trace so the same detection can be counted once."),
    ]),
]


def catalogue_json():
    return [{"group": group, "tests": [
        {"id": sid, "title": title, "blurb": blurb} for sid, title, blurb in tests]}
        for group, tests in CATALOGUE]


# ----------------------------------------------------------------------------
# Fixture: synthetic steps (injects) and their expectations
# ----------------------------------------------------------------------------
AGENT_UUID = "22222222-2222-2222-2222-222222222222"
SRC_IP = "10.0.0.5"
DST_IP = "10.0.0.9"
SRC_IP6 = "2001:db8::5"
DST_IP6 = "2001:db8::9"
STEP_HOST = "WS-TEST-01"          # host the simulated step ran on
OTHER_HOST = "WS-OTHER-99"
IS_V6 = SCENARIO == "ipv6"

_now = datetime.now(timezone.utc)
FMT = "%Y-%m-%dT%H:%M:%S"
START = _now - timedelta(minutes=4)
END = _now - timedelta(minutes=1)
START_DATE = START.strftime(FMT)
END_DATE = END.strftime(FMT)
ALERT_TIME = (START + timedelta(seconds=30)).strftime(FMT)   # alert 30 s into the step
LONG_AGO_STR = (_now - timedelta(minutes=40)).strftime(FMT)


def inject_uuid(n=1):
    return f"{n:08d}-1111-1111-1111-111111111111"


def parent_process(n=1):
    """Implant name the platform emits; it encodes inject + agent IDs."""
    return f"oaev-implant-{inject_uuid(n)}-agent-{AGENT_UUID}"


def implant_url(n=1):
    return f"/api/injects/{inject_uuid(n)}/{AGENT_UUID}/executable-payload"


def marker_cmd(n=1):
    return f"cmd.exe /c echo oaev-step-{inject_uuid(n)}"


INJECT_UUID = inject_uuid(1)
MARKER_FILE = f"C:\\Temp\\oaev-step-{INJECT_UUID.replace('-', '')}.txt"
MARKER_DNS = f"oaev-step-{INJECT_UUID}.sim.invalid"

IP_ONLY_SCENARIOS = ("ip_only", "ipv6", "ip_bleed")
HOSTNAME_SCENARIOS = ("marker_match", "marker_file", "marker_dns", "marker_absent",
                      "time_window_miss", "wrong_host")


def expectation(n=1, kind="DETECTION", include_parent=True, include_host=False,
                host=STEP_HOST, start=START_DATE, end=END_DATE):
    """The dict OpenAEV returns for a pending expectation of step n."""
    if IS_V6:
        sigs = [{"type": "source_ipv6_address", "value": SRC_IP6},
                {"type": "target_ipv6_address", "value": DST_IP6}]
    else:
        sigs = [{"type": "source_ipv4_address", "value": SRC_IP},
                {"type": "target_ipv4_address", "value": DST_IP}]
    if include_parent:
        sigs.append({"type": "parent_process_name", "value": parent_process(n)})
    if include_host:
        sigs.append({"type": "target_hostname_address", "value": host})
    sigs += [{"type": "start_date", "value": start},
             {"type": "end_date", "value": end}]
    return {
        "inject_expectation_id": str(uuid.uuid4()),
        "inject_expectation_type": kind,
        "inject_expectation_name": "Detection",
        # OpenAEV gives every run new inject IDs; the asset ID is what stays.
        "inject_expectation_inject": inject_uuid(n),
        "inject_expectation_asset": f"asset-{host.lower()}",
        "inject_expectation_signatures": sigs,
    }


def memory_key(host=STEP_HOST):
    return f"asset:asset-{host.lower()}|expectation:detection"


# ---- rows the mock Splunk can return ---------------------------------------
def splunk_alert_row(match=True, n=1):
    if match:
        return {
            "_time": ALERT_TIME,
            "src_ip": SRC_IP6 if IS_V6 else SRC_IP,
            "dst_ip": DST_IP6 if IS_V6 else DST_IP,
            "url_path": implant_url(n),
            "parent_process_name": parent_process(n),
            "signature": "OpenAEV Implant Callback",
            "rule_name": "Suspicious Beacon",
            "severity": "high",
        }
    return {
        "_time": ALERT_TIME,
        "src_ip": "192.168.254.254",
        "dst_ip": "192.168.254.253",
        "parent_process_name": "explorer.exe",
        "signature": "Unrelated noise",
    }


def stale_ip_alert_row():
    """Shares only the IP pair - e.g. a beacon from a PRIOR run, no marker."""
    return {"_time": ALERT_TIME, "src_ip": SRC_IP, "dst_ip": DST_IP,
            "signature": "Prior-run beacon (no implant marker)"}


def implant_url_row(n=1):
    """Proxy/web log of the implant callback: URL + IPs, no process fields."""
    return {"_time": ALERT_TIME, "src_ip": SRC_IP, "dst_ip": DST_IP,
            "url_path": implant_url(n), "signature": "Proxy - implant download"}


def marker_row(host=STEP_HOST, when=None, sourcetype="XmlWinEventLog", **fields):
    """Endpoint event from a plain index: host name + a field carrying the marker."""
    row = {
        "_time": when or ALERT_TIME,
        "index": "main",
        "sourcetype": sourcetype,
        "dest_host": f"{host.lower()}.lab.local",
        "signature": "Suspicious command line",
        "rule_name": "Endpoint Suspicious Command",
    }
    row.update(fields)
    return row


def single_step_rows(kind, call_no):
    """Rows for the single-step scenarios."""
    if SCENARIO == "late_alert":
        return [] if call_no < 2 else [splunk_alert_row(match=True)]
    if SCENARIO == "ip_bleed":
        return [stale_ip_alert_row()]
    if SCENARIO == "not_detected":
        return [splunk_alert_row(match=False)]
    if SCENARIO == "implant_url":
        return [implant_url_row()]
    if SCENARIO == "marker_match":
        return [marker_row(process=marker_cmd())]
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
        return [marker_row(when=LONG_AGO_STR, process=marker_cmd())]
    if SCENARIO == "wrong_host":
        return [marker_row(host=OTHER_HOST, process=marker_cmd())]
    return [splunk_alert_row(match=True)]


# ----------------------------------------------------------------------------
# Mutable mock state (multi-run scenarios change it between cycles)
# ----------------------------------------------------------------------------
STATE = {
    "expectations": [],          # what the mock OpenAEV hands out
    "rows": single_step_rows,    # fn(kind, call_no) -> rows; kind = narrow | wide
    "searches": [],              # kind of every search POST that reached Splunk
    "spl": [],                   # the SPL of every search POST
    "drop_search": False,        # close the connection on a search POST
}
CAPTURED = {"bulk_update": None, "individual": [], "traces": None, "results": []}


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
            event("auth_failed")
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
            event("index_check", index=name, ok=False)
            return
        self._send_json(200, {"entry": [{"name": name}]})
        log_wire("SPLUNK", "res", "200 OK")
        event("index_check", index=name, ok=True)

    def do_POST(self):
        if not self._auth_ok():
            return
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode()
        spl = parse_qs(raw).get("search", [""])[0]
        if spl.startswith("search "):
            spl = spl[7:]
        kind = "narrow" if spl.lstrip().startswith("(") else "wide"
        STATE["searches"].append(kind)
        STATE["spl"].append(spl)
        log_wire("SPLUNK", "req", f"POST {self.path}  exec_mode=oneshot  [{kind} search]")
        print(f"              SPL: {spl}")
        event("search", kind=kind, spl=spl)

        if STATE["drop_search"]:
            event("dropped", kind=kind)
            # Simulate a connection that breaks mid-request: no response at all.
            log_wire("SPLUNK", "res", "(connection dropped)")
            self.close_connection = True
            try:
                self.connection.shutdown(2)
            except OSError:
                pass
            return
        if SCENARIO == "cnc_search_error":
            payload = {"results": [], "messages": [
                {"type": "ERROR", "text": "Error in 'search' command: search failed"}]}
            self._send_json(200, payload)
            log_wire("SPLUNK", "res", "200 OK (0 rows, ERROR message)", payload["messages"])
            event("search_error", message=payload["messages"][0]["text"])
            return
        results = [dict(r) for r in STATE["rows"](kind, len(STATE["searches"]))]
        for row in results:   # every real row has these; default them for old fixtures
            row.setdefault("index", "main")
            row.setdefault("sourcetype", "mock:events")
        payload = {"results": results,
                   "fields": [{"name": k} for k in results[0].keys()] if results else []}
        self._send_json(200, payload)
        log_wire("SPLUNK", "res", f"200 OK ({len(results)} row(s))", results)
        event("rows", kind=kind, rows=results)


class OpenAEVHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _read(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length).decode()) if length else None

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if "/injects/expectations/assets/" in self.path:
            payload = STATE["expectations"]
            log_wire("OPENAEV", "req", f"GET {self.path}")
            self._send(200, payload)
            log_wire("OPENAEV", "res", f"200 OK ({len(payload)} pending expectation(s))", payload)
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


def start(handler, port):
    srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ----------------------------------------------------------------------------
# Collector under test
# ----------------------------------------------------------------------------
MEMORY_FILE = Path(tempfile.mkdtemp(prefix="oaev-harness-")) / "location_memory.json"


def set_env(**overrides):
    env = {
        "OPENAEV_URL": "http://127.0.0.1:18080",
        "OPENAEV_TOKEN": "test-token-1234",
        "COLLECTOR_ID": "splunkes--0b13e3f7-5c9e-46f5-acc4-33032e9b4921",
        "COLLECTOR_NAME": "SplunkES",
        "COLLECTOR_PERIOD": "PT1M",
        "SPLUNKES_BASE_URL": "http://127.0.0.1:18089",
        "SPLUNKES_USERNAME": "svc_openaev",
        "SPLUNKES_PASSWORD": "s3cr3t",
        "SPLUNKES_ALERTS_INDEX": "main",
        "SPLUNKES_TIME_WINDOW": "PT1H",
        "SPLUNKES_MAX_RETRY": "0",
        "SPLUNKES_OFFSET": "PT1S",
        "SPLUNKES_VERIFY_SSL": "false",  # mock server is plain HTTP
        "SPLUNKES_MEMORY_PATH": str(MEMORY_FILE),
    }
    env.update(overrides)
    os.environ.update(env)


def new_collector():
    """A fresh collector (as after a restart): reloads config and the memory file."""
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

    cfg = SplunkESConfig().load
    api = OpenAEV(url=str(cfg.openaev.url), token=cfg.openaev.token, ssl_verify=False)
    service = SplunkESExpectationService(cfg)
    handler = GenericExpectationHandler(service)
    original_batch = handler.handle_batch_expectations

    def capturing_batch(*a, **kw):
        results = original_batch(*a, **kw)
        CAPTURED["results"] = list(results)
        return results

    handler.handle_batch_expectations = capturing_batch
    manager = GenericExpectationManager(
        oaev_api=api, collector_id=cfg.collector.id,
        expectation_handler=handler, trace_service=SplunkESTraceService(cfg),
    )
    helper = OpenAEVDetectionHelper(
        logger=logging.getLogger("dh"),
        relevant_signatures_types=service.get_supported_signatures(),
    )
    return {"manager": manager, "helper": helper, "service": service}


def cycle(collector, expectations):
    """Run one collector cycle. Returns what happened."""
    STATE["expectations"] = expectations
    STATE["searches"], STATE["spl"] = [], []
    CAPTURED.update({"bulk_update": None, "individual": [], "traces": None, "results": []})
    print(f" CYCLE ({len(expectations)} expectation(s)) - wire trace:")
    steps = []
    for exp in expectations:
        sigs = {}
        for sig in exp["inject_expectation_signatures"]:
            sigs.setdefault(sig["type"], sig["value"])
        steps.append({
            "id": exp["inject_expectation_id"],
            "kind": exp["inject_expectation_type"],
            "inject": exp["inject_expectation_inject"],
            "asset": exp["inject_expectation_asset"],
            "has_marker": "parent_process_name" in sigs,
            "host": sigs.get("target_hostname_address"),
            "source_ip": sigs.get("source_ipv4_address") or sigs.get("source_ipv6_address"),
            "target_ip": sigs.get("target_ipv4_address") or sigs.get("target_ipv6_address"),
            "start": sigs.get("start_date"),
            "end": sigs.get("end_date"),
        })
    event("cycle_start", steps=steps, memory=read_memory())
    summary = collector["manager"].process_expectations(detection_helper=collector["helper"])
    verdicts = {}
    bulk = CAPTURED["bulk_update"]
    if bulk and bulk.get("inputs"):
        for eid, upd in bulk["inputs"].items():
            verdicts[eid] = (upd.get("result"), upd.get("is_success"))
    traces = (CAPTURED["traces"] or {}).get("expectation_traces", [])
    event(
        "cycle_end",
        results=[{
            "id": r.expectation_id,
            "outcome": r.outcome.value,
            "reason": r.outcome_reason,
            "method": r.match_method,
            "field": r.match_field,
            "path": r.search_path,
            "message": r.error_message,
            "verdict": verdicts.get(r.expectation_id),
        } for r in CAPTURED["results"]],
        traces=[t.get("inject_expectation_trace_alert_name") for t in traces],
        searches=list(STATE["searches"]),
        deferred=summary.deferred,
        memory=read_memory(),
    )
    return {
        "summary": summary,
        "results": {r.expectation_id: r for r in CAPTURED["results"]},
        "verdicts": verdicts,
        "traces": traces,
        "searches": list(STATE["searches"]),
        "spl": list(STATE["spl"]),
    }


def describe(run):
    print(" RESULT")
    for eid, r in run["results"].items():
        print(f"   outcome            : {r.outcome.value} (reason={r.outcome_reason}, "
              f"match_method={r.match_method}, search_path={r.search_path})")
        v = run["verdicts"].get(eid)
        print("   verdict written    : "
              + (f"result='{v[0]}' is_success={v[1]}" if v
                 else "NONE - left pending (not mislabelled 'Not Detected')"))
    print(f"   searches sent      : {run['searches']}")
    print(f"   evidence traces    : {len(run['traces'])}")
    for t in run["traces"]:
        print(f"       {t.get('inject_expectation_trace_alert_name')}")
    print("-" * 78)


WANT_VERDICT = {"Detected": ("Detected", True), "Missed": ("Not Detected", False),
                "Could not check": None}


def check_result(run, exp, outcome, reason=None, method=None, path=None):
    """Failures for one expectation of a run."""
    eid = exp["inject_expectation_id"]
    r = run["results"].get(eid)
    if r is None:
        return [f"no result for step {exp['inject_expectation_inject']}"]
    fails = []
    if r.outcome.value != outcome:
        fails.append(f"outcome={r.outcome.value!r}, expected {outcome!r}")
    if reason is not None and r.outcome_reason != reason:
        fails.append(f"reason={r.outcome_reason!r}, expected {reason!r}")
    if method is not None and r.match_method != method:
        fails.append(f"match_method={r.match_method!r}, expected {method!r}")
    if path is not None and r.search_path != path:
        fails.append(f"search_path={r.search_path!r}, expected {path!r}")
    if run["verdicts"].get(eid) != WANT_VERDICT[outcome]:
        fails.append(f"verdict={run['verdicts'].get(eid)!r}, expected {WANT_VERDICT[outcome]!r}")
    return fails


def expect_searches(run, want):
    return [] if run["searches"] == want else [f"searches={run['searches']}, expected {want}"]


def read_memory():
    if not MEMORY_FILE.exists():
        return {}
    return json.loads(MEMORY_FILE.read_text(encoding="utf-8")).get("entries", {})


def seed_memory(sourcetype="XmlWinEventLog", age_days=0, narrow_runs=0, host=STEP_HOST):
    proven = datetime.now(timezone.utc) - timedelta(days=age_days)
    MEMORY_FILE.write_text(json.dumps({"version": 1, "entries": {memory_key(host): {
        "narrow_runs_since_wide": narrow_runs,
        "locations": [{"index": "main", "sourcetype": sourcetype, "field": "process",
                       "rule_name": "Endpoint Suspicious Command", "delay_seconds": 30.0,
                       "found_on": proven.date().isoformat(),
                       "proven_at": proven.isoformat()}]}}}), encoding="utf-8")


# ----------------------------------------------------------------------------
# Single-step scenario runner
# ----------------------------------------------------------------------------
def run_single():
    spec = SCENARIOS[SCENARIO]
    overrides = {}
    if SCENARIO == "cnc_unreachable":      # closed local port -> connection refused
        overrides["SPLUNKES_BASE_URL"] = "http://127.0.0.1:18099"
    if SCENARIO == "late_alert":           # needs a retry so the collector re-polls
        overrides["SPLUNKES_MAX_RETRY"] = "3"
    if SCENARIO == "query_refused":
        overrides["SPLUNKES_QUERY_TEMPLATE"] = (
            "index={alerts_index} sourcetype=* earliest={start_date} latest={end_date} | delete")
    set_env(**overrides)
    if SCENARIO == "token":                # bearer token instead of basic credentials
        os.environ.pop("SPLUNKES_USERNAME", None)
        os.environ.pop("SPLUNKES_PASSWORD", None)
        os.environ["SPLUNKES_TOKEN"] = "splunk-bearer-abc123"
    STATE["drop_search"] = SCENARIO == "cnc_wide_conn"

    exp = expectation(
        kind="PREVENTION" if SCENARIO == "prevention" else "DETECTION",
        include_parent=SCENARIO not in IP_ONLY_SCENARIOS,
        include_host=SCENARIO in HOSTNAME_SCENARIOS,
    )
    run = cycle(new_collector(), [exp])
    describe(run)
    fails = check_result(run, exp, spec["outcome"], spec.get("reason"),
                         spec.get("method"), spec.get("path"))
    if "searches" in spec:
        fails += expect_searches(run, spec["searches"])
    r = run["results"].get(exp["inject_expectation_id"])
    note = (f"{r.outcome.value} reason={r.outcome_reason} method={r.match_method} "
            f"searches={len(run['searches'])}") if r else "no result"
    return fails, note


# ----------------------------------------------------------------------------
# Multi-run scenarios (query writer, location memory, batching)
# ----------------------------------------------------------------------------
def rows_marker_for(*steps, sourcetype="XmlWinEventLog", only_kind=None, extra=None):
    """Row function: one marker row per (n, host), optionally only for one search kind."""
    def rows(kind, call_no):
        if only_kind and kind != only_kind:
            return []
        out = []
        for n, host in steps:
            row = marker_row(host=host, sourcetype=sourcetype, process=marker_cmd(n))
            row.update(extra or {})
            out.append(row)
        return out
    return rows


def flow_memory_narrow_hit():
    """First run searches wide and remembers; the repeat run searches the remembered place."""
    set_env()
    fails = []
    first = expectation(n=1, include_host=True)
    STATE["rows"] = rows_marker_for((1, STEP_HOST))
    run1 = cycle(new_collector(), [first])
    describe(run1)
    fails += check_result(run1, first, "Detected", method="step_marker", path="wide")
    fails += expect_searches(run1, ["wide"])
    entry = read_memory().get(memory_key(), {})
    loc = (entry.get("locations") or [{}])[0]
    if (loc.get("index"), loc.get("sourcetype"), loc.get("field")) != \
            ("main", "XmlWinEventLog", "process"):
        fails.append(f"memory after first run = {loc}")

    repeat = expectation(n=2, include_host=True)       # same test, new run -> new inject ID
    STATE["rows"] = rows_marker_for((2, STEP_HOST))
    run2 = cycle(new_collector(), [repeat])            # new collector = restart, memory from file
    describe(run2)
    fails += check_result(run2, repeat, "Detected", method="step_marker", path="narrow")
    fails += expect_searches(run2, ["narrow"])
    if 'sourcetype="XmlWinEventLog"' not in (run2["spl"] or [""])[0]:
        fails.append("narrow search does not name the remembered sourcetype")
    if len(run2["searches"]) > len(run1["searches"]):
        fails.append("repeat run sent more searches than the first run")
    return fails, (f"first run {len(run1['searches'])} search (wide), "
                   f"repeat run {len(run2['searches'])} search (narrow)")


def flow_memory_late_first_run():
    """First run has to poll for a late alert; the repeat run needs one narrow search."""
    set_env(SPLUNKES_MAX_RETRY="3")
    fails = []
    first = expectation(n=1, include_host=True)
    hit = rows_marker_for((1, STEP_HOST))
    STATE["rows"] = lambda kind, call_no: [] if call_no < 2 else hit(kind, call_no)
    run1 = cycle(new_collector(), [first])
    describe(run1)
    fails += check_result(run1, first, "Detected", path="wide")
    fails += expect_searches(run1, ["wide", "wide"])

    repeat = expectation(n=2, include_host=True)
    STATE["rows"] = rows_marker_for((2, STEP_HOST))
    run2 = cycle(new_collector(), [repeat])
    describe(run2)
    fails += check_result(run2, repeat, "Detected", path="narrow")
    fails += expect_searches(run2, ["narrow"])
    if not len(run2["searches"]) < len(run1["searches"]):
        fails.append("repeat run did not send fewer searches than the first run")
    return fails, (f"first run {len(run1['searches'])} searches (polled), "
                   f"repeat run {len(run2['searches'])} search (narrow)")


def flow_memory_wide_fallback():
    """Remembered place is empty -> wide search finds it elsewhere -> new place remembered first."""
    set_env()
    seed_memory(sourcetype="old:sourcetype")
    exp = expectation(n=3, include_host=True)
    STATE["rows"] = rows_marker_for((3, STEP_HOST), sourcetype="XmlWinEventLog", only_kind="wide")
    run = cycle(new_collector(), [exp])
    describe(run)
    fails = check_result(run, exp, "Detected", path="wide")
    fails += expect_searches(run, ["narrow", "wide"])
    newest = (read_memory().get(memory_key(), {}).get("locations") or [{}])[0]
    if newest.get("sourcetype") != "XmlWinEventLog":
        fails.append(f"memory not updated to the new place: {newest}")
    return fails, "narrow empty, wide hit, new place added to the memory"


def flow_memory_miss():
    """Remembered place empty AND wide empty -> Missed, only after both searches."""
    set_env()
    seed_memory()
    exp = expectation(n=4, include_host=True)
    STATE["rows"] = lambda kind, call_no: []
    run = cycle(new_collector(), [exp])
    describe(run)
    fails = check_result(run, exp, "Missed", reason="no_alerts", path="wide")
    fails += expect_searches(run, ["narrow", "wide"])
    if memory_key() in read_memory():
        fails.append("memory entry kept after a confirmed miss")
    return fails, "narrow empty, wide empty -> Missed; entry forgotten"


def flow_memory_expired():
    """An expired entry is not trusted: wide search, then re-proven."""
    set_env()
    seed_memory(age_days=60)                             # TTL default is 30 days
    exp = expectation(n=5, include_host=True)
    STATE["rows"] = rows_marker_for((5, STEP_HOST))
    run = cycle(new_collector(), [exp])
    describe(run)
    fails = check_result(run, exp, "Detected", path="wide")
    fails += expect_searches(run, ["wide"])
    loc = (read_memory().get(memory_key(), {}).get("locations") or [{}])[0]
    if loc.get("found_on") != datetime.now(timezone.utc).date().isoformat():
        fails.append(f"entry not re-proven today: {loc}")
    return fails, "expired entry skipped, wide search, re-proven today"


def flow_memory_periodic_wide():
    """Every Nth run searches wide even with a valid entry (default N=5)."""
    set_env()
    seed_memory(narrow_runs=4)                           # 4 narrow runs since last wide
    exp = expectation(n=6, include_host=True)
    STATE["rows"] = rows_marker_for((6, STEP_HOST))
    run = cycle(new_collector(), [exp])
    describe(run)
    fails = check_result(run, exp, "Detected", path="wide")
    fails += expect_searches(run, ["wide"])
    counter = read_memory().get(memory_key(), {}).get("narrow_runs_since_wide")
    if counter != 0:
        fails.append(f"narrow-run counter not reset after the wide search: {counter}")
    return fails, "5th run went wide despite a valid entry; counter reset"


def flow_batched_markers():
    """Three steps in one cycle share ONE search, on the first run and on the repeat."""
    set_env()
    hosts = ["WS-TEST-01", "WS-TEST-02", "WS-TEST-03"]
    fails = []
    first = [expectation(n=i + 1, include_host=True, host=h) for i, h in enumerate(hosts)]
    STATE["rows"] = rows_marker_for(*[(i + 1, h) for i, h in enumerate(hosts)])
    run1 = cycle(new_collector(), first)
    describe(run1)
    for exp in first:
        fails += check_result(run1, exp, "Detected", method="step_marker", path="wide")
    fails += expect_searches(run1, ["wide"])
    for i in range(3):
        if inject_uuid(i + 1) not in (run1["spl"] or [""])[0]:
            fails.append(f"wide search does not cover step {i + 1}")

    repeat = [expectation(n=i + 11, include_host=True, host=h) for i, h in enumerate(hosts)]
    STATE["rows"] = rows_marker_for(*[(i + 11, h) for i, h in enumerate(hosts)])
    run2 = cycle(new_collector(), repeat)
    describe(run2)
    for exp in repeat:
        fails += check_result(run2, exp, "Detected", path="narrow")
    fails += expect_searches(run2, ["narrow"])
    return fails, (f"3 steps: first run {len(run1['searches'])} search, repeat run "
                   f"{len(run2['searches'])} search (one search per step would be 3)")


def flow_cnc_narrow_conn():
    """Connection breaks on the narrow search -> Could not check, wide not attempted."""
    set_env()
    seed_memory()
    STATE["drop_search"] = True
    exp = expectation(n=7, include_host=True)
    run = cycle(new_collector(), [exp])
    describe(run)
    fails = check_result(run, exp, "Could not check", reason="source_unreachable", path="narrow")
    fails += expect_searches(run, ["narrow"])
    if memory_key() not in read_memory():
        fails.append("memory entry dropped although nothing was checked")
    return fails, "narrow search connection dropped -> Could not check, memory kept"


def flow_not_yet_due():
    """A step whose alerts are not due yet is not searched and gets no verdict."""
    set_env()
    exp = expectation(n=8, include_host=True,
                      end=(_now + timedelta(minutes=2)).strftime(FMT))
    run = cycle(new_collector(), [exp])
    describe(run)
    fails = expect_searches(run, [])
    if run["results"] or run["verdicts"]:
        fails.append("a not-yet-due step got a result or a verdict")
    if run["summary"].deferred != 1:
        fails.append(f"deferred={run['summary'].deferred}, expected 1")
    return fails, "step still inside its alert delay: 0 searches, no verdict"


def flow_falcon_id():
    """A forwarded CrowdStrike alert keeps its Falcon alert id in the trace."""
    set_env()
    falcon_id = "cid0a1b2c:ind:9f8e7d:4242-10357-99"
    exp = expectation(n=9, include_host=True)
    STATE["rows"] = rows_marker_for(
        (9, STEP_HOST), sourcetype="crowdstrike:events:sensor",
        extra={"event.CompositeId": falcon_id})
    run = cycle(new_collector(), [exp])
    describe(run)
    fails = check_result(run, exp, "Detected", method="step_marker")
    name = run["traces"][0].get("inject_expectation_trace_alert_name", "") if run["traces"] else ""
    for piece in (f"falcon_alert_id={falcon_id}", "index=main",
                  "sourcetype=crowdstrike:events:sensor", "field=process"):
        if piece not in name:
            fails.append(f"trace name lacks '{piece}': {name!r}")
    return fails, "trace name carries index, sourcetype, field and falcon_alert_id"


def flow_validator_rules():
    """The validator refuses anything that writes, deletes, sends, calls out or runs scripts."""
    import src.collector.collector  # noqa: F401
    from src.services.spl_validator import SplunkESQueryRefusedError, validate_spl
    ok = "index=main sourcetype=x earliest=1 latest=2"
    refused = {
        "writes (outputlookup)": ok + " | outputlookup x.csv",
        "writes (collect)": ok + " | collect index=summary",
        "deletes": ok + " | delete",
        "sends (sendemail)": ok + ' | sendemail to="a@example.invalid"',
        "calls out (rest)": "| rest /services/server/info",
        "runs scripts (script)": ok + " | script python x",
        "runs other searches (map)": ok + ' | map search="search index=main"',
        "transforms (eval, not on the list)": ok + " | eval a=1",
        "subsearch": "index=main sourcetype=x [search index=other] earliest=1 latest=2",
        "macro": "index=main sourcetype=x `some_macro` earliest=1 latest=2",
        "no index": "sourcetype=x earliest=1 latest=2 | table _time",
        "wildcard index": "index=* sourcetype=x earliest=1 latest=2",
        "no sourcetype": "index=main earliest=1 latest=2 | table _time",
        "no time window": "index=main sourcetype=x | table _time",
        "half a time window": "index=main sourcetype=x earliest=1 | table _time",
    }
    accepted = {
        "filter + select + limit":
            ok + ' "abc" | where x=1 | table _time, host | sort 0 -_time | head 10',
        "count": ok + " | stats count by sourcetype",
        "pipe inside a quoted term": ok + ' "a | delete" | table _time',
    }
    fails = []
    for label, spl in refused.items():
        try:
            validate_spl(spl)
            fails.append(f"NOT refused: {label}")
        except SplunkESQueryRefusedError as e:
            print(f"   refused  {label:<36} {e}")
            event("validator", label=label, spl=spl, refused=True, message=str(e))
    for label, spl in accepted.items():
        try:
            validate_spl(spl)
            print(f"   accepted {label}")
            event("validator", label=label, spl=spl, refused=False, message="")
        except SplunkESQueryRefusedError as e:
            fails.append(f"wrongly refused: {label} ({e})")
    return fails, f"{len(refused)} searches refused, {len(accepted)} accepted"


def flow_template_proving():
    """A template can only be used after it was run against the mock."""
    set_env()
    collector = new_collector()
    from src.services.query_writer import TemplateStore
    from src.services.spl_validator import SplunkESQueryRefusedError
    client = collector["service"].client_api
    STATE["rows"] = lambda kind, call_no: []
    path = MEMORY_FILE.with_name("templates.json")
    path.write_text(json.dumps({"version": 1, "templates": [
        {"id": "unproven", "purpose": "wide",
         "spl": "index={index} {sourcetype_filter} earliest={earliest} latest={latest} "
                "| table {fields}"}
    ]}), encoding="utf-8")
    store = TemplateStore(path)
    good = {"id": "count_by_sourcetype", "purpose": "wide",
            "spl": "index={index} {sourcetype_filter} ({step_filter}) earliest={earliest} "
                   "latest={latest} | stats count by sourcetype"}
    bad = dict(good, id="exfil", spl=good["spl"] + " | outputlookup stolen.csv")
    odd = dict(good, id="odd", spl=good["spl"].replace("{index}", "{anything}"))
    fails = []

    def refused(label, fn):
        try:
            fn()
            fails.append(f"NOT refused: {label}")
        except SplunkESQueryRefusedError as e:
            print(f"   refused  {label:<40} {e}")
            event("template", label=label, refused=True, message=str(e))

    values = dict(index="main", sourcetype_filter="sourcetype=*", step_filter='("x")',
                  earliest=1, latest=2, fields="_time", limit=10)
    refused("render of an unproven template", lambda: store.render("unproven", **values))
    refused("save without running it", lambda: store.add(good, run_search=None))
    refused("template with a refused command", lambda: store.add(bad, client.run_search))
    refused("template with an unknown placeholder", lambda: store.add(odd, client.run_search))
    sent_before = len(STATE["searches"])
    saved = store.add(good, client.run_search, against="mock_e2e_harness")
    if len(STATE["searches"]) != sent_before + 1:
        fails.append("the new template was not run against the mock before saving")
    if not saved.get("proven"):
        fails.append("saved template has no proven stamp")
    event("template", label="new template, run against the mock first", refused=False,
          message=f"saved with stamp {json.dumps(saved.get('proven'))}", spl=saved["spl"])
    reloaded = TemplateStore(path)
    if reloaded.ids() != ["count_by_sourcetype"]:
        fails.append(f"usable templates after reload: {reloaded.ids()}")
    try:
        reloaded.render("count_by_sourcetype", **values)
    except SplunkESQueryRefusedError as e:
        fails.append(f"proven template refused: {e}")
    shipped = TemplateStore().ids()
    if sorted(shipped) != ["host_window_search", "narrow_location_search", "wide_step_search"]:
        fails.append(f"shipped templates usable: {shipped}")
    return fails, "unproven / unsafe templates refused; new one saved only after a mock run"


FLOWS = {
    "memory_narrow_hit": flow_memory_narrow_hit,
    "memory_late_first_run": flow_memory_late_first_run,
    "memory_wide_fallback": flow_memory_wide_fallback,
    "memory_miss": flow_memory_miss,
    "memory_expired": flow_memory_expired,
    "memory_periodic_wide": flow_memory_periodic_wide,
    "batched_markers": flow_batched_markers,
    "cnc_narrow_conn": flow_cnc_narrow_conn,
    "not_yet_due": flow_not_yet_due,
    "falcon_id": flow_falcon_id,
    "validator_rules": flow_validator_rules,
    "template_proving": flow_template_proving,
}


def prove_templates():
    """Run the repo's query templates against the mock Splunk and stamp them."""
    set_env()
    collector = new_collector()
    from src.services.query_writer import TemplateStore
    STATE["rows"] = lambda kind, call_no: []
    ids = TemplateStore().prove_existing(collector["service"].client_api.run_search,
                                         against="mock_e2e_harness")
    fails = [] if len(STATE["searches"]) == len(ids) else ["not every template was run"]
    return fails, f"proven and stamped: {', '.join(ids)}"


def run_all():
    """Run every scenario in its own process (fresh ports, memory file, module state)."""
    names = list(SCENARIOS) + list(FLOWS)
    print(f"{'scenario':<22} {'result':<6} detail")
    print("-" * 100)
    failed = []
    for name in names:
        proc = subprocess.run([sys.executable, __file__, name],
                              capture_output=True, text=True, timeout=240)
        line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("HARNESS ")), "")
        ok = proc.returncode == 0 and line.startswith("HARNESS PASS")
        detail = line.split(" ", 2)[2] if line.count(" ") >= 2 else proc.stderr.strip()[-300:]
        print(f"{name:<22} {'PASS' if ok else 'FAIL':<6} {detail}")
        if not ok:
            failed.append(name)
    print("-" * 100)
    print(f"{len(names) - len(failed)}/{len(names)} scenarios passed")
    return 1 if failed else 0


def main():
    if SCENARIO == "all":
        sys.exit(run_all())
    if SCENARIO == "catalogue":
        print(json.dumps(catalogue_json()))
        sys.exit(0)
    known = list(SCENARIOS) + list(FLOWS) + ["prove_templates"]
    if SCENARIO not in known:
        print(f"unknown scenario {SCENARIO!r}; choose one of: all, {', '.join(known)}")
        sys.exit(2)

    logging.basicConfig(level=logging.WARNING, format="%(message)s")
    splunk = start(SplunkHandler, 18089)
    openaev = start(OpenAEVHandler, 18080)
    print("=" * 78)
    print(f" SCENARIO: {SCENARIO}")
    print("=" * 78)
    if SCENARIO == "prove_templates":
        fails, note = prove_templates()
    elif SCENARIO in FLOWS:
        fails, note = FLOWS[SCENARIO]()
    else:
        fails, note = run_single()
    print("=" * 78)
    if fails:
        print(f"HARNESS FAIL {note} :: " + "; ".join(fails))
    else:
        print(f"HARNESS PASS {note}")
    event("harness", ok=not fails, note=note, fails=fails)
    dump_events()
    splunk.shutdown()
    openaev.shutdown()
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
