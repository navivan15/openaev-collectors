"""
End-to-end mock harness for the OpenAEV Splunk-ES collector.

Runs the REAL collector code (client_api, expectation_service, converter,
trace_service, expectation_manager) against two in-process mock HTTP servers:

  * Mock Splunk ES  -> answers POST /services/search/jobs (SPL search)
  * Mock OpenAEV    -> answers the expectation + trace REST endpoints

No Docker, no real Splunk, no real OpenAEV. Everything runs in one process so
we can watch the entire message flow and judge whether the round-trip data is
rich enough or limited.

Scenarios (pass as argv[1]): detected | not_detected | prevention | auth_fail
"""

import json
import logging
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
# Shared test fixture: one simulated attack (inject) and its detection expectation
# ----------------------------------------------------------------------------
INJECT_UUID = "11111111-1111-1111-1111-111111111111"
AGENT_UUID = "22222222-2222-2222-2222-222222222222"
EXPECTATION_ID = str(uuid.uuid4())
SRC_IP = "10.0.0.5"
DST_IP = "10.0.0.9"
SRC_IP6 = "2001:db8::5"
DST_IP6 = "2001:db8::9"
IS_V6 = (len(sys.argv) > 1 and sys.argv[1] == "ipv6")
# Parent-process signature the platform emits encodes inject+agent UUIDs
PARENT_PROCESS = f"oaev-implant-{INJECT_UUID}-agent-{AGENT_UUID}"
# The collector reconstructs the parent process from this exact URL-path form
IMPLANT_URL_PATH = f"/api/injects/{INJECT_UUID}/{AGENT_UUID}/executable-payload"

_now = datetime.now(timezone.utc)
START_DATE = (_now - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%S")
END_DATE = (_now + timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%S")

SCENARIO = sys.argv[1] if len(sys.argv) > 1 else "detected"


def build_expectation_payload(kind="DETECTION", include_parent=True):
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
            "_time": _now.strftime("%Y-%m-%dT%H:%M:%S"),
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
        "_time": _now.strftime("%Y-%m-%dT%H:%M:%S"),
        "src_ip": "192.168.254.254",
        "dst_ip": "192.168.254.253",
        "parent_process_name": "explorer.exe",
        "signature": "Unrelated noise",
    }


def stale_ip_alert_row():
    """An alert that shares only the IP pair - e.g. a beacon from a PRIOR run of the
    same action, with NO per-execution implant marker (url_path). Used to show that
    IP-only expectations can be satisfied by a stale alert (cross-run bleed)."""
    return {
        "_time": _now.strftime("%Y-%m-%dT%H:%M:%S"),
        "src_ip": SRC_IP,
        "dst_ip": DST_IP,
        "signature": "Prior-run beacon (no implant marker)",
        "event_type": "notable",
    }


# call counter so "late_alert" can return empty first, then a match on retry
SPLUNK_CALLS = {"n": 0}


# ----------------------------------------------------------------------------
# Mock Splunk ES
# ----------------------------------------------------------------------------
class SplunkHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        auth = self.headers.get("Authorization", "")
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode()

        # "token" scenario must present a Bearer header; others use Basic.
        auth_ok = auth.startswith("Bearer ") if SCENARIO == "token" \
            else auth.startswith("Basic ")
        if SCENARIO == "auth_fail" or not auth_ok:
            log_wire("SPLUNK", "req", f"POST {self.path} (auth={auth[:14] or 'none'})")
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"messages":[{"type":"WARN","text":"login failed"}]}')
            log_wire("SPLUNK", "res", "401 Unauthorized")
            return
        if SCENARIO == "token":
            print(f"              (authenticated via {auth[:20]}...)")

        # decode the SPL query that the collector actually built
        from urllib.parse import parse_qs
        spl = parse_qs(raw).get("search", [""])[0]
        log_wire("SPLUNK", "req", f"POST {self.path}  exec_mode=oneshot")
        print(f"              SPL: {spl}")

        SPLUNK_CALLS["n"] += 1
        if SCENARIO == "late_alert":
            # No alert on the first poll (SIEM hasn't indexed it yet), then it appears.
            if SPLUNK_CALLS["n"] < 2:
                results = []
            else:
                results = [splunk_alert_row(match=True)]
        elif SCENARIO == "ip_bleed":
            # A stale alert sharing only the IP pair, from a different execution.
            results = [stale_ip_alert_row()]
        else:
            match = SCENARIO in ("detected", "prevention", "token", "ip_only", "ipv6")
            results = [splunk_alert_row(match=match)] if SCENARIO != "not_detected" else \
                      [splunk_alert_row(match=False)]
        payload = {"results": results,
                   "fields": [{"name": k} for k in results[0].keys()] if results else []}
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)
        log_wire("SPLUNK", "res", f"200 OK ({len(results)} row(s))", results)


# ----------------------------------------------------------------------------
# Mock OpenAEV
# ----------------------------------------------------------------------------
CAPTURED = {"bulk_update": None, "individual": [], "traces": None}


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
                kind, include_parent=(SCENARIO not in ("ip_only", "ipv6", "ip_bleed")))]
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
            self._send(200, {"status": "ok"})
            log_wire("OPENAEV", "res", "200 OK")
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


def main():
    logging.basicConfig(level=logging.WARNING, format="%(message)s")
    splunk = start(ThreadingHTTPServer, SplunkHandler, 18089)
    openaev = start(ThreadingHTTPServer, OpenAEVHandler, 18080)

    import os
    os.environ.update({
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
    print(" Simulated attack (inject):")
    print(f"   inject={INJECT_UUID}  agent={AGENT_UUID}")
    print(f"   src_ip={SRC_IP}  dst_ip={DST_IP}")
    print(f"   expectation_id={EXPECTATION_ID}")
    print("-" * 78)
    print(" WIRE TRACE (real collector code <-> mock servers):")

    cfg = SplunkESConfig().load
    collector_id = cfg.collector.id

    api = OpenAEV(url=str(cfg.openaev.url), token=cfg.openaev.token, ssl_verify=False)
    exp_service = SplunkESExpectationService(cfg)
    trace_service = SplunkESTraceService(cfg)
    handler = GenericExpectationHandler(exp_service)
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
          f"valid={summary.valid} invalid={summary.invalid} skipped={summary.skipped}")
    bu = CAPTURED["bulk_update"]
    if bu and bu.get("inputs"):
        for eid, upd in bu["inputs"].items():
            print(f"   verdict written    : result='{upd.get('result')}' "
                  f"is_success={upd.get('is_success')}")
    elif CAPTURED["individual"]:
        print(f"   verdict written    : (individual={len(CAPTURED['individual'])})")
    else:
        print("   verdict written    : NONE - expectation left PENDING "
              "(not mislabelled 'Not Detected')")
    tr = CAPTURED["traces"]
    if tr:
        n = len(tr.get("expectation_traces", []))
        print(f"   evidence traces    : {n} trace(s) pushed back to OpenAEV")
        if n:
            print(f"       first trace fields: {sorted(tr['expectation_traces'][0].keys())}")
    else:
        print("   evidence traces    : none")
    print("=" * 78)

    splunk.shutdown(); openaev.shutdown()


if __name__ == "__main__":
    main()
