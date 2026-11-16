"""
Sandbox for the validation ants: the whole pipeline on mocks, with checks.

  intel -> scenario builder -> planner -> gatekeeper -> (simulated) agent
        -> Splunk observer + Falcon observer -> analyst -> matcher -> reporter

The Splunk observer is the real splunk-es collector code talking to a mock
Splunk. The Falcon observer talks to a mock Falcon Alerts API. The agent is
simulated: it runs no command and only writes synthetic telemetry. No real
Splunk, no real Falcon tenant, no real host.

  python validation-ants/sandbox.py all          # every scenario, pass/fail table
  python validation-ants/sandbox.py full_run     # one scenario with details
  python validation-ants/sandbox.py catalogue    # scenario list as JSON
  python validation-ants/sandbox.py playground   # one blind run (PLAYGROUND_SEED=n to repeat one)
  python validation-ants/sandbox.py playground_many 100   # 100 blind runs, tally of the calls
  python validation-ants/sandbox.py library      # the attack library as JSON (for the demo page)
  python validation-ants/sandbox.py custom       # run the attack types named in SANDBOX_CUSTOM
  python validation-ants/sandbox.py survey FILE  # how many gaps a public test library file would close

Several sandboxes can run side by side: SANDBOX_PORT_BASE moves the three mock
ports, and HARNESS_EVENTS_STREAM names a file that gets one JSON line per event
as it happens.

Run it with the splunk-es virtualenv's Python (it has pyoaev and requests).
"""

import io
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from ants.agent_sim import (FIREWALL_INDEX, FMT, MAIL_INDEX, RAW_INDEX,  # noqa: E402
                            SimulatedAgent, Telemetry)
from ants.detection_engineer import LIBRARY_PATH as DETECTIONS_PATH  # noqa: E402
from ants.detection_engineer import DetectionEngineer, evaluate, strip_markers  # noqa: E402
from ants.analyst import SearchAnalyst  # noqa: E402
from ants.gatekeeper import Gatekeeper, Refused  # noqa: E402
from ants.intel import TACTIC_ORDER, IntelAnt, IntelError, OpenCTIClient, Technique, Threat  # noqa: E402
from ants.drafter import Drafter  # noqa: E402
from ants.librarian import Librarian, LibrarianError, check_command  # noqa: E402
from ants.scenario_builder import ScenarioBuilder  # noqa: E402
from ants.matcher import Matcher, RuleBook  # noqa: E402
from ants.models import COULD_NOT_CHECK, DETECTED, MISSED, PREVENTED  # noqa: E402
from ants.observers import FalconHttpClient, FalconObserver, SplunkObserver  # noqa: E402
from ants.pipeline import run_validation  # noqa: E402
from ants.planner import CATALOGUE_PATH, Planner  # noqa: E402
from ants.reversible import ReversibleError, check_reversible, load_reversible  # noqa: E402
from ants.reporter import Reporter, team_views  # noqa: E402

SCENARIO = sys.argv[1] if len(sys.argv) > 1 else "full_run"
_PORT_BASE = int(os.environ.get("SANDBOX_PORT_BASE", "18189"))   # one block of three per sandbox
SPLUNK_PORT, FALCON_PORT, OPENCTI_PORT = _PORT_BASE, _PORT_BASE + 1, _PORT_BASE + 2
STARTED = time.time()
EVENTS_STREAM = os.environ.get("HARNESS_EVENTS_STREAM")
WORK = Path(tempfile.mkdtemp(prefix="oaev-ants-"))
TELEMETRY = Telemetry()
MOCK = {"falcon_mode": "ok", "splunk_searches": []}
EVENTS = []

# 'mailbox' is the dedicated test mailbox an email test for that host goes to.
HOST1 = {"name": "WS-TEST-01", "source_ip": "10.0.0.5", "target_ip": "10.0.0.9",
         "mailbox": "oaev-test-01@lab.invalid"}
HOST2 = {"name": "WS-TEST-02", "source_ip": "10.0.0.6", "target_ip": "10.0.0.9",
         "mailbox": "oaev-test-02@lab.invalid"}
OUTSIDER = {"name": "WS-PROD-77", "source_ip": "10.9.9.7", "target_ip": "10.0.0.9"}
ALL_TESTS = ["T-EXEC-001", "T-FILE-002", "T-DNS-003", "T-NET-004"]
DNS_RULE = {"sourcetype": "stream:dns", "rule_name": "DNS lookup of rare domain", "field": "query"}
# What the (simulated) defences do for each test.
DEFENCES = {
    "T-EXEC-001": {"falcon": "detect", "forward": True},
    "T-FILE-002": {"falcon": "prevent", "forward": True,
                   "falcon_rule": "File written to temp by script"},
    "T-DNS-003": {"splunk_rule": DNS_RULE},
    "T-NET-004": {},   # nothing sees it
    "T-MAIL-005": {"proofpoint": "quarantine"},     # the mail gateway quarantines it
    "T-WEB-006": {"checkpoint": "drop"},            # the firewall drops it
    # Defaults per action, for tests built from a scenario.
    "action:ps_echo_marker": {"falcon": "detect", "forward": True, "falcon_rule": "Suspicious PowerShell"},
    "action:echo_marker": {"falcon": "detect", "forward": True},
    "action:system_info": {"splunk_rule": {"sourcetype": "XmlWinEventLog", "field": "process",
                                           "rule_name": "Discovery commands in a short time"}},
    "action:whoami": {"splunk_rule": {"sourcetype": "XmlWinEventLog", "field": "process",
                                      "rule_name": "Discovery commands in a short time"}},
    "action:local_groups": {"splunk_rule": {"sourcetype": "XmlWinEventLog", "field": "process",
                                            "rule_name": "Discovery commands in a short time"}},
    "action:portproxy_show": {"falcon": "detect", "forward": False,
                              "falcon_rule": "Port proxy tool used"},
    "action:drop_marker_file": {"falcon": "prevent", "forward": True,
                                "falcon_rule": "File written to temp by script"},
    "action:dns_lookup_marker": {"splunk_rule": DNS_RULE},
    "action:email_marker": {"proofpoint": "quarantine"},
    # Change-and-undo actions: two are seen, the rest are not.
    "action:task_create_marked": {"falcon": "detect", "forward": True, "falcon_rule": "Scheduled task created"},
    "action:run_key_marked": {"splunk_rule": {"sourcetype": "XmlWinEventLog", "field": "process",
                                              "rule_name": "Logon autostart value added"}},
    "action:web_request_marker": {"checkpoint": "drop"},
    # network_config, process_list, local_accounts, neighbours, tcp_probe: nothing sees them
}


def event(type_, **data):
    item = {"type": type_, "t": round(time.time() - STARTED, 3), **data}
    EVENTS.append(item)
    if EVENTS_STREAM:               # one line per event, as it happens
        with open(EVENTS_STREAM, "a", encoding="utf-8") as out:
            out.write(json.dumps(item, default=str) + "\n")


def emit(ant, title, detail="", status="ok", data=None):
    print(f"   [{ant:<16}] {title}" + (f"\n{'':22}{detail}" if detail else ""))
    event("ant", ant=ant, title=title, detail=detail, status=status, data=data)


# ----------------------------------------------------------------------------
# Mock Splunk: answers the index check and searches from the telemetry store
# ----------------------------------------------------------------------------
def _row_time(row):
    return datetime.strptime(row["_time"], FMT).replace(tzinfo=timezone.utc).timestamp()


class SplunkMock(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._json(200, {"entry": [{"name": "main"}]})

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        spl = parse_qs(raw).get("search", [""])[0]
        base = spl.split(" | ")[0]
        MOCK["splunk_searches"].append(spl)
        # A small stand-in for Splunk's filtering: quoted terms and the time range.
        # sourcetype="X" (narrow search) limits the rows; other quoted strings are terms.
        indexes = set(re.findall(r"\bindex=([\w\-.]+)", base))
        sourcetypes = set(re.findall(r'sourcetype="([^"]+)"', base))
        # Like a real Splunk, a quoted term has to be a word of its own: a marker glued
        # inside a longer word is not found. (Checked against Splunk Enterprise 10.6.)
        terms = [re.compile(r"(?<![a-z0-9])" + re.escape(t.rstrip("*").lower())
                            + ("" if t.endswith("*") else r"(?![a-z0-9])"))
                 for t in re.findall(r'"([^"]+)"', base) if t not in sourcetypes]
        earliest = int(re.search(r"earliest=(\d+)", base).group(1))
        latest = int(re.search(r"latest=(\d+)", base).group(1))
        rows = []
        for row in TELEMETRY.splunk_rows:
            if not (earliest <= _row_time(row) <= latest):
                continue
            if sourcetypes and row.get("sourcetype") not in sourcetypes:
                continue
            if indexes and row.get("index", "main") not in indexes:
                continue
            text = " ".join(str(v) for v in row.values()).lower()
            if not terms or any(t.search(text) for t in terms):
                # A real Splunk gives the time with milliseconds and a UTC offset.
                rows.append(dict(row, _time=row["_time"] + ".000+00:00"))
        # A real Splunk returns only the fields the search asks for with '| table'.
        table = re.search(r"\| table (.+?)(?: \||$)", spl)
        if table:
            wanted = {f.strip().strip('"') for f in table.group(1).split(",")}
            rows = [{k: v for k, v in row.items() if k in wanted} for row in rows]
        self._json(200, {"results": rows})


# ----------------------------------------------------------------------------
# Mock Falcon Alerts API
# ----------------------------------------------------------------------------
class FalconMock(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def _broken(self):
        mode = MOCK["falcon_mode"]
        if mode == "drop":
            self.close_connection = True
            try:
                self.connection.shutdown(2)
            except OSError:
                pass
            return True
        if mode == "auth":
            self._json(401, {"errors": [{"message": "access denied"}]})
            return True
        if mode == "error" and "oauth2" not in self.path:
            self._json(500, {"errors": [{"message": "internal error"}]})
            return True
        return False

    def do_GET(self):
        if self._broken():
            return
        query = unquote(urlparse(self.path).query)
        since = re.search(r"timestamp:>'([^']+)'", query)
        start = datetime.fromisoformat(since.group(1)) if since else None
        ids = [a["composite_id"] for a in TELEMETRY.falcon_alerts
               if not start or datetime.fromisoformat(
                   a["created_timestamp"].replace("Z", "+00:00")) > start]
        self._json(200, {"resources": ids})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode()
        if self._broken():
            return
        if "oauth2/token" in self.path:
            self._json(201, {"access_token": "mock-token", "expires_in": 1799})
            return
        wanted = set(json.loads(raw).get("composite_ids", []))
        self._json(200, {"resources": [a for a in TELEMETRY.falcon_alerts
                                       if a["composite_id"] in wanted]})


# ----------------------------------------------------------------------------
# Mock OpenCTI: serves one report as a STIX bundle over GraphQL
# ----------------------------------------------------------------------------
REPORT_ID = "report--5a1d4f0e-0000-4000-8000-000000000001"


def sample_bundle():
    """A synthetic bundle in the shape OpenCTI exports.

    Illustrative only: the technique list is modelled on public reporting about
    living-off-the-land intrusions and is NOT an authoritative profile of any
    named group. It exists to exercise the ants.
    """
    threat_id = "intrusion-set--5a1d4f0e-0000-4000-8000-0000000000aa"
    rows = [
        ("T1059.001", "PowerShell", "execution"),
        ("T1059.003", "Windows Command Shell", "execution"),
        ("T1070.001", "Clear Windows Event Logs", "defense-evasion"),
        ("T1003.003", "NTDS", "credential-access"),
        ("T1110.003", "Password Spraying", "credential-access"),
        ("T1082", "System Information Discovery", "discovery"),
        ("T1016", "System Network Configuration Discovery", "discovery"),
        ("T1033", "System Owner/User Discovery", "discovery"),
        ("T1057", "Process Discovery", "discovery"),
        ("T1069.001", "Local Groups", "discovery"),
        ("T1087.001", "Local Account", "discovery"),
        ("T1018", "Remote System Discovery", "discovery"),
        ("T1090.001", "Internal Proxy", "command-and-control"),
        ("T1105", "Ingress Tool Transfer", "command-and-control"),
    ]
    objects = [{"type": "intrusion-set", "id": threat_id,
                "name": "Sample living-off-the-land intrusion set",
                "description": "Synthetic sample for the sandbox. Uses built-in system "
                               "tools instead of malware."}]
    for i, (attack_id, name, tactic) in enumerate(rows):
        pattern_id = f"attack-pattern--5a1d4f0e-0000-4000-8000-{i:012d}"
        objects.append({
            "type": "attack-pattern", "id": pattern_id, "name": name,
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": tactic}],
            "external_references": [{"source_name": "mitre-attack", "external_id": attack_id}]})
        objects.append({"type": "relationship", "id": f"relationship--5a1d4f0e-0000-4000-8000-{i:012d}",
                        "relationship_type": "uses", "source_ref": threat_id,
                        "target_ref": pattern_id})
    note_id = "attack-pattern--5a1d4f0e-0000-4000-8000-0000000000ff"
    objects.append({"type": "attack-pattern", "id": note_id,
                    "name": "Operator tradecraft note without an ATT&CK id"})
    objects.append({"type": "relationship", "id": "relationship--5a1d4f0e-0000-4000-8000-0000000000ff",
                    "relationship_type": "uses", "source_ref": threat_id, "target_ref": note_id})
    return {"type": "bundle", "id": "bundle--5a1d4f0e-0000-4000-8000-0000000000bb",
            "objects": objects}


class OpenCTIMock(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode())
        mode = MOCK.get("opencti_mode", "ok")
        if mode == "auth" or not self.headers.get("Authorization", "").startswith("Bearer "):
            code, out = 401, {"errors": [{"message": "You must be logged in"}]}
        elif mode == "missing" or (body.get("variables") or {}).get("id") != REPORT_ID:
            code, out = 200, {"data": {"report": None}}
        elif mode == "not_a_bundle":
            code, out = 200, {"data": {"report": {"toStixReportBundle": json.dumps({"type": "report"})}}}
        elif mode == "no_techniques":
            empty = dict(sample_bundle(), objects=sample_bundle()["objects"][:1])
            code, out = 200, {"data": {"report": {"toStixReportBundle": json.dumps(empty)}}}
        else:
            code, out = 200, {"data": {"report": {"toStixReportBundle": json.dumps(sample_bundle())}}}
        data = json.dumps(out).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)


def start(handler, port):
    srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ----------------------------------------------------------------------------
# The ants, wired together
# ----------------------------------------------------------------------------
class Ants:
    def __init__(self, scope=None, work=None, splunk_env=None, extra_actions=None, reversible=False):
        work = work or WORK
        splunk_env = splunk_env or {}     # lab_splunk.py points the readers at a lab Splunk
        now = datetime.now(timezone.utc)
        # reversible=True switches the change-and-undo actions on for this run.
        self.planner = Planner(reversible=reversible)
        if extra_actions:                 # actions a person approved through the librarian
            self.planner.add_actions(extra_actions)
        self.scope = scope or {
            "allowed_hosts": [HOST1["name"], HOST2["name"]],
            "allowed_targets": [HOST1["target_ip"]],
            "allowed_mailboxes": [HOST1["mailbox"], HOST2["mailbox"]],
            # Only the first host is a dedicated test machine for change-and-undo steps.
            "reversible_hosts": [HOST1["name"]] if reversible else [],
            "allowed_actions": list(self.planner.actions),
            "not_before": (now - timedelta(hours=1)).isoformat(),
            "not_after": (now + timedelta(hours=2)).isoformat(),
            "max_steps": 20,
        }
        self.gatekeeper = Gatekeeper(self.scope, self.planner.actions, os.urandom(32),
                                     work / "audit.jsonl", work / "KILL_SWITCH")
        self.defences = {k: dict(v) for k, v in DEFENCES.items()}
        self.agent = SimulatedAgent(self.gatekeeper, TELEMETRY, self.defences)
        self.splunk = SplunkObserver({
            "OPENAEV_URL": "http://127.0.0.1:9", "OPENAEV_TOKEN": "unused-in-sandbox",
            "COLLECTOR_ID": "splunkes--0b13e3f7-5c9e-46f5-acc4-33032e9b4921",
            "COLLECTOR_NAME": "SplunkES", "COLLECTOR_PERIOD": "PT1M",
            "SPLUNKES_BASE_URL": f"http://127.0.0.1:{SPLUNK_PORT}",
            "SPLUNKES_USERNAME": "svc_mock", "SPLUNKES_PASSWORD": "mock-only",
            # Alerts, mail gateway logs and firewall logs each have their own index.
            "SPLUNKES_ALERTS_INDEX": f"main,{MAIL_INDEX},{FIREWALL_INDEX}", "SPLUNKES_MAX_RETRY": "0",
            "SPLUNKES_OFFSET": "PT1S", "SPLUNKES_VERIFY_SSL": "false",
            "SPLUNKES_MEMORY_PATH": str(work / "location_memory.json"),
            **splunk_env,
        })
        seed_baseline()
        # A second, read-only view of Splunk: the plain endpoint logs, through the
        # same checked search path, for the detection engineer.
        self.raw = SplunkObserver({
            **splunk_env, "SPLUNKES_ALERTS_INDEX": RAW_INDEX,
            "SPLUNKES_MEMORY_PATH": str(work / "raw_reader_memory.json")})
        from src.services.spl_validator import validate_spl
        self.engineer = DetectionEngineer(self.raw.candidates, validate_spl, RAW_INDEX,
                                          work / "detection_proposals.json")
        self._alerted = set()
        run_step = self.agent.run

        def run_then_rules(step):
            entry = run_step(step)
            self.fire_deployed_rules()
            return entry

        self.agent.run = run_then_rules
        self.falcon = FalconObserver(FalconHttpClient(
            f"http://127.0.0.1:{FALCON_PORT}", "mock-client-id", "mock-only"))
        self.rulebook = RuleBook(work / "rulebook.json")
        self.matcher = Matcher(self.rulebook)
        self.reporter = Reporter(work / "history.json")
        self.analyst = SearchAnalyst(work / "search_changes.jsonl")
        self.builder = ScenarioBuilder(self.planner.actions, self.planner.not_simulated,
                                       work / "scenarios")
        self.opencti = OpenCTIClient(f"http://127.0.0.1:{OPENCTI_PORT}", "mock-only-token")
        self.runs = 0

    def fire_deployed_rules(self):
        """Stand-in for Splunk running the rules people have deployed: a deployed
        detection that matches an endpoint log raises an alert in the alerts index."""
        deployed = self.engineer.deployed()
        if not deployed:
            return
        raw = [r for r in TELEMETRY.splunk_rows if r.get("index") == RAW_INDEX]
        events = [{"time": datetime.strptime(r["_time"], FMT).replace(tzinfo=timezone.utc),
                   "host": r["dest_host"].split(".")[0], "text": strip_markers(r.get("process", ""))}
                  for r in raw]
        for det in deployed:
            for i in evaluate(det, events):
                key = (det["id"], id(raw[i]))
                if key in self._alerted:
                    continue
                self._alerted.add(key)
                when = datetime.strptime(raw[i]["_time"], FMT) + timedelta(seconds=20)
                TELEMETRY.splunk_rows.append({
                    "_time": when.strftime(FMT), "index": "main", "sourcetype": "detection:alerts",
                    "dest_host": raw[i]["dest_host"], "rule_name": det["title"],
                    "process": raw[i]["process"]})

    def run(self, tests, hosts, before_step=None, label=None, scenario=None, plan=None,
            finish=None):
        if self.runs:
            age_telemetry()          # the next run happens "an hour later"
        self.runs += 1
        before = dict(self.splunk.searches)
        print(f" RUN {self.runs}" + (f": {label}" if label else ""))
        event("run_start", n=self.runs, label=label or f"Run {self.runs}")
        if callable(tests):
            tests = tests()          # the intel ant and the builder work inside the run
        report = run_validation(
            planner=self.planner, gatekeeper=self.gatekeeper, agent=self.agent,
            observers=[self.splunk, self.falcon], matcher=self.matcher,
            reporter=self.reporter, test_ids=tests, hosts=hosts,
            approver="purple.lead", analyst=self.analyst, engineer=self.engineer,
            emit=emit, before_step=before_step, plan=plan)
        report["splunk_searches"] = {k: self.splunk.searches[k] - before[k]
                                     for k in before}
        report["teams"] = team_views(report, {
            tid: self.planner.actions[t["action"]].get("category", "endpoint")
            for tid, t in self.planner.tests.items()})
        if finish:
            finish(report)
        if scenario and scenario.get("scenario"):
            built = scenario["scenario"]
            report["scenario"] = {k: built.get(k) for k in
                                  ("id", "name", "approved_by", "coverage", "skipped_patterns")}
        event("run_end", n=self.runs, report=report,
              audit=self.gatekeeper.read_audit()[-12:])
        for step in report["steps"]:
            print(f"   => {step['test_id']} on {step['host']}: {step['outcome']}"
                  + (f" ({step['reason']})" if step["reason"] else "")
                  + "".join(f"\n        ! {f}" for f in step["findings"]))
        for item in report["not_run"]:
            print(f"   => {item['test_id']} on {item['host']}: Not run ({item['reason']})")
        return report


def age_telemetry(hours=1):
    """Move everything recorded so far one hour into the past."""
    shift = timedelta(hours=hours)
    for row in TELEMETRY.splunk_rows:
        row["_time"] = (datetime.strptime(row["_time"], FMT) - shift).strftime(FMT)
    for alert in TELEMETRY.falcon_alerts:
        for key in ("created_timestamp", "updated_timestamp"):
            moved = datetime.strptime(alert[key].rstrip("Z"), FMT) - shift
            alert[key] = moved.strftime(FMT) + "Z"


def step_rows():
    """Splunk rows written because a step ran (the baseline activity is not one)."""
    return [r for r in TELEMETRY.splunk_rows if r.get("source") != "baseline"]


def outcome_of(report, test_id, host=HOST1["name"]):
    return next((s for s in report["steps"]
                 if s["test_id"] == test_id and s["host"] == host), None)


def want(fails, report, test_id, outcome, host=HOST1["name"], finding=None, sightings=None):
    step = outcome_of(report, test_id, host)
    if step is None:
        fails.append(f"{test_id} on {host}: no verdict")
        return
    if step["outcome"] != outcome:
        fails.append(f"{test_id} on {host}: {step['outcome']!r}, expected {outcome!r}")
    if finding and not any(finding in f for f in step["findings"]):
        fails.append(f"{test_id}: no finding containing {finding!r} in {step['findings']}")
    if sightings is not None and step["sightings"] != sightings:
        fails.append(f"{test_id}: counted {step['sightings']} detection(s), expected {sightings}")


def want_not_run(fails, report, reason, count):
    got = [i for i in report["not_run"] if i["reason"] == reason]
    if len(got) != count:
        fails.append(f"{len(got)} step(s) refused for {reason!r}, expected {count}: "
                     f"{[(i['test_id'], i['reason']) for i in report['not_run']]}")


# ----------------------------------------------------------------------------
# Scenarios
# ----------------------------------------------------------------------------
def s_full_run():
    """All ants, four tests on one host: detected, prevented, detected, missed."""
    ants, fails = Ants(), []
    r = ants.run(ALL_TESTS, [HOST1])
    want(fails, r, "T-EXEC-001", DETECTED, sightings=1)     # Falcon + forwarded copy = 1
    want(fails, r, "T-FILE-002", PREVENTED, sightings=1)
    want(fails, r, "T-DNS-003", DETECTED, sightings=1)
    want(fails, r, "T-NET-004", MISSED)
    if r["detection_rate"] != 0.75:
        fails.append(f"detection rate {r['detection_rate']}, expected 0.75")
    if r["splunk_searches"]["wide"] != 1 or r["splunk_searches"]["narrow"] != 0:
        fails.append(f"Splunk searches {r['splunk_searches']}, expected one wide search")
    if not r["audit_intact"]:
        fails.append("audit log chain is broken")
    return fails, (f"4 steps: 2 Detected, 1 Prevented, 1 Missed; rate 75%; "
                   f"{r['splunk_searches']['wide']} Splunk search for all four")


def s_repeat_run():
    """The repeat run uses the location memory, keyed by the real test id."""
    ants, fails = Ants(), []
    ants.run(ALL_TESTS, [HOST1], label="first run")
    r = ants.run(ALL_TESTS, [HOST1], label="repeat run")
    want(fails, r, "T-EXEC-001", DETECTED)
    want(fails, r, "T-FILE-002", PREVENTED)
    want(fails, r, "T-DNS-003", DETECTED)
    want(fails, r, "T-NET-004", MISSED)
    if r["splunk_searches"] != {"narrow": 1, "wide": 1, "candidates": 0}:
        fails.append(f"repeat-run Splunk searches {r['splunk_searches']}, expected 1 narrow "
                     f"(three remembered tests) + 1 wide (the one never found)")
    if r["drift"]:
        fails.append(f"unexpected drift: {r['drift']}")
    changes = sorted(c["change"] for c in r["search_changes"])
    if changes != ["confirmed", "confirmed", "confirmed", "none"]:
        fails.append(f"repeat-run search changes {changes}")
    return fails, "repeat run: 1 narrow search for the 3 remembered tests, 1 wide for the other"


def build_from_opencti(ants):
    """Intel ant reads the scenario from OpenCTI; the builder turns it into a draft."""
    threat = IntelAnt.from_bundle(ants.opencti.report_bundle(REPORT_ID))
    emit("Intel", f"Read '{threat.name}' from OpenCTI: {len(threat.techniques)} techniques"
                  + (f", {len(threat.skipped)} entry without an ATT&CK id left out"
                     if threat.skipped else ""), data=threat.to_dict())
    draft = ants.builder.draft(threat)
    gaps = [c for c in draft["coverage"] if c["status"] in ("not simulated", "no action")]
    emit("Scenario builder", f"Draft '{draft['id']}': {len(draft['tests'])} tests built from the "
                             f"action library; {len(gaps)} technique(s) cannot be tested",
         status="stop" if gaps else "ok", data=draft)
    return threat, draft


def s_threat_scenario():
    """Fetch a scenario from OpenCTI, build the tests, approve, run it in the sandbox."""
    ants, fails, box = Ants(), [], {}

    def build():
        threat, draft = build_from_opencti(ants)
        box.update(threat=threat, draft=draft)
        try:
            ants.planner.use_scenario(draft)
            fails.append("an unapproved draft was accepted by the planner")
        except ValueError:
            pass
        scenario = ants.builder.approve(draft["id"], "purple.lead")
        emit("Scenario builder", f"Approved by {scenario['approved_by']}; the approval is bound to "
                                 f"these {len(scenario['tests'])} tests")
        box["scenario"] = scenario
        return ants.planner.use_scenario(scenario)

    r = ants.run(build, [HOST1], label="scenario from OpenCTI, built and run", scenario=box)
    threat, draft = box["threat"], box["draft"]
    if len(threat.techniques) != 14 or len(threat.skipped) != 1:
        fails.append(f"intel read {len(threat.techniques)} techniques, {len(threat.skipped)} skipped")
    status = {}
    for c in draft["coverage"]:
        status[c["status"]] = status.get(c["status"], 0) + 1
    if status != {"simulated": 9, "partial": 2, "not simulated": 2, "no action": 1}:
        fails.append(f"coverage {status}")
    order = [t["technique"] for t in draft["tests"]]
    if order[0] != "T1059.001" or order[-1] != "T1105" or len(order) != 11:
        fails.append(f"test order {order}")
    totals = r["totals"]
    if (totals[DETECTED], totals[PREVENTED], totals[MISSED]) != (6, 1, 4) or r["detection_rate"] != 0.636:
        fails.append(f"outcomes {totals}, rate {r['detection_rate']}")
    want(fails, r, draft["id"] + "-T1090.001", DETECTED, finding="log pipeline gap")
    want(fails, r, draft["id"] + "-T1105", PREVENTED)
    want(fails, r, draft["id"] + "-T1016", MISSED)
    if r["splunk_searches"]["wide"] != 1:
        fails.append(f"Splunk searches {r['splunk_searches']}, expected one for all 11 steps")
    teams = {t["team"]: t for t in r["teams"]}
    if teams["NetOps"]["steps"] != 1 or teams["SecOps"]["steps"] != 10 or teams["Purple team"]["steps"] != 11:
        fails.append(f"team views {r['teams']}")
    r2 = ants.run(ants.planner.use_scenario(box["scenario"]), [HOST1], label="repeat run of the same scenario")
    if r2["splunk_searches"]["narrow"] != 1 or r2["regressions"]:
        fails.append(f"repeat run: searches {r2['splunk_searches']}, regressions {r2['regressions']}")
    return fails, ("14 techniques from OpenCTI -> 11 tests built (9 full, 2 partial), 3 not testable; "
                   "run: 6 Detected, 1 Prevented, 4 Missed, rate 64%; repeat run uses the memory")


def s_scenario_guards():
    """A scenario cannot be built from a broken source, run unapproved, or changed after approval."""
    ants, fails = Ants(), []

    def refused(label, fn, kinds=(ValueError, IntelError)):
        try:
            fn()
            fails.append(f"NOT refused: {label}")
        except kinds:
            pass

    for mode, label in (("auth", "OpenCTI rejects the sign-in"), ("missing", "report does not exist"),
                        ("not_a_bundle", "answer is not a STIX bundle"),
                        ("no_techniques", "bundle has no technique")):
        MOCK["opencti_mode"] = mode
        refused(label, lambda: IntelAnt.from_bundle(ants.opencti.report_bundle(REPORT_ID)))
    MOCK["opencti_mode"] = "ok"
    refused("OpenCTI unreachable", lambda: OpenCTIClient("http://127.0.0.1:9", "x").report_bundle(REPORT_ID))
    if list((WORK / "scenarios").glob("*.json")) or step_rows():
        fails.append("something was built or run from a broken source")

    threat = IntelAnt.from_bundle(ants.opencti.report_bundle(REPORT_ID))
    draft = ants.builder.draft(threat)
    refused("planning an unapproved draft", lambda: ants.planner.use_scenario(draft))
    refused("approval without a person", lambda: ants.builder.approve(draft["id"], "  "))
    approved = ants.builder.approve(draft["id"], "purple.lead")
    changed = json.loads(json.dumps(approved))
    changed["tests"][0]["action"] = "tcp_probe"
    refused("scenario changed after approval", lambda: ants.planner.use_scenario(changed))
    sneaky = json.loads(json.dumps(draft))
    sneaky["tests"].append({"id": "x", "title": "x", "technique": "T1003.003",
                            "action": "dump_credentials", "expect": {"splunk": "detection"}})
    ants.builder.save(sneaky)
    refused("approving a test whose action is not on the allow-list",
            lambda: ants.builder.approve(draft["id"], "purple.lead"))
    if any(not c["action"] for c in draft["coverage"] if c["status"] in ("simulated", "partial")) \
            or any(c["action"] for c in draft["coverage"] if c["status"] in ("not simulated", "no action")):
        fails.append("coverage table is inconsistent")
    if any(t["technique"].startswith(("T1003", "T1070", "T1110")) for t in draft["tests"]):
        fails.append("a technique without a safe action got a test")
    emit("Scenario builder", "Refused: broken or unreachable OpenCTI, unapproved draft, approval "
                             "without a person, scenario changed after approval, action off the allow-list",
         status="stop")
    return fails, ("9 refusals: broken sources, unapproved draft, nameless approval, change after "
                   "approval, action off the allow-list")


# ----------------------------------------------------------------------------
# Playground: a blind run. Random steps, random defence behaviour and decoy
# alerts that the ants are not told about; a referee then compares what the
# ants said with what really happened.
# ----------------------------------------------------------------------------
DECOYS = {
    "unmarked": "an unrelated alert on the same host at the same time",
    "other_marker": "an alert carrying another step's marker",
    "wrong_host": "this step's marker, but on a different host",
    "stale": "this step's marker, but 40 minutes before the step",
    "falcon_unmarked": "an unrelated Falcon alert on the same host",
    "ip_pair": "an unrelated connection between the same two addresses",
}


def playground_setup(ants, rng, n_steps):
    """Pick random steps and decide, hidden from the ants, what the defences do."""
    import uuid as _uuid
    truths, pairs = {}, []
    # The mail gateway and firewall tests are not in the blind pool yet: the hidden
    # behaviours below are written for endpoint tools.
    actions = [a for a, spec in ants.planner.actions.items() if not spec.get("tool")]
    for i in range(n_steps):
        action_id = rng.choice(actions)
        action = ants.planner.actions[action_id]
        host = rng.choice([HOST1, HOST2])
        test_id = f"PG-{i + 1:02d}-{action_id}"
        expect = dict(action["expect"])
        ants.planner.tests[test_id] = {
            "id": test_id, "title": f"{action['techniques'][0]} ({action_id})",
            "technique": action["techniques"][0], "action": action_id, "expect": expect}
        agentless = bool(action.get("agentless"))
        profile = {}
        if "falcon" in expect:
            roll = rng.random()
            falcon = (("prevent" if roll < 0.5 else "detect" if roll < 0.75 else None)
                      if expect["falcon"] == "prevention" else ("detect" if roll < 0.6 else None))
            if falcon:
                profile.update(falcon=falcon, forward=rng.random() < 0.7)
        if agentless:
            if rng.random() < 0.4:
                profile["splunk_rule"] = {"sourcetype": "pan:traffic",
                                          "rule_name": "SMB to server", "ips": True}
        elif rng.random() < (0.25 if profile.get("falcon") else 0.55):
            dns = action_id == "dns_lookup_marker"
            profile["splunk_rule"] = {
                "sourcetype": "stream:dns" if dns else "XmlWinEventLog",
                "rule_name": "DNS lookup of rare domain" if dns else "Suspicious command line",
                "field": "query" if dns else "process"}
        if profile and not agentless and rng.random() < 0.15:
            profile["marker_in_alert"] = False        # the tool cut the command line short
        pool = [d for d in DECOYS if (d == "ip_pair") == agentless or d in ("unmarked",)]
        if not agentless:
            pool = [d for d in pool if d != "ip_pair"]
        else:
            pool = ["ip_pair", "unmarked"]
        decoys = rng.sample(pool, rng.choice([0, 0, 1, 1, 2]))
        ants.defences[test_id] = profile
        truths[test_id] = {"profile": profile, "decoys": decoys, "agentless": agentless,
                           "expect": expect, "host": host["name"], "other": str(_uuid.UUID(int=rng.getrandbits(128), version=4))}
        pairs.append((test_id, host))
    return truths, pairs


def add_decoys(step, truth):
    """Alerts that have nothing to do with the step, or only look like they do."""
    when = (step.start + timedelta(seconds=45)).strftime(FMT)
    host = f"{step.host.lower()}.lab.local"
    base = {"_time": when, "index": "main", "sourcetype": "XmlWinEventLog", "dest_host": host,
            "rule_name": "Routine admin activity"}
    for decoy in truth["decoys"]:
        if decoy == "unmarked":
            TELEMETRY.splunk_rows.append(dict(base, process="powershell.exe -nop Get-Process"))
        elif decoy == "other_marker":
            TELEMETRY.splunk_rows.append(dict(base, process=f"cmd.exe /c echo oaev-step-{truth['other']}"))
        elif decoy == "wrong_host":
            TELEMETRY.splunk_rows.append(dict(base, dest_host="ws-other-99.lab.local",
                                              process=step.command))
        elif decoy == "stale":
            old = (step.start - timedelta(minutes=40)).strftime(FMT)
            TELEMETRY.splunk_rows.append(dict(base, _time=old, process=step.command))
        elif decoy == "falcon_unmarked":
            TELEMETRY.falcon_alerts.append({
                "id": f"ind:decoy:{len(TELEMETRY.falcon_alerts)}",
                "composite_id": f"cid0a1b2c:ind:decoy:{len(TELEMETRY.falcon_alerts)}",
                "display_name": "Routine admin activity", "filename": "powershell.exe",
                "cmdline": "powershell.exe -nop Get-Process",
                "parent_details": {"filename": "explorer.exe", "cmdline": "explorer.exe"},
                "grandparent_details": {"filename": "userinit.exe"},
                "device": {"hostname": step.host}, "pattern_disposition": 0,
                "created_timestamp": when + "Z", "updated_timestamp": when + "Z"})
        elif decoy == "ip_pair":
            TELEMETRY.splunk_rows.append({"_time": when, "index": "main", "sourcetype": "pan:traffic",
                                          "rule_name": "Backup job traffic",
                                          "src_ip": step.source_ip, "dst_ip": step.target_ip})


def referee(report, truths, falcon_down):
    """Compare each verdict with what really happened. Returns one row per step."""
    rows = []
    for step in report["steps"]:
        truth = truths[step["test_id"]]
        p = truth["profile"]
        marked = p.get("marker_in_alert", True)
        falcon_fired = p.get("falcon") in ("detect", "prevent")
        falcon_asked = "falcon" in truth["expect"]
        splunk_real = bool(p.get("splunk_rule")) or (falcon_fired and p.get("forward", True))
        falcon_visible = falcon_fired and marked and falcon_asked and not falcon_down
        splunk_visible = splunk_real and (marked or truth["agentless"])
        real_alert = falcon_fired or splunk_real
        if falcon_visible and p["falcon"] == "prevent":
            should = PREVENTED
        elif falcon_visible or splunk_visible:
            should = DETECTED
        elif falcon_down and falcon_asked:
            should = COULD_NOT_CHECK
        else:
            should = MISSED
        happened = []
        if p.get("falcon") == "prevent":
            happened.append("Falcon blocked it")
        elif p.get("falcon") == "detect":
            happened.append("Falcon raised an alert")
        if falcon_fired:
            happened.append("copy forwarded to Splunk" if p.get("forward", True)
                            else "copy never reached Splunk")
        if p.get("splunk_rule"):
            happened.append("a Splunk rule fired")
        if real_alert and not marked:
            happened.append("but the alert does not carry the marker")
        if not real_alert:
            happened.append("no defence reacted")
        if falcon_down:
            happened.append("Falcon was down when the ants asked")
        said = step["outcome"]
        flagged = any(f.startswith(("weak match", "needs confirmation")) for f in step["findings"])
        if said == should:
            if said in (DETECTED, PREVENTED):
                call, ok = "caught", True
            elif said == COULD_NOT_CHECK:
                call, ok = "correctly could not check", True
            elif real_alert:
                call, ok = "not tied: the real alert has no marker", True   # known limit
            else:
                call, ok = "correct: nothing to catch", True
        elif said in (DETECTED, PREVENTED) and should in (MISSED, COULD_NOT_CHECK):
            call = "false catch, flagged as weak" if flagged else "FALSE CATCH"
            ok = flagged and truth["agentless"]                             # known limit
        elif said == MISSED and should in (DETECTED, PREVENTED):
            call, ok = "MISSED A REAL ALERT", False
        elif said in (DETECTED, PREVENTED) and should in (DETECTED, PREVENTED):
            call, ok = "WRONG KIND", False
        else:
            call, ok = "WRONG", False
        rows.append({"test_id": step["test_id"], "host": step["host"],
                     "happened": "; ".join(happened),
                     "decoys": [DECOYS[d] for d in truth["decoys"]],
                     "should": should, "said": said, "call": call, "ok": ok})
    return rows


def run_playground(seed, n_steps=8, work=None):
    """One blind run. Returns (fails, note, rows)."""
    import random
    rng = random.Random(seed)
    ants = Ants(work=work)
    truths, pairs = playground_setup(ants, rng, n_steps)
    falcon_down = rng.random() < 0.15
    MOCK["falcon_mode"] = "error" if falcon_down else "ok"
    plain_run = ants.agent.run

    def run_with_decoys(step):
        entry = plain_run(step)
        add_decoys(step, truths[step.test_id])
        return entry

    ants.agent.run = run_with_decoys
    box = {}

    def finish(report):
        rows = referee(report, truths, falcon_down)
        box["rows"] = rows
        report["referee"] = {"seed": seed, "rows": rows}
        wrong = [r for r in rows if not r["ok"]]
        emit("Referee", f"{sum(1 for r in rows if r['call'] == 'caught')} caught, "
                        f"{sum(1 for r in rows if r['call'].startswith('correct'))} correct "
                        f"non-catches, {len(wrong)} wrong", status="ok" if not wrong else "none",
             data=rows)

    ants.run([], [], label=f"blind run, seed {seed}", plan=ants.planner.plan_pairs(pairs),
             finish=finish)
    MOCK["falcon_mode"] = "ok"
    rows = box["rows"]
    fails = [f"{r['test_id']}: {r['call']} (should be {r['should']}, ants said {r['said']}; "
             f"{r['happened']}; decoys: {r['decoys']})" for r in rows if not r["ok"]]
    real = sum(1 for r in rows if r["should"] in (DETECTED, PREVENTED))
    caught = sum(1 for r in rows if r["call"] == "caught")
    limits = sum(1 for r in rows if r["call"].startswith(("not tied", "false catch, flagged")))
    note = (f"seed {seed}: {caught} of {real} catchable alerts caught, "
            f"{sum(len(r['decoys']) for r in rows)} decoys, "
            f"{sum(1 for r in rows if r['call'] == 'FALSE CATCH')} unflagged false catches, "
            f"{limits} known-limit case(s)")
    return fails, note, rows


def s_playground():
    """Random steps, hidden defence behaviour and decoy alerts; a referee scores the ants."""
    import random
    seed = int(os.environ.get("PLAYGROUND_SEED") or random.SystemRandom().randrange(1, 10 ** 6))
    fails, note, _ = run_playground(seed)
    return fails, note


def playground_many(count, first_seed=1):
    """Many blind runs in one process; prints a tally and every wrong call."""
    tally, wrong = {}, []
    for seed in range(first_seed, first_seed + count):
        TELEMETRY.splunk_rows.clear()
        TELEMETRY.falcon_alerts.clear()
        fails, _, rows = run_playground(seed, work=WORK / f"seed-{seed}")
        for row in rows:
            tally[row["call"]] = tally.get(row["call"], 0) + 1
        wrong += [f"seed {seed}: {f}" for f in fails]
    return tally, wrong


def seed_baseline():
    """A day of ordinary admin activity in the endpoint logs (no test markers)."""
    if any(r.get("source") == "baseline" for r in TELEMETRY.splunk_rows):
        return
    commands = ["ipconfig /all", "whoami", "tasklist /svc", "systeminfo",
                "net user administrator", "netsh advfirewall show allprofiles", "arp -a",
                "net localgroup administrators", "ping fileserver01", "gpupdate /force"]
    hosts = ["ws-test-01", "ws-test-02", "ws-admin-07"]
    start = datetime.now(timezone.utc) - timedelta(hours=24)
    for k in range(72):                                   # one command every 20 minutes
        TELEMETRY.splunk_rows.append({
            "_time": (start + timedelta(minutes=20 * k)).strftime(FMT), "index": RAW_INDEX,
            "sourcetype": "XmlWinEventLog:Sysmon", "EventCode": "1", "source": "baseline",
            "dest_host": f"{hosts[k % 3]}.lab.local", "process": commands[k % len(commands)],
            "parent_process_name": "explorer.exe"})


def detection_loop_tests(ants):
    """The OpenCTI scenario's tests plus one test that should be blocked but is only detected."""
    threat, draft = build_from_opencti(ants)
    scenario = ants.builder.approve(draft["id"], "purple.lead")
    ants.defences["T-FILE-002"] = dict(DEFENCES["T-FILE-002"], falcon="detect")
    return ants.planner.use_scenario(scenario) + ["T-FILE-002"]


def s_detection_loop():
    """Missed -> tested proposal -> a person approves and deploys -> the re-run says Detected."""
    ants, fails, box = Ants(), [], {}

    def first():
        box["ids"] = detection_loop_tests(ants)
        return box["ids"]

    r1 = ants.run(first, [HOST1], label="first run: four techniques are missed")
    d = r1["detection_proposals"]
    by_id = {p["id"]: p for p in d["proposals"]}
    burst = by_id.get("DET-DISCOVERY-BURST", {})
    if (burst.get("status"), burst.get("caught"), burst.get("of"), burst.get("noise")) != \
            ("ready for review", 4, 4, 0):
        fails.append(f"burst proposal: {burst.get('status')}, caught {burst.get('caught')}/"
                     f"{burst.get('of')}, noise {burst.get('noise')}")
    noisy = [p for p in d["proposals"] if p["kind"] == "single"]
    if len(noisy) != 4 or any(p["status"] != "too noisy" or p["noise"] < 1 for p in noisy):
        fails.append(f"single-command rules: {[(p['id'], p['status'], p['noise']) for p in noisy]}")
    if any("oaev" in p["spl"].lower() for p in d["proposals"]):
        fails.append("a proposed search keys on the test marker")
    if d["no_proposal"] or d["error"]:
        fails.append(f"unexpected gaps: {d['no_proposal']} {d['error']}")
    if [a["test_id"] for a in d["advice"]] != ["T-FILE-002"]:
        fails.append(f"prevention advice: {d['advice']}")
    if (r1["totals"][DETECTED], r1["totals"][PREVENTED], r1["totals"][MISSED]) != (7, 1, 4):
        fails.append(f"first run totals {r1['totals']}")

    for label, fn in (("deploying before approval", lambda: ants.engineer.record_deployed("DET-DISCOVERY-BURST", "x")),
                      ("approving without a person", lambda: ants.engineer.approve("DET-DISCOVERY-BURST", " ")),
                      ("approving a noisy rule", lambda: ants.engineer.approve(noisy[0]["id"], "secops.lead"))):
        try:
            fn()
            fails.append(f"NOT refused: {label}")
        except ValueError:
            pass
    if ants.engineer.deployed():
        fails.append("something counts as deployed before a person said so")

    ants.engineer.approve("DET-DISCOVERY-BURST", "secops.lead")
    ants.engineer.record_deployed("DET-DISCOVERY-BURST", "secops.engineer")
    ants.defences["T-FILE-002"]["falcon"] = "prevent"       # a person changed the Falcon policy
    event("people", text="secops.lead approved the discovery rule, secops.engineer deployed it "
                         "in Splunk, and the Falcon policy for the file test was set to block.")
    r2 = ants.run(box["ids"], [HOST1], label="re-run after people deployed the rule and the policy")
    if (r2["totals"][DETECTED], r2["totals"][PREVENTED], r2["totals"][MISSED]) != (10, 2, 0) \
            or r2["detection_rate"] != 1.0:
        fails.append(f"re-run totals {r2['totals']}, rate {r2['detection_rate']}")
    kinds = sorted(x["kind"] for x in r2["drift"])
    if kinds != ["improvement"] * 5 or r2["regressions"]:
        fails.append(f"drift after the fix: {kinds}")
    after = r2["detection_proposals"]
    if after.get("proposals") or after.get("advice"):
        fails.append(f"proposals after the fix: {after}")
    return fails, ("4 missed -> 1 rule ready (catches 4 of 4, no noise in 24 h), 4 single-command "
                   "rules set aside as too noisy; after people deployed: 10 Detected, 2 Prevented, "
                   "0 Missed")


def s_detection_guards():
    """What the detection engineer refuses, and what it will not propose."""
    ants, fails = Ants(), []
    from src.services.spl_validator import validate_spl
    library = json.loads((HERE / "ants" / "detections.json").read_text(encoding="utf-8"))

    def engineer(detections, raw=None):
        path = WORK / f"library-{len(list(WORK.glob('library-*')))}.json"
        path.write_text(json.dumps(dict(library, detections=detections)), encoding="utf-8")
        return DetectionEngineer(raw or ants.raw.candidates, validate_spl, RAW_INDEX,
                                 WORK / f"{path.stem}-proposals.json", library_path=path)

    cheat = dict(library["detections"][1], id="DET-CHEAT", all=["oaev-step"])
    unsafe = dict(library["detections"][1], id="DET-UNSAFE", all=['x" | delete'])
    for label, det in (("a rule that keys on the test marker", cheat),
                       ("a rule with something other than plain words", unsafe)):
        try:
            engineer([det])
            fails.append(f"NOT refused: {label}")
        except ValueError:
            pass

    # Steps with nothing a real rule could key on, and a technique with no library entry.
    ants.defences.update({"T-EXEC-001": {}, "T-DNS-003": {}, "T-NET-004": {}})
    r = ants.run(["T-EXEC-001", "T-DNS-003", "T-NET-004"], [HOST1], label="three misses with nothing to propose")
    d = r["detection_proposals"]
    if d["proposals"] or len(d["no_proposal"]) != 3:
        fails.append(f"expected three 'no proposal' entries: {d}")

    # A rule that does not catch the step is reported as such.
    plan = ants.planner.plan(["T-EXEC-001"], [HOST1])
    wrong = dict(library["detections"][2], id="DET-WRONG", all=["ipconfig", "/displaydns"])
    ants.planner.tests["PG-IPCONFIG"] = {"id": "PG-IPCONFIG", "title": "T1016", "technique": "T1016",
                                         "action": "network_config", "expect": {"splunk": "detection"}}
    ants.defences["PG-IPCONFIG"] = {}
    ants.engineer = engineer([wrong])
    r2 = ants.run(["PG-IPCONFIG"], [HOST1], label="a rule that does not catch the step")
    got = [(p["id"], p["status"]) for p in r2["detection_proposals"]["proposals"]]
    if got != [("DET-WRONG", "does not catch")]:
        fails.append(f"non-catching rule: {got}")

    # Unreadable endpoint logs: nothing is proposed, nothing crashes.
    def broken(*a):
        raise RuntimeError("endpoint log index unreachable")

    ants.engineer = engineer(library["detections"], raw=broken)
    r3 = ants.run(["PG-IPCONFIG"], [HOST1], label="endpoint logs cannot be read")
    d3 = r3["detection_proposals"]
    if d3["proposals"] or not d3["error"]:
        fails.append(f"unreadable logs: {d3}")
    _ = plan
    return fails, ("refused: marker-keyed rule, non-plain terms; nothing proposed for marker-only "
                   "steps or an uncovered technique; a non-catching rule is reported; unreadable "
                   "logs give no proposal")


def s_search_changes():
    """Every change to how a test is searched is written down with the reason."""
    ants, fails = Ants(), []
    test = "T-DNS-003"

    def kinds(report):
        return [c["change"] for c in report["search_changes"]]

    r1 = ants.run([test], [HOST1], label="first run: found by the wide search")
    r2 = ants.run([test], [HOST1], label="repeat run: found in the remembered place")
    ants.defences[test]["splunk_rule"] = dict(DNS_RULE, sourcetype="XmlWinEventLog:Sysmon")
    r3 = ants.run([test], [HOST1], label="the logs moved to another sourcetype")
    ants.defences[test] = {}
    r4 = ants.run([test], [HOST1], label="the detection stopped working")
    got = [kinds(r) for r in (r1, r2, r3, r4)]
    if got != [["learned"], ["confirmed"], ["added"], ["dropped"]]:
        fails.append(f"changes {got}, expected learned, confirmed, added, dropped")
    first = (r1["search_changes"] or [{}])[0]
    evidence = first.get("evidence", {})
    if (evidence.get("sourcetype") != "stream:dns" or evidence.get("field") != "query"
            or "stream:dns" not in first.get("search_next", "")):
        fails.append(f"first entry does not say where the evidence was: {first}")
    if "Sysmon" not in (r3["search_changes"] or [{}])[0].get("search_next", ""):
        fails.append("the moved location is not in the next search")
    if not (r4["search_changes"] or [{}])[0].get("search_next", "").startswith("wide"):
        fails.append("after a confirmed miss the next search is not the wide one")
    log = ants.analyst.read_log()
    if len(log) != 4 or ants.analyst.verify_log() != (True, None):
        fails.append(f"change log has {len(log)} entries or does not verify")
    path = ants.analyst.log_path
    lines = path.read_text(encoding="utf-8").splitlines()
    edited = json.loads(lines[0])
    edited["why"] = "edited afterwards"
    path.write_text(chr(10).join([json.dumps(edited)] + lines[1:]) + chr(10), encoding="utf-8")
    if ants.analyst.verify_log()[0]:
        fails.append("an edited change-log entry was not detected")
    return fails, ("learned -> confirmed -> added -> dropped, each with its reason; "
                   "edits to the log are detected")


def s_gate_hardening():
    """Review fixes: injection through an address, look-alike hosts, restart replay, limits."""
    ants, fails = Ants(), []
    g = ants.gatekeeper

    def refused(label, step, reason):
        try:
            g.authorise(step)
            fails.append(f"NOT refused: {label}")
        except Refused as e:
            if e.reason != reason:
                fails.append(f"{label}: refused for {e.reason!r}, expected {reason!r}")

    def signed_step(test="T-EXEC-001", host=HOST1):
        plan = ants.planner.plan([test], [host])
        g.sign_plan(plan, "purple.lead")
        return plan.steps[0]

    # 1. An address that is not an address cannot smuggle a second command.
    try:
        ants.planner.plan(["T-NET-004"], [dict(HOST1, target_ip="10.0.0.9:445 & whoami & rem ")])
        fails.append("planner accepted a target address with a command in it")
    except ValueError:
        pass
    step = signed_step("T-NET-004")
    step.target_ip = "10.0.0.9:445 & whoami & rem "
    step.command = "tcp-connect " + step.target_ip + ":445"
    refused("command injected through the target address", step, "bad_address")
    step = signed_step()
    step.id = "x & net user"
    refused("step id that is not a UUID", step, "bad_step_id")
    step = signed_step("T-NET-004")
    step.target_ip = "10.9.9.9"
    step.command = "tcp-connect 10.9.9.9:445"
    refused("target address that is not on the scope list", step, "out_of_scope")

    # 2. Look-alike host names are not the host on the list.
    for name in ("ws-test-01.prod.corp.example", "WS-TEST-01.evil.example", "10.0.0.5"):
        step = signed_step()
        step.host = name
        refused(f"host {name}", step, "out_of_scope")

    # 3. Replay after a restart, and from a second gatekeeper on the same files.
    step = signed_step()
    g.authorise(step)
    restarted = Gatekeeper(ants.scope, ants.planner.actions, g._key, g.audit_path,
                           g.kill_switch_path)
    for label, keeper in (("restarted gatekeeper", restarted), ("same gatekeeper", g)):
        try:
            keeper.authorise(step)
            fails.append(f"replay allowed by the {label}")
        except Refused as e:
            if e.reason != "replay":
                fails.append(f"{label}: {e.reason!r}, expected 'replay'")

    # 4. The step limit holds across several signing calls for one run.
    g.max_steps = 2
    plan = ants.planner.plan(ALL_TESTS, [HOST1])
    for one in plan.steps:                          # sign one step at a time
        g.sign_plan(type(plan)(plan.run_id, plan.created, [one]), "purple.lead")
    ran = 0
    for one in plan.steps:
        try:
            g.authorise(one)
            ran += 1
        except Refused as e:
            if e.reason != "too_many_steps":
                fails.append(f"over-limit step refused for {e.reason!r}")
    if ran != 2:
        fails.append(f"{ran} steps authorised with a limit of 2")
    g.max_steps = 20

    # 5. A signature made for one window is void under another.
    step = signed_step()
    later = dict(ants.scope, not_after=(datetime.now(timezone.utc) + timedelta(days=3)).isoformat())
    other = Gatekeeper(later, ants.planner.actions, g._key, g.audit_path, g.kill_switch_path)
    try:
        other.authorise(step)
        fails.append("a step signed for one window ran under another window")
    except Refused as e:
        if e.reason != "bad_signature":
            fails.append(f"other window: {e.reason!r}, expected 'bad_signature'")

    # 6. Every refusal above is in the audit log, with the command.
    log = g.read_audit()
    refusals = [e for e in log if e["event"] == "refused"]
    if len(refusals) < 9 or not all("command" in e for e in refusals):
        fails.append(f"{len(refusals)} refusals in the audit log, or the command is missing")
    if g.verify_audit() != (True, None):
        fails.append("audit log does not verify after the refusals")
    emit("Gatekeeper", f"{len(refusals)} attempts refused and logged: injected command, bad id, "
                       f"look-alike hosts, replay after restart, step limit, other window",
         status="stop", data=[{"test": e.get("test_id"), "host": e.get("host"), "why": e.get("detail")}
                              for e in refusals])
    return fails, (f"{len(refusals)} bypass attempts refused and logged: injection, look-alike "
                   f"hosts, replay after restart, step limit, signature under another window")


def s_matcher_hardening():
    """Review fixes: a learned rule cannot claim another step's alert; unasked sources; drift."""
    ants, fails = Ants(), []
    test, rule = "T-DNS-003", DNS_RULE["rule_name"]
    # One person confirming twice counts once.
    ants.rulebook.confirm(test, "splunk", rule, "purple.analyst.1")
    ants.rulebook.confirm(test, "splunk", rule, "purple.analyst.1")
    if ants.rulebook.trusted(test, "splunk"):
        fails.append("the same person confirming twice made the rule trusted")
    ants.rulebook.confirm(test, "splunk", rule, "purple.analyst.2")

    # Two steps of the same test in one run; only the first has an alert (with ITS marker).
    # The second must not be "detected" by the first one's alert through the learned rule.
    r1 = ants.run([test], [HOST1], label="one alert, carrying its own marker")
    want(fails, r1, test, DETECTED)
    ants.defences[test] = {}
    ants.runs = 0                                   # do not age: the old alert is still in the window
    r2 = ants.run([test], [HOST1], label="next run right after, detection removed")
    ants.runs = 2
    want(fails, r2, test, MISSED)                   # not Detected through run 1's alert
    if [d["kind"] for d in r2["regressions"]] != ["regression"]:
        fails.append(f"the regression was hidden: {r2['drift']}")

    # A source that was expected but never asked is Could not check, not Missed.
    plan = ants.planner.plan(["T-EXEC-001"], [HOST1])
    ants.gatekeeper.sign_plan(plan, "purple.lead")
    ants.defences["T-EXEC-001"] = {}                # nothing would be seen anyway
    ants.agent.run(plan.steps[0])
    verdict = ants.matcher.fuse(plan.steps, ants.splunk.observe(plan.steps, set()),
                                {"splunk": ants.splunk.candidates})[0]
    if verdict.outcome != COULD_NOT_CHECK or verdict.reason != "no_observer":
        fails.append(f"Falcon never asked -> {verdict.outcome} ({verdict.reason})")

    # Prevented baseline, then Falcon down: Detected via Splunk must not be a regression.
    ants2 = ants
    ants2.defences["T-FILE-002"] = dict(DEFENCES["T-FILE-002"])
    b1 = ants2.run(["T-FILE-002"], [HOST1], label="baseline: prevented")
    want(fails, b1, "T-FILE-002", PREVENTED)
    MOCK["falcon_mode"] = "error"
    b2 = ants2.run(["T-FILE-002"], [HOST1], label="Falcon cannot be checked")
    MOCK["falcon_mode"] = "ok"
    want(fails, b2, "T-FILE-002", DETECTED, finding="partly checked")
    if b2["regressions"] or [d["kind"] for d in b2["drift"]] != ["unknown"]:
        fails.append(f"partly checked run reported as a regression: {b2['drift']}")
    b3 = ants2.run(["T-FILE-002"], [HOST1], label="Falcon back")
    want(fails, b3, "T-FILE-002", PREVENTED)
    if b3["drift"]:
        fails.append(f"history was overwritten by the partly checked run: {b3['drift']}")

    # An address-only match is flagged, never silently trusted.
    ants.defences["T-NET-004"] = {"splunk_rule": {"sourcetype": "pan:traffic",
                                                  "rule_name": "SMB to server", "ips": True}}
    n1 = ants.run(["T-NET-004"], [HOST1], label="network step matched on addresses only")
    want(fails, n1, "T-NET-004", DETECTED, finding="weak match")
    return fails, ("learned rule cannot claim another step's alert; unasked source is Could not "
                   "check; a partly checked run is not a regression; address-only match flagged")


def s_gate_out_of_scope():
    """A host that is not on the scope list is never touched."""
    ants, fails = Ants(), []
    r = ants.run(["T-EXEC-001", "T-DNS-003"], [HOST1, OUTSIDER])
    want(fails, r, "T-EXEC-001", DETECTED)
    want(fails, r, "T-DNS-003", DETECTED)
    want_not_run(fails, r, "out_of_scope", 2)
    if any("ws-prod-77" in json.dumps(x).lower()
           for x in TELEMETRY.splunk_rows + TELEMETRY.falcon_alerts):
        fails.append("telemetry exists for the out-of-scope host: a step ran there")
    return fails, "2 steps on the out-of-scope host refused; nothing ran there"


def s_gate_tampered():
    """A step changed after signing is refused."""
    ants, fails = Ants(), []

    def tamper(index, step):
        if index == 0:
            step.host = HOST2["name"]                       # in scope, but not what was signed
        if index == 1:
            step.command = step.command + " & whoami"       # not the allow-listed command

    r = ants.run(["T-EXEC-001", "T-FILE-002", "T-DNS-003"], [HOST1], before_step=tamper)
    want_not_run(fails, r, "bad_signature", 1)
    want_not_run(fails, r, "command_not_allowed", 1)
    want(fails, r, "T-DNS-003", DETECTED)
    return fails, "changed host -> bad signature; changed command -> not allow-listed"


def s_gate_kill_switch():
    """Once the kill switch is engaged, no further step runs."""
    ants, fails = Ants(), []

    def pull(index, step):
        if index == 2:
            ants.gatekeeper.engage_kill_switch("soc.oncall", "stop requested")

    r = ants.run(ALL_TESTS, [HOST1], before_step=pull)
    want(fails, r, "T-EXEC-001", DETECTED)
    want(fails, r, "T-FILE-002", PREVENTED)
    want_not_run(fails, r, "kill_switch", 2)
    events = [e["event"] for e in ants.gatekeeper.read_audit()]
    if "kill_switch_engaged" not in events:
        fails.append("kill switch not in the audit log")
    return fails, "2 steps ran, kill switch engaged, the remaining 2 refused"


def s_gate_outside_window():
    """Outside the approved time window nothing runs."""
    now = datetime.now(timezone.utc)
    ants, fails = Ants(scope={
        "allowed_hosts": [HOST1["name"]], "allowed_targets": [HOST1["target_ip"]],
        "allowed_actions": ["echo_marker", "drop_marker_file", "dns_lookup_marker", "tcp_probe"],
        "not_before": (now - timedelta(days=2)).isoformat(),
        "not_after": (now - timedelta(days=1)).isoformat(), "max_steps": 20}), []
    r = ants.run(["T-EXEC-001", "T-DNS-003"], [HOST1])
    want_not_run(fails, r, "outside_window", 2)
    if r["steps"] or r["detection_rate"] is not None or step_rows():
        fails.append("something ran or was scored outside the window")
    return fails, "window ended yesterday: both steps refused, nothing scored"


def s_gate_replay_and_limit():
    """A signed step is authorised once; a run cannot exceed its step limit."""
    ants, fails = Ants(), []
    plan = ants.planner.plan(["T-EXEC-001"], [HOST1])
    ants.gatekeeper.sign_plan(plan, "purple.lead")
    ants.agent.run(plan.steps[0])
    try:
        ants.agent.run(plan.steps[0])
        fails.append("the same signed step ran twice")
    except Refused as e:
        if e.reason != "replay":
            fails.append(f"second run refused for {e.reason!r}, expected 'replay'")
    unsigned = Planner().plan(["T-EXEC-001"], [HOST1]).steps[0]
    try:
        ants.agent.run(unsigned)
        fails.append("an unsigned step ran")
    except Refused as e:
        if e.reason != "not_signed":
            fails.append(f"unsigned step refused for {e.reason!r}")
    ants.gatekeeper.max_steps = 2
    big = ants.planner.plan(ALL_TESTS, [HOST1])
    over = ants.gatekeeper.sign_plan(big, "purple.lead")
    if [e.reason for _, e in over] != ["too_many_steps", "too_many_steps"]:
        fails.append(f"step limit not enforced: {[e.reason for _, e in over]}")
    emit("Gatekeeper", "Replay refused, unsigned step refused, step limit enforced")
    return fails, "replay refused; unsigned step refused; step limit of 2 enforced"


def s_audit_tamper():
    """An edited or removed audit entry is detected."""
    ants, fails = Ants(), []
    ants.run(["T-EXEC-001", "T-DNS-003"], [HOST1])
    path = ants.gatekeeper.audit_path
    original = path.read_text(encoding="utf-8")
    if ants.gatekeeper.verify_audit() != (True, None):
        fails.append("untouched audit log does not verify")
    lines = original.splitlines()
    edited = json.loads(lines[1])
    edited["host"] = "WS-SOMETHING-ELSE"
    path.write_text("\n".join([lines[0], json.dumps(edited)] + lines[2:]) + "\n", encoding="utf-8")
    ok, seq = ants.gatekeeper.verify_audit()
    if ok or seq != 2:
        fails.append(f"edited entry not detected (ok={ok}, seq={seq})")
    path.write_text("\n".join(lines[:2] + lines[3:]) + "\n", encoding="utf-8")
    ok, seq = ants.gatekeeper.verify_audit()
    if ok:
        fails.append("removed entry not detected")
    path.write_text("\n".join(lines[:-2]) + "\n", encoding="utf-8")       # cut off the end
    if ants.gatekeeper.verify_audit()[0]:
        fails.append("cut-off tail not detected")
    import hashlib
    prev, rewritten = "0" * 64, []
    for line in lines:                                  # rewrite everything, re-hash without the key
        entry = json.loads(line)
        entry["host"], entry["prev"] = "WS-REWRITTEN", prev
        body = {k: v for k, v in entry.items() if k != "hash"}
        entry["hash"] = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        prev = entry["hash"]
        rewritten.append(json.dumps(entry))
    path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
    if ants.gatekeeper.verify_audit()[0]:
        fails.append("a fully rewritten, re-hashed log was not detected")
    plan = ants.planner.plan(["T-EXEC-001"], [HOST1])
    try:
        ants.gatekeeper.sign_plan(plan, "purple.lead")
        ants.agent.run(plan.steps[0])
        fails.append("a step ran while the audit log did not verify")
    except Refused as e:
        if e.reason not in ("audit_broken", "not_signed"):
            fails.append(f"broken log: refused for {e.reason!r}")
    path.write_text(original, encoding="utf-8")
    if ants.gatekeeper.verify_audit() != (True, None):
        fails.append("restored audit log does not verify")
    emit("Gatekeeper", f"Audit log: {len(lines)} entries; an edit, a removal, a cut-off end and "
                       f"a re-hashed rewrite are all detected, and nothing runs while it is broken")
    return fails, (f"{len(lines)} audit entries; edit, removal, cut-off end and re-hashed rewrite "
                   f"all detected; no step runs while the log is broken")


def _falcon_broken(mode, reason):
    ants, fails = Ants(), []
    ants.defences["T-EXEC-001"]["forward"] = False      # so only Falcon could have seen it
    MOCK["falcon_mode"] = mode
    r = ants.run(["T-EXEC-001", "T-FILE-002"], [HOST1])
    want(fails, r, "T-EXEC-001", COULD_NOT_CHECK)       # not Missed
    step = outcome_of(r, "T-EXEC-001")
    if step and step["reason"] != reason:
        fails.append(f"reason {step['reason']!r}, expected {reason!r}")
    want(fails, r, "T-FILE-002", DETECTED, finding="partly checked")
    if r["detection_rate"] != 1.0 or r["scored_steps"] != 1:
        fails.append(f"rate {r['detection_rate']} over {r['scored_steps']}: the unchecked "
                     f"step must be left out of the rate")
    return fails, (f"Falcon {reason}: the Falcon-only step is Could not check, the other is "
                   f"Detected from Splunk and flagged partly checked")


def s_falcon_down():
    """Falcon API answers with an error: Could not check, never Missed."""
    return _falcon_broken("error", "search_failed")


def s_falcon_auth():
    """Falcon rejects the sign-in."""
    return _falcon_broken("auth", "auth_failed")


def s_falcon_unreachable():
    """The connection to Falcon drops."""
    return _falcon_broken("drop", "source_unreachable")


def s_pipeline_gap():
    """Falcon sees it, the forwarded copy never reaches Splunk: a finding of its own."""
    ants, fails = Ants(), []
    ants.defences["T-EXEC-001"]["forward"] = False
    r = ants.run(["T-EXEC-001"], [HOST1])
    want(fails, r, "T-EXEC-001", DETECTED, finding="log pipeline gap", sightings=1)
    return fails, "Detected by Falcon, missing in Splunk -> log pipeline gap reported"


def s_prevention_gap():
    """A step that should be blocked is only detected."""
    ants, fails = Ants(), []
    ants.defences["T-FILE-002"]["falcon"] = "detect"
    r = ants.run(["T-FILE-002"], [HOST1])
    want(fails, r, "T-FILE-002", DETECTED, finding="prevention gap")
    return fails, "expected Prevented, got Detected -> prevention gap reported"


def s_learned_rule():
    """A rule confirmed twice by purple team matches an alert that has no marker."""
    ants, fails = Ants(), []
    test, rule = "T-DNS-003", DNS_RULE["rule_name"]
    r1 = ants.run([test], [HOST1], label="marker match, confirmed by purple team")
    want(fails, r1, test, DETECTED)
    ants.rulebook.confirm(test, "splunk", rule, "purple.analyst.1")
    if ants.rulebook.trusted(test, "splunk"):
        fails.append("rule trusted after a single confirmation")
    r2 = ants.run([test], [HOST1], label="marker match, confirmed again")
    want(fails, r2, test, DETECTED)
    ants.rulebook.confirm(test, "splunk", rule, "purple.analyst.2")
    emit("Matcher", f"Purple team confirmed rule '{rule}' twice: it is now trusted for {test}")

    ants.defences[test]["marker_in_alert"] = False       # the alert no longer carries the marker
    r3 = ants.run([test], [HOST1], label="alert without the marker")
    want(fails, r3, test, DETECTED, finding="needs confirmation")
    obs = (outcome_of(r3, test) or {}).get("observations", [{}])[0]
    if obs.get("method") != "learned_rule":
        fails.append(f"run 3 method {obs.get('method')!r}, expected 'learned_rule'")

    ants.defences[test]["noise_before"] = True           # the rule also fires when nothing runs
    r4 = ants.run([test], [HOST1], label="same rule also fires in the quiet window")
    want(fails, r4, test, MISSED, finding="learned rule not used")
    return fails, ("confirmed twice -> trusted; unmarked alert matched by the learned rule and "
                   "flagged; not used when the rule also fires in the quiet window")


def s_drift():
    """Detected last run, missed now is a regression. Could not check is not."""
    ants, fails = Ants(), []
    r1 = ants.run(["T-EXEC-001"], [HOST1], label="baseline")
    want(fails, r1, "T-EXEC-001", DETECTED)
    ants.defences["T-EXEC-001"] = {}                      # the detection stops working
    r2 = ants.run(["T-EXEC-001"], [HOST1], label="detection broken")
    want(fails, r2, "T-EXEC-001", MISSED)
    if [d["kind"] for d in r2["regressions"]] != ["regression"]:
        fails.append(f"regression not reported: {r2['drift']}")
    ants.defences["T-EXEC-001"] = {"falcon": "detect", "forward": False}
    MOCK["falcon_mode"] = "error"
    r3 = ants.run(["T-EXEC-001"], [HOST1], label="Falcon cannot be checked")
    want(fails, r3, "T-EXEC-001", COULD_NOT_CHECK)
    if r3["regressions"] or [d["kind"] for d in r3["drift"]] != ["unknown"]:
        fails.append(f"an unchecked step was reported as drift: {r3['drift']}")
    return fails, "Detected -> Missed reported as a regression; Could not check is 'unknown', not a regression"


# ----------------------------------------------------------------------------
# Attack library (for the demo page) and a run of whatever was picked from it
# ----------------------------------------------------------------------------
def _defence_text(action_id):
    d = DEFENCES.get("action:" + action_id)
    if not d:
        return "Nothing reacts, so the step should come back Missed."
    parts = []
    if d.get("falcon") == "prevent":
        parts.append("Falcon blocks it")
    elif d.get("falcon") == "detect":
        parts.append("Falcon raises an alert")
    if d.get("falcon"):
        parts.append("the alert is forwarded to Splunk" if d.get("forward")
                     else "the alert is not forwarded to Splunk")
    if d.get("splunk_rule"):
        parts.append(f"a Splunk rule fires ({d['splunk_rule']['rule_name']})")
    if d.get("proofpoint"):
        parts.append("the mail gateway quarantines the email and logs it to Splunk"
                     if d["proofpoint"] == "quarantine" else "the mail gateway delivers the email")
    if d.get("checkpoint"):
        parts.append("the firewall drops the request and logs it to Splunk"
                     if d["checkpoint"] == "drop" else "the firewall accepts the request")
    text = ", ".join(parts) + "."
    return text[0].upper() + text[1:]


def attack_library():
    """Every action on the allow-list and every family the ants refuse, by ATT&CK tactic."""
    data = json.loads(Path(CATALOGUE_PATH).read_text(encoding="utf-8"))
    detections = json.loads(Path(DETECTIONS_PATH).read_text(encoding="utf-8"))
    names = dict(data.get("techniques", {}))
    reversible_actions, reversible_names = load_reversible()
    names.update(reversible_names)
    data["actions"] = {**data["actions"], **reversible_actions}

    def info(tech):
        entry = names.get(tech) or names.get(tech.split(".", 1)[0]) or {}
        return entry.get("name", tech), entry.get("tactic", "")

    attacks = []
    for action_id, action in data["actions"].items():
        tech = action["techniques"][0]
        name, tactic = info(tech)
        attacks.append({
            "id": action_id, "technique": tech, "name": name, "tactic": tactic,
            "description": action["description"], "command": action["command"],
            "category": action.get("category", "endpoint"),
            "fidelity": action.get("fidelity", "full"),
            "agentless": bool(action.get("agentless")),
            "tool": action.get("tool"),
            "reversible": bool(action.get("reversible")),
            "changes": action.get("changes"), "cleanup": action.get("cleanup"),
            "verify": action.get("verify"),
            "expect": action.get("expect", {}),
            "detections": [{"id": d["id"], "title": d["title"], "kind": d["kind"]}
                           for d in detections["detections"] if tech in d["techniques"]],
            "no_behaviour": detections.get("no_behaviour", {}).get(action_id),
            "sandbox_defence": _defence_text(action_id),
        })
    refused = []
    for tech, why in data.get("not_simulated", {}).items():
        name, tactic = info(tech)
        refused.append({"technique": tech, "name": name, "tactic": tactic, "why": why})
    order = lambda t: TACTIC_ORDER.index(t) if t in TACTIC_ORDER else 99   # noqa: E731
    used = sorted({a["tactic"] for a in attacks} | {r["tactic"] for r in refused}, key=order)
    attacks.sort(key=lambda a: (order(a["tactic"]), a["technique"]))
    refused.sort(key=lambda r: (order(r["tactic"]), r["technique"]))
    return {"tactics": used, "attacks": attacks, "not_simulated": refused,
            "hosts": [HOST1["name"], HOST2["name"]]}


def s_custom():
    """Run the attack types picked in the library through every ant. Shows a run; asserts little."""
    spec = json.loads(os.environ.get("SANDBOX_CUSTOM") or "{}")
    library = attack_library()
    known = {a["technique"]: a for a in library["attacks"]}
    known.update({r["technique"]: r for r in library["not_simulated"]})
    picked = [t for t in dict.fromkeys(spec.get("techniques") or []) if t in known]
    hosts = [h for h in (HOST1, HOST2) if h["name"] in (spec.get("hosts") or [HOST1["name"]])]
    name = re.sub(r"[^A-Za-z0-9 _\-]", "", str(spec.get("name") or ""))[:48].strip() or "Library selection"
    if not picked or not hosts:
        return ["nothing to run: pick at least one attack type and one host"], "custom run"
    # Change-and-undo attack types switch that kind of action on for this run. They still
    # only run on the dedicated test machine.
    ants, fails, box = Ants(reversible=any(known[t].get("reversible") for t in picked)), [], {}

    def build():
        techniques = sorted((Technique(id=t, name=known[t]["name"], tactic=known[t]["tactic"])
                             for t in picked), key=lambda t: (t.order, t.id))
        threat = Threat(id="library-selection", name=name, kind="selection",
                        description="Picked in the attack library", techniques=techniques)
        emit("Library", f"Scenario '{name}' came in from the attack library: "
                        f"{len(techniques)} attack type(s)", data=threat.to_dict())
        draft = ants.builder.draft(threat)
        gaps = [c for c in draft["coverage"] if c["status"] in ("not simulated", "no action")]
        emit("Scenario builder", f"Draft '{draft['id']}': {len(draft['tests'])} test(s) built from "
                                 f"the action library; {len(gaps)} attack type(s) cannot be tested",
             status="stop" if gaps else "ok", data=draft)
        scenario = ants.builder.approve(draft["id"], "sandbox.operator")
        emit("Scenario builder", f"Approved by {scenario['approved_by']} (the person who pressed "
                                 f"Run); the approval is bound to these {len(scenario['tests'])} test(s)")
        box["scenario"] = scenario
        return ants.planner.use_scenario(scenario)

    try:
        report = ants.run(build, hosts, label=f"{name}: built and run", scenario=box)
    except ValueError as e:
        return [str(e)], "custom run"
    if not report["audit_intact"]:
        fails.append("the audit log does not verify")
    totals = report["totals"]
    rate = report["detection_rate"]
    return fails, (f"{len(report['steps'])} step(s) on {len(hosts)} host(s): "
                   f"{totals[DETECTED]} Detected, {totals[PREVENTED]} Prevented, "
                   f"{totals[MISSED]} Missed, {totals[COULD_NOT_CHECK]} Could not check; "
                   f"detection rate {'n/a' if rate is None else format(rate, '.0%')}")


SAMPLE_ATOMICS = HERE / "ants" / "sample_atomics.yaml"


def trial_draft(librarian, draft_id):
    """Try a draft action in a throw-away sandbox, before anyone is asked to approve it.

    It shows that the action plans, passes the gatekeeper and leaves a marked endpoint
    log. It cannot show that the command is harmless: the agent here is simulated.
    That is what the rules and the person are for.
    """
    draft = librarian.load(draft_id)
    notes, passed = [], False
    try:
        trial = Ants(work=Path(tempfile.mkdtemp(prefix="oaev-trial-")),
                     extra_actions={draft_id: draft["action"]})
        test_id = f"TRIAL-{draft['technique']}"
        trial.planner.tests[test_id] = {
            "id": test_id, "title": f"Trial of {draft_id}", "technique": draft["technique"],
            "action": draft_id, "expect": dict(draft["action"]["expect"])}
        plan = trial.planner.plan([test_id], [HOST1])
        refused = trial.gatekeeper.sign_plan(plan, "sandbox.trial")
        if refused:
            notes.append(f"the gatekeeper refused it: {refused[0][1].detail}")
        else:
            step = plan.steps[0]
            trial.agent.run(step)
            logged = [r for r in TELEMETRY.splunk_rows
                      if r.get("index") == RAW_INDEX and step.id in str(r.get("process"))]
            seen = trial.splunk.observe([step], set())
            passed = bool(logged) and seen[0].outcome == MISSED
            notes.append(f"planned, signed and run; {len(logged)} marked endpoint log; with no "
                         f"defence in the sandbox the step reads {seen[0].outcome}")
    except Exception as e:               # a trial must report, never crash the run
        notes.append(f"the trial itself failed: {type(e).__name__}: {e}")
    return librarian.record_trial(draft_id, passed, "; ".join(notes))


def s_librarian():
    """A scenario names techniques the library has no action for. The librarian finds harmless public tests; a person approves them."""
    work = WORK / "librarian"
    ants, fails, box = Ants(), [], {}
    librarian = Librarian(SAMPLE_ATOMICS, ants.planner.actions, ants.planner.not_simulated, work)
    wanted = [("T1082", "System Information Discovery", "discovery"),
              ("T1049", "System Network Connections Discovery", "discovery"),
              ("T1007", "System Service Discovery", "discovery"),
              ("T1012", "Query Registry", "discovery"),
              ("T1124", "System Time Discovery", "discovery"),
              ("T1135", "Network Share Discovery", "discovery"),
              ("T1053.005", "Scheduled Task", "persistence"),
              ("T1547.001", "Registry Run Keys", "persistence"),
              ("T1003.001", "LSASS Memory", "credential-access"),
              ("T1999", "A technique no public test covers", "discovery")]
    threat = Threat(id="library-gap-demo", name="Scenario with gaps", kind="selection",
                    description="Mostly techniques the library has no action for",
                    techniques=[Technique(id=t, name=n, tactic=c) for t, n, c in wanted])

    def build(planner, builder):
        draft = builder.draft(threat)
        gaps = [c for c in draft["coverage"] if c["status"] in ("not simulated", "no action")]
        emit("Scenario builder", f"Draft '{draft['id']}': {len(draft['tests'])} test(s) built from the "
                                 f"action library; {len(gaps)} technique(s) cannot be tested",
             status="stop" if gaps else "ok", data=draft)
        scenario = builder.approve(draft["id"], "purple.lead")
        box.update(draft=draft, scenario=scenario)
        return planner.use_scenario(scenario)

    def first():
        tests = build(ants.planner, ants.builder)
        missing = [c["technique"] for c in box["draft"]["coverage"] if c["status"] == "no action"]
        found = librarian.fill_gaps(missing)
        box["found"] = {f["technique"]: f for f in found}
        drafts = [f for f in found if f["status"] == "draft"]
        emit("Librarian", f"{len(missing)} technique(s) with no action: {len(drafts)} draft(s) from "
                          f"harmless public tests, {len(found) - len(drafts)} left as gaps",
             status="stop" if len(drafts) < len(found) else "ok", data=found)
        for item in drafts:
            tried = trial_draft(librarian, item["draft_id"])
            item["trial"] = tried["trial"]
        emit("Librarian", f"Sandbox trial: {sum(1 for d in drafts if d['trial']['passed'])} of "
                          f"{len(drafts)} draft(s) passed. They wait for a person; nothing is "
                          f"on the allow-list yet", data=drafts)
        return tests

    r1 = ants.run(first, [HOST1], label="before: what the library can test today", scenario=box)
    found = box["found"]
    status = {t: f["status"] for t, f in found.items()}
    expected = {"T1049": "draft", "T1007": "draft", "T1012": "draft", "T1124": "draft", "T1135": "draft",
                "T1053.005": "nothing harmless found", "T1547.001": "nothing harmless found",
                "T1999": "not in the public library"}
    if status != expected:
        fails.append(f"librarian results {status}")
    if "T1003.001" in found or librarian.find("T1003.001")["status"] != "refused family":
        fails.append("a refused family was looked up in the public library")
    if len(r1["steps"]) != 1:
        fails.append(f"{len(r1['steps'])} step(s) ran before any approval, expected only T1082")
    if librarian.approved_actions():
        fails.append("a draft is usable without an approval")
    why = " ".join(" ".join(c["why"]) for c in found["T1053.005"]["candidates"])
    if "changes something" not in why:
        fails.append(f"the scheduled-task test was refused for the wrong reason: {why}")
    drafts = sorted(f["draft_id"] for f in found.values() if f["status"] == "draft")

    def refused(label, fn):
        try:
            fn()
            fails.append(f"{label}: accepted")
        except (LibrarianError, ValueError):
            pass

    # Guards on the way to the allow-list.
    untried = librarian.find("T1201")["draft_id"]              # a draft that had no trial
    refused("approval without a sandbox trial", lambda: librarian.approve(untried, "purple.lead"))
    refused("approval without a person", lambda: librarian.approve(drafts[0], " "))
    path = work / f"{drafts[0]}.json"
    honest = path.read_text(encoding="utf-8")
    changed = json.loads(honest)
    changed["source_command"] = "net user guest /active:yes"
    changed["action"]["command"] = "cmd.exe /c net user guest /active:yes & rem oaev-step-{marker}"
    path.write_text(json.dumps(changed), encoding="utf-8")
    refused("approval of a draft edited into something that changes an account",
            lambda: librarian.approve(drafts[0], "purple.lead"))
    path.write_text(honest, encoding="utf-8")
    refused("an action for a refused family on the allow-list", lambda: Planner().add_actions(
        {"art_t1003_demo": {"command": "cmd.exe /c whoami & rem oaev-step-{marker}", "techniques": ["T1003.001"]}}))

    for draft_id in drafts:
        librarian.approve(draft_id, "purple.lead")
    if sorted(librarian.approved_actions()) != drafts:
        fails.append(f"approved actions {sorted(librarian.approved_actions())}")
    # Changed after approval: dropped when the approved actions are loaded.
    changed = json.loads(path.read_text(encoding="utf-8"))
    changed["action"]["command"] = "cmd.exe /c whoami /all & rem oaev-step-{marker}"
    path.write_text(json.dumps(changed), encoding="utf-8")
    if drafts[0] in librarian.approved_actions():
        fails.append("a draft changed after its approval is still usable")
    path.write_text(honest, encoding="utf-8")          # put back as it was, then approve again
    librarian.approve(drafts[0], "purple.lead")

    approved = librarian.approved_actions()
    ants2 = Ants(work=Path(tempfile.mkdtemp(prefix="oaev-ants-")), extra_actions=approved)
    emit("Librarian", f"{len(approved)} action(s) approved by purple.lead and added to the allow-list",
         data=[{"technique": a["techniques"][0], "status": "approved", "command": a["command"],
                "draft_id": i, "name": a["description"]} for i, a in approved.items()])
    r2 = ants2.run(lambda: build(ants2.planner, ants2.builder), [HOST1],
                   label="after: the same scenario with the approved actions", scenario=box)
    cover = {}
    for c in box["draft"]["coverage"]:
        cover[c["status"]] = cover.get(c["status"], 0) + 1
    if cover != {"simulated": 6, "not simulated": 1, "no action": 3}:
        fails.append(f"coverage after approval {cover}")
    if len(r2["steps"]) != 6 or r2["not_run"]:
        fails.append(f"{len(r2['steps'])} step(s) scored after approval, {len(r2['not_run'])} not run")
    if not r2["audit_intact"]:
        fails.append("audit log chain is broken")

    # The five new tests are missed, and the library has no detection for their techniques:
    # the detection engineer builds one from each test's command, and one combined one.
    proposals = r2["detection_proposals"]["proposals"]
    built = [p for p in proposals if p.get("origin") == "built from the test"]
    burst = next((p for p in built if p["kind"] == "burst"), None)
    status = sorted(p["status"] for p in built if p["kind"] == "single")
    if len(built) != 6 or status != ["ready for review"] * 4 + ["too noisy"]:
        fails.append(f"built detections: {[(p['title'], p['status']) for p in built]}")
    if not burst or (burst["status"], burst["caught"], burst["noise"]) != ("ready for review", 5, 0):
        fails.append(f"combined built detection: {burst}")
    if any("oaev" in p["spl"].lower() for p in built):
        fails.append("a built detection keys on the test marker")
    if burst:
        ants2.engineer.approve(burst["id"], "detection.lead")
        ants2.engineer.record_deployed(burst["id"], "splunk.admin")
        r3 = ants2.run(ants2.planner.use_scenario(box["scenario"]), [HOST1],
                       label="after people deployed the built detection")
        if r3["totals"][DETECTED] != 6 or r3["totals"][MISSED]:
            fails.append(f"after deployment: {r3['totals']}")
    return fails, ("9 techniques without an action: 5 drafts from harmless public tests (tried, approved by a "
                   "person, then run), 2 with only tests that change something, 1 not in the public library, "
                   "1 refused family never looked up; unsafe, untried, nameless and changed drafts all refused; "
                   "the 5 new tests were missed, the detection engineer built detections from their commands, "
                   "and after a person deployed the combined one all 6 steps are Detected")


# What the librarian's rules must allow (True) and refuse (False). Read-only tools in
# read-only forms pass; anything that changes, writes, reaches out or is not recognised
# does not.
RULE_CASES = [
    ("whoami /all", True), ("net localgroup administrators", True), ("net start", True),
    ('net group "Domain Admins" /domain', True), ("wmic os get caption", True),
    ("netsh advfirewall show allprofiles", True), ("tasklist | findstr svchost", True),
    (r"reg query HKLM\Software\Microsoft", True), ("schtasks /query /fo list", True),
    ("netstat -ano && net use", True), ("wevtutil el", True),
    ("net user bob Pass1", False),                      # sets a password
    ("net accounts /maxpwage:30", False), ("net share data=C:\\data", False),
    ("net start spooler", False), ("ipconfig /flushdns", False), ("arp -d", False),
    ("sc stop wuauserv", False), ("wmic process call create calc", False),
    ("wevtutil cl Security", False),                    # clears a log
    ("netsh wlan show profile name=x key=clear", False),  # shows stored passwords
    (r"reg query HKLM\SAM", False), ('tasklist /fi "imagename eq lsass.exe"', False),
    ("echo hi > x.txt", False), ("dir & del x", False), ("whoami & cmd /c calc", False),
    ("powershell -enc AAA", False), ("for /f %i in (x) do echo", False), ("set x=1", False),
    (r"C:\tools\x.exe", False), ("type C:\\secret.txt", False),
    ("systeminfo /s srv01", False), ("net view \\\\dc01", False),
    # Found by reading what the rules accepted from the real public library:
    ("time", False), ("date", False),                   # the bare form waits for input and can set the clock
    ("time /t", True),
    ("set", False),                                     # prints the environment, which can hold secrets
    ("query user", True), ("query user /SERVER:srv01", False),
    (r"reg query HKCU\Software\SimonTatham\PuTTY\Sessions /t REG_SZ /s", False),   # sweeps up saved sessions
    (r"where /R C:\Users\ Bookmarks", False), (r"dir /s /b %USERPROFILE%\Favorites", False),
]
POWERSHELL_CASES = [
    ("Get-Process", True), ("Get-NetTCPConnection -State Listen", True),
    ("Get-Process | Stop-Process", False), ("Get-Content C:\\x.txt", False),
    ("Get-CimInstance Win32_Service -ComputerName dc01", False),
    ("Invoke-WebRequest http://x", False), ("Get-Date; Remove-Item x", False),
]


def s_librarian_rules():
    """The librarian's rules: read-only commands pass, everything else is refused."""
    fails = []
    for cases, executor in ((RULE_CASES, "command_prompt"), (POWERSHELL_CASES, "powershell")):
        for command, expected in cases:
            allowed, why = check_command(command, executor)
            if bool(allowed) != expected:
                fails.append(f"{'allowed' if allowed else 'refused'} {command!r} ({'; '.join(why)})")
            emit("Librarian", f"{'Allowed' if allowed else 'Refused'}: {command}",
                 detail="" if allowed else "; ".join(why), status="ok" if allowed else "stop")
    total = len(RULE_CASES) + len(POWERSHELL_CASES)
    refused = sum(1 for cases in (RULE_CASES, POWERSHELL_CASES) for _, ok in cases if not ok)
    return fails, f"{total} commands checked: {total - refused} read-only ones allowed, {refused} refused"


def s_reversible():
    """Change-and-undo tests: one small marked change, undone and checked, on a dedicated test machine only."""
    fails, box = [], {}
    actions, names = load_reversible()
    techniques = [Technique(id=a["techniques"][0], name=names[a["techniques"][0]]["name"],
                            tactic=names[a["techniques"][0]]["tactic"]) for a in actions.values()]
    threat = Threat(id="change-and-undo", name="Change and undo", kind="selection",
                    description="Persistence, hiding and execution techniques", techniques=techniques)

    # Off by default: without the switch the library has no action for any of them.
    plain = Ants()
    try:
        plain.builder.draft(threat)
        fails.append("change-and-undo actions are on without the switch")
    except ValueError:
        pass

    ants = Ants(work=Path(tempfile.mkdtemp(prefix="oaev-ants-")), reversible=True)

    def build():
        draft = ants.builder.draft(threat)
        emit("Scenario builder", f"Draft '{draft['id']}': {len(draft['tests'])} change-and-undo test(s) "
                                 f"built from the action library", data=draft)
        box["scenario"] = ants.builder.approve(draft["id"], "purple.lead")
        return ants.planner.use_scenario(box["scenario"])

    r1 = ants.run(build, [HOST1, HOST2], label="nine change-and-undo tests on two machines", scenario=box)
    undone = [c for c in r1["cleanups"] if c["confirmed"]]
    if len(r1["steps"]) != 9 or len(undone) != 9 or {c["host"] for c in r1["cleanups"]} != {HOST1["name"]}:
        fails.append(f"{len(r1['steps'])} step(s) scored, {len(undone)} undo(s) confirmed")
    want_not_run(fails, r1, "reversible_not_allowed", 9)          # the second machine is not a test machine
    totals = r1["totals"]
    if (totals[DETECTED], totals[MISSED]) != (2, 7):
        fails.append(f"outcomes {totals}")
    audit = [a["event"] for a in ants.gatekeeper.read_audit()]
    if audit.count("cleanup_confirmed") != 9 or not r1["audit_intact"]:
        fails.append(f"audit log has {audit.count('cleanup_confirmed')} confirmed undo(s)")
    built = [p for p in r1["detection_proposals"]["proposals"] if p.get("origin") == "built from the test"]
    titles = sorted(p["title"] for p in built if p["kind"] == "single")
    if titles != ["attrib +h run", "bitsadmin /create run", "certutil -decode run", "cscript //nologo run",
                  "reg add run"]:
        fails.append(f"built detections {titles}")

    # An undo that cannot be confirmed: flagged, and the machine is blocked until a person clears it.
    slug = box["scenario"]["id"]
    ants.defences["action:registry_value_marked"] = {"cleanup_fails": True}
    r2 = ants.run([f"{slug}-T1112", f"{slug}-T1140"], [HOST1], label="an undo that cannot be confirmed")
    left = [s for s in r2["steps"] if any("undo not confirmed" in f for f in s["findings"])]
    if len(left) != 1 or left[0]["test_id"] != f"{slug}-T1112":
        fails.append(f"unconfirmed undo not flagged: {[s['findings'] for s in r2['steps']]}")
    want_not_run(fails, r2, "host_not_clean", 1)
    if list(ants.gatekeeper.unclean_hosts()) != [HOST1["name"].lower()]:
        fails.append(f"blocked machines {ants.gatekeeper.unclean_hosts()}")
    # A read-only step still runs on the blocked machine.
    r3 = ants.run(["T-EXEC-001"], [HOST1], label="a read-only test on the blocked machine")
    want(fails, r3, "T-EXEC-001", DETECTED)
    ants.defences.pop("action:registry_value_marked")
    ants.gatekeeper.clear_host(HOST1["name"], "purple.lead")
    r4 = ants.run([f"{slug}-T1140"], [HOST1], label="after a person checked the machine and cleared it")
    if len(r4["steps"]) != 1 or r4["not_run"] or not r4["cleanups"][0]["confirmed"]:
        fails.append("a cleared machine still refuses change-and-undo steps")

    # Guards.
    def refused(label, step, reason):
        try:
            ants.gatekeeper.authorise(step)
            fails.append(f"{label}: authorised")
        except Refused as e:
            if e.reason != reason:
                fails.append(f"{label}: refused as {e.reason}, expected {reason}")

    plan = ants.planner.plan([f"{slug}-T1053.005", "T-EXEC-001"], [HOST1])
    ants.gatekeeper.sign_plan(plan, "purple.lead")
    task, echo = plan.steps
    task.cleanup = "cmd.exe /c schtasks /delete /tn SomeoneElsesTask /f"
    refused("an undo changed to delete another task", task, "command_not_allowed")
    echo.cleanup = "cmd.exe /c del important.txt"
    refused("a read-only step given an undo", echo, "command_not_allowed")
    payload = "cmd.exe /c echo oaev-step-{marker}"
    good = actions["task_create_marked"]
    bad = {
        "launches something else": dict(good, command=good["command"].replace("cmd.exe /c echo oaev-step-{marker}\"", "calc.exe\"")),
        "runs as another account": dict(good, command=good["command"] + " /ru SYSTEM"),
        "no undo": dict(good, cleanup=""),
        "no check": dict(good, verify=""),
        "task not named with the marker": dict(good, command=good["command"].replace("/tn oaev-step-{marker}", "/tn Updater")),
        "machine-wide registry": dict(actions["run_key_marked"], command=actions["run_key_marked"]["command"].replace("HKCU", "HKLM")),
        "deletes something else": dict(actions["hidden_file_marked"], cleanup="cmd.exe /c del %TEMP%\\oaev-step-{marker}.txt & del C:\\Windows\\win.ini"),
        "uses a tool that is not on the list": dict(actions["script_marked"], command=actions["script_marked"]["command"] + " & powershell -c calc"),
    }
    for label, action in bad.items():
        if not check_reversible(action, payload):
            fails.append(f"a change-and-undo action that {label} passed the rules")
    return fails, ("9 change-and-undo tests on the dedicated test machine: all ran, were undone and checked "
                   "(2 Detected, 7 Missed, 5 detections built from the commands); the same 9 refused on a "
                   "machine that is not a test machine; an undo that could not be confirmed was flagged and "
                   "blocked the machine until a person cleared it; 8 unsafe variants refused by the rules")


class ScriptedModel:
    """Stands in for a model in the sandbox. It answers from a script, so a run is repeatable
    and needs no model at all. A real model is any callable that takes the request text."""

    def __init__(self, script):
        self.script = {k: list(v) for k, v in script.items()}
        self.seen = []
        self.current = None

    def __call__(self, request):
        self.seen.append(request)
        named = re.search(r"ATT&CK technique: (T\d{4}(?:\.\d{3})?)", request)
        if named:
            self.current = named.group(1)
        answers = self.script.get(self.current) or ['{"command": null, "why": "No idea"}']
        return answers.pop(0) if len(answers) > 1 else answers[0]


MODEL_SCRIPT = {
    # First answer changes the system and is refused; the model is told why and corrects itself.
    "T1053.005": ['{"command": "schtasks /create /tn Updater /tr calc.exe /sc onlogon", "why": "Creates a task"}',
                  '{"command": "schtasks /query /fo list", "why": "Uses the scheduled task tool to list the tasks"}'],
    "T1547.001": [r'{"command": "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", '
                  r'"why": "Reads the key a logon autostart would be written to"}'],
    # Never gives a usable answer: chat text, a smuggled second command, then something that deletes.
    "T1112": ["Sure! Here is a command you can use: reg add HKCU\\Software\\Test /v x /d 1",
                  '{"command": "whoami & powershell -enc SQBFAFgA", "why": "x"}',
                  r'{"command": "dir C:\\Users & del C:\\Users\\x", "why": "x"}'],
    "T1999": ['{"command": null, "why": "I do not know a read-only way to imitate this"}'],
}


def s_drafter():
    """No public test fits, so the drafter ant asks a model. Its answers are checked by the same rules; a person approves."""
    work = WORK / "drafter"
    ants, fails, box = Ants(), [], {}
    librarian = Librarian(SAMPLE_ATOMICS, ants.planner.actions, ants.planner.not_simulated, work)
    model = ScriptedModel(MODEL_SCRIPT)
    drafter = Drafter(librarian, model, "scripted stand-in (no real model)")
    wanted = [("T1082", "System Information Discovery", "discovery"),
              ("T1049", "System Network Connections Discovery", "discovery"),
              ("T1053.005", "Scheduled Task", "persistence"),
              ("T1547.001", "Registry Run Keys", "persistence"),
              ("T1112", "Modify Registry", "defense-impairment"),
              ("T1560.001", "Archive via Utility", "collection"),
              ("T1003.001", "LSASS Memory", "credential-access"),
              ("T1999", "A technique no public test covers", "discovery")]
    threat = Threat(id="drafter-demo", name="Quarterly purple scenario CONFIDENTIAL", kind="selection",
                    description="Techniques the public library cannot fill",
                    techniques=[Technique(id=t, name=n, tactic=c) for t, n, c in wanted])
    names = {t: (n, c) for t, n, c in wanted}

    def build(planner, builder):
        draft = builder.draft(threat)
        gaps = [c for c in draft["coverage"] if c["status"] in ("not simulated", "no action")]
        emit("Scenario builder", f"Draft '{draft['id']}': {len(draft['tests'])} test(s) built from the "
                                 f"action library; {len(gaps)} technique(s) cannot be tested",
             status="stop" if gaps else "ok", data=draft)
        scenario = builder.approve(draft["id"], "purple.lead")
        box.update(draft=draft, scenario=scenario)
        return planner.use_scenario(scenario)

    def first():
        tests = build(ants.planner, ants.builder)
        missing = [c["technique"] for c in box["draft"]["coverage"] if c["status"] == "no action"]
        found = librarian.fill_gaps(missing)
        ready = [f for f in found if f["status"] == "draft"]
        emit("Librarian", f"{len(missing)} technique(s) with no action: {len(ready)} draft(s) from "
                          f"harmless public tests, {len(found) - len(ready)} left as gaps",
             status="stop" if len(ready) < len(found) else "ok", data=found)
        left = [f["technique"] for f in found if f["status"] in ("nothing harmless found", "not in the public library")]
        asked = [drafter.draft(t, *names[t]) for t in left]
        box["asked"] = {a["technique"]: a for a in asked}
        drafted = [a for a in asked if a["status"] == "draft"]
        emit("Drafter", f"Called for {len(left)} technique(s) the librarian could not fill: {len(drafted)} "
                        f"draft(s) passed the rules after {drafter.calls} answer(s) from the model "
                        f"({drafter.model_name})",
             status="stop" if len(drafted) < len(asked) else "ok", data=asked)
        for item in ready + drafted:
            item["trial"] = trial_draft(librarian, item["draft_id"])["trial"]
        emit("Librarian", f"Sandbox trial: {sum(1 for d in ready + drafted if d['trial']['passed'])} of "
                          f"{len(ready + drafted)} draft(s) passed. They wait for a person; nothing is on "
                          f"the allow-list yet", data=ready + drafted)
        return tests

    ants.run(first, [HOST1], label="before: what the library can test today", scenario=box)
    asked = box["asked"]
    status = {t: a["status"] for t, a in asked.items()}
    if status != {"T1053.005": "draft", "T1547.001": "draft", "T1112": "refused by the rules",
                  "T1999": "model declined"}:
        fails.append(f"drafter results {status}")
    tries = {t: [x["verdict"] for x in a["tries"]] for t, a in asked.items()}
    if tries.get("T1053.005") != ["refused", "passed"] or tries.get("T1112") != ["refused"] * 3:
        fails.append(f"model answers were judged {tries}")
    if drafter.calls != 7:
        fails.append(f"the model was called {drafter.calls} times, expected 7")
    leaked = [s for s in model.seen if "CONFIDENTIAL" in s or "WS-TEST" in s or "purple" in s.lower()]
    if leaked:
        fails.append("the request to the model carries the scenario's name or a host")
    before = drafter.calls
    # Never sent to the model: a refused family, a refused tactic (collection), a technique
    # that is only in a refused tactic because the scenario says so, a covered one, a drafted one.
    for technique, tactic, expected in (("T1003.001", "credential-access", "refused family"),
                                        ("T1560.001", "collection", "refused family"),
                                        ("T1999", "exfiltration", "refused family"),
                                        ("T1082", "discovery", "already in the library"),
                                        ("T1049", "discovery", "draft")):
        got = drafter.draft(technique, "x", tactic)["status"]
        if got != expected or drafter.calls != before:
            fails.append(f"the model was asked about {technique} ({got})")
    if librarian.approved_actions():
        fails.append("a model draft is usable without a person's approval")
    if any(a["action"]["fidelity"] != "partial" for a in librarian.drafts() if a["id"].startswith("ai_")):
        fails.append("a model draft is not marked as a partial imitation")

    for draft in librarian.drafts():
        librarian.approve(draft["id"], "purple.lead")
    approved = librarian.approved_actions()
    ants2 = Ants(work=Path(tempfile.mkdtemp(prefix="oaev-ants-")), extra_actions=approved)
    emit("Librarian", f"{len(approved)} action(s) approved by purple.lead and added to the allow-list",
         data=[{"technique": a["techniques"][0], "status": "approved", "command": a["command"],
                "draft_id": i, "name": a["description"]} for i, a in approved.items()])
    r2 = ants2.run(lambda: build(ants2.planner, ants2.builder), [HOST1],
                   label="after: the same scenario with the approved actions", scenario=box)
    cover = {}
    for c in box["draft"]["coverage"]:
        cover[c["status"]] = cover.get(c["status"], 0) + 1
    if cover != {"simulated": 2, "partial": 2, "not simulated": 1, "no action": 3}:
        fails.append(f"coverage after approval {cover}")
    if len(r2["steps"]) != 4 or r2["not_run"] or not r2["audit_intact"]:
        fails.append(f"{len(r2['steps'])} step(s) scored after approval, {len(r2['not_run'])} not run")
    return fails, ("4 gaps the public library could not fill: the model was called 7 times; 2 drafts passed the "
                   "rules (one after a refused first answer), 1 never gave a harmless answer, 1 declined; "
                   "the refused family and covered techniques were never sent to it; after approval 4 tests run")


def survey(path):
    """How far a public test library file would close the gaps of the action library."""
    planner = Planner()
    result = Librarian(path, planner.actions, planner.not_simulated,
                       Path(tempfile.mkdtemp(prefix="oaev-survey-"))).survey()
    print(f"{result['techniques']} techniques with {result['tests']} public tests in {path}")
    for label, n in result["tally"].items():
        print(f"  {n:5d}  {label}")
    print("harmless test found, by attack type:")
    for tactic, n in sorted(result["found_by_tactic"].items(), key=lambda kv: -kv[1]):
        print(f"  {n:5d}  {tactic}")
    print("most common reasons a test was refused:")
    for reason, n in result["top_reasons"]:
        print(f"  {n:5d}  {reason}")
    return 0


def s_gateways():
    """Email and firewall tests: the mail gateway's and the firewall's own logs, in Splunk, say what happened."""
    ants, fails = Ants(), []
    tests = ["T-MAIL-005", "T-WEB-006", "T-NET-004"]
    ants.defences["T-NET-004"] = {"checkpoint": "drop"}     # a plain connection, dropped
    r1 = ants.run(tests, [HOST1], label="the mail gateway quarantines, the firewall drops")
    want(fails, r1, "T-MAIL-005", PREVENTED)
    want(fails, r1, "T-WEB-006", PREVENTED)
    want(fails, r1, "T-NET-004", PREVENTED, finding="weak match")     # no marker: addresses only
    where = {}
    for step in r1["steps"]:
        splunk = next((o for o in step["observations"] if o["source"] == "splunk"), {})
        where[step["test_id"]] = ((splunk.get("evidence") or {}).get("index"), splunk.get("field"))
    if where.get("T-MAIL-005") != (MAIL_INDEX, "msg.header.subject"):
        fails.append(f"the email was tied through {where.get('T-MAIL-005')}")
    if where.get("T-WEB-006") != (FIREWALL_INDEX, "resource"):
        fails.append(f"the web request was tied through {where.get('T-WEB-006')}")
    if r1["splunk_searches"]["wide"] != 1:
        fails.append(f"Splunk searches {r1['splunk_searches']}, expected one for the three indexes")
    teams = {t["team"]: t["steps"] for t in r1["teams"]}
    if teams != {"Purple team": 3, "SecOps": 1, "NetOps": 2}:
        fails.append(f"team views {teams}")

    ants.defences.update({"T-MAIL-005": {"proofpoint": "deliver"}, "T-WEB-006": {"checkpoint": "accept"},
                          "T-NET-004": {"checkpoint": "accept"}})
    r2 = ants.run(tests, [HOST1], label="both let the test through")
    for test in tests:
        want(fails, r2, test, MISSED)
    reasons = {s["test_id"]: s["reason"] for s in r2["steps"]}
    if set(reasons.values()) != {"seen_not_flagged"}:
        fails.append(f"miss reasons {reasons}, expected 'seen_not_flagged' for all three")
    if len(r2["regressions"]) != 3:
        fails.append(f"{len(r2['regressions'])} regression(s) reported, expected 3")
    notes = r2["detection_proposals"].get("no_proposal", [])
    if len(notes) != 3 or r2["detection_proposals"].get("proposals"):
        fails.append(f"detection engineer: {r2['detection_proposals']}")

    stranger = dict(HOST1, mailbox="someone.real@example.com")
    r3 = ants.run(["T-MAIL-005"], [stranger], label="an email to a mailbox that is not on the scope list")
    want_not_run(fails, r3, "out_of_scope", 1)
    if r3["steps"]:
        fails.append("an email step outside the scope list was scored")
    try:
        ants.planner.plan(["T-MAIL-005"], [{k: v for k, v in HOST1.items() if k != "mailbox"}])
        fails.append("an email test was planned for a host with no test mailbox")
    except ValueError:
        pass
    return fails, ("quarantined email and dropped requests read from Splunk as Prevented (the plain "
                   "connection flagged as weak); when both let the test through: 3 Missed and 3 "
                   "regressions; an email to a mailbox off the scope list is refused")


SCENARIOS = {
    "reversible": ("Change-and-undo tests: persistence, hiding, execution", s_reversible),
    "librarian": ("Librarian: a missing technique gets a harmless public test", s_librarian),
    "librarian_rules": ("Librarian: what its rules allow and refuse", s_librarian_rules),
    "drafter": ("Drafter: a model drafts a test when no public test fits", s_drafter),
    "gateways": ("Email and firewall tests (Proofpoint and Check Point logs in Splunk)", s_gateways),
    "detection_loop": ("From Missed to Detected: proposal, approval, re-run", s_detection_loop),
    "detection_guards": ("Detection engineer: what it refuses", s_detection_guards),
    "playground": ("Playground: blind run with decoys", s_playground),
    "threat_scenario": ("Scenario from OpenCTI, built and run", s_threat_scenario),
    "scenario_guards": ("Scenario builder: what it refuses", s_scenario_guards),
    "full_run": ("All ants, one run", s_full_run),
    "repeat_run": ("Repeat run uses the memory", s_repeat_run),
    "search_changes": ("Analyst: search changes and why", s_search_changes),
    "gate_out_of_scope": ("Gatekeeper: host not in scope", s_gate_out_of_scope),
    "gate_hardening": ("Gatekeeper: bypass attempts", s_gate_hardening),
    "matcher_hardening": ("Matcher: no borrowed alerts, no false regressions", s_matcher_hardening),
    "gate_tampered": ("Gatekeeper: step changed after signing", s_gate_tampered),
    "gate_kill_switch": ("Gatekeeper: kill switch", s_gate_kill_switch),
    "gate_outside_window": ("Gatekeeper: outside the time window", s_gate_outside_window),
    "gate_replay_and_limit": ("Gatekeeper: replay, unsigned step, step limit", s_gate_replay_and_limit),
    "audit_tamper": ("Gatekeeper: audit log tampering", s_audit_tamper),
    "falcon_down": ("Falcon observer: API error", s_falcon_down),
    "falcon_auth": ("Falcon observer: sign-in rejected", s_falcon_auth),
    "falcon_unreachable": ("Falcon observer: connection drops", s_falcon_unreachable),
    "pipeline_gap": ("Matcher: in Falcon, not in Splunk", s_pipeline_gap),
    "prevention_gap": ("Matcher: detected but not blocked", s_prevention_gap),
    "learned_rule": ("Matcher: learned rule and quiet window", s_learned_rule),
    "drift": ("Reporter: regression between runs", s_drift),
}


def run_all():
    print(f"{'scenario':<24} {'result':<6} detail")
    print("-" * 110)
    failed = []
    for name in SCENARIOS:
        proc = subprocess.run([sys.executable, __file__, name],
                              capture_output=True, text=True, timeout=240)
        line = next((ln for ln in proc.stdout.splitlines() if ln.startswith("SANDBOX ")), "")
        ok = proc.returncode == 0 and line.startswith("SANDBOX PASS")
        detail = line.split(" ", 2)[2] if line.count(" ") >= 2 else proc.stderr.strip()[-400:]
        print(f"{name:<24} {'PASS' if ok else 'FAIL':<6} {detail}")
        if not ok:
            failed.append(name)
    print("-" * 110)
    print(f"{len(SCENARIOS) - len(failed)}/{len(SCENARIOS)} scenarios passed")
    return 1 if failed else 0


def main():
    if SCENARIO == "all":
        sys.exit(run_all())
    if SCENARIO == "catalogue":
        print(json.dumps([{"id": k, "title": v[0], "blurb": (v[1].__doc__ or "").strip()}
                          for k, v in SCENARIOS.items()]))
        sys.exit(0)
    if SCENARIO == "library":
        print(json.dumps(attack_library()))
        sys.exit(0)
    if SCENARIO == "survey":
        sys.exit(survey(sys.argv[2] if len(sys.argv) > 2 else str(SAMPLE_ATOMICS)))
    if SCENARIO == "playground_many":
        logging.basicConfig(level=logging.CRITICAL)
        start(SplunkMock, SPLUNK_PORT), start(FalconMock, FALCON_PORT)
        count = int(sys.argv[2]) if len(sys.argv) > 2 else 50
        global emit
        emit = lambda *a, **k: None                      # quiet: only the tally matters
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            tally, wrong = playground_many(count, int(sys.argv[3]) if len(sys.argv) > 3 else 1)
        print(f"{count} blind runs, {sum(tally.values())} steps")
        for call, n in sorted(tally.items(), key=lambda kv: -kv[1]):
            print(f"  {n:5d}  {call}")
        print("\n".join(wrong) if wrong else "no wrong calls")
        sys.exit(1 if wrong else 0)
    if SCENARIO not in SCENARIOS and SCENARIO != "custom":
        print(f"unknown scenario {SCENARIO!r}; choose one of: all, {', '.join(SCENARIOS)}")
        sys.exit(2)
    title, runner = (("Attack types picked in the library", s_custom) if SCENARIO == "custom"
                     else SCENARIOS[SCENARIO])
    logging.basicConfig(level=logging.CRITICAL)
    splunk, falcon = start(SplunkMock, SPLUNK_PORT), start(FalconMock, FALCON_PORT)
    start(OpenCTIMock, OPENCTI_PORT)
    print("=" * 78 + f"\n SCENARIO: {SCENARIO} - {title}\n" + "=" * 78)
    fails, note = runner()
    print("=" * 78)
    print(("SANDBOX FAIL " + note + " :: " + "; ".join(fails)) if fails else "SANDBOX PASS " + note)
    event("harness", ok=not fails, note=note, fails=fails)
    path = os.environ.get("HARNESS_EVENTS_FILE")
    if path:
        Path(path).write_text(json.dumps(EVENTS, default=str), encoding="utf-8")
    splunk.shutdown()
    falcon.shutdown()
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
