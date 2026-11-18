"""
Lab check: the real collector code and the ants against a real Splunk Enterprise.

Everything the sandbox proves, it proves against a mock Splunk that I wrote.
This script repeats the important parts against a real Splunk Enterprise
running in a container on this machine, to find where the mock was wrong.

  splunk-es/.venv/Scripts/python validation-ants/lab_splunk.py          # all checks
  splunk-es/.venv/Scripts/python validation-ants/lab_splunk.py wire     # one group

Groups: wire (sign-in, index check, failed search), markers (where a step
marker can sit and still be found), run (all ants, first run and repeat run),
detections (the detection engineer's proposed searches), reader (the same
through a read-only account that may search four indexes and nothing else),
gateways (email and firewall tests: synthetic mail gateway and firewall logs
in their own indexes, read with the read-only account).

Rules this script keeps:

* It talks to 127.0.0.1 only. Any other address is refused before anything is
  sent, so it cannot be pointed at a real Splunk by mistake.
* Every event it sends is synthetic, made here. No real log is read or sent.
* The password and the event-collector token are read from a file outside the
  repository (OAEV_LAB_ENV, default ~/.oaev-lab/splunk-lab.env) and are never
  printed.
* Falcon stays a mock. Only Splunk is real.
"""

import json
import logging
import os
import sys
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests  # type: ignore[import-untyped]
import urllib3

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
GROUP = sys.argv[1] if len(sys.argv) > 1 else "all"
sys.argv = [sys.argv[0], "lab"]          # sandbox.py reads its scenario from argv

MANAGEMENT = "https://127.0.0.1:8089"
COLLECTOR = "https://127.0.0.1:18088"    # the container's event collector (8088 is taken on this PC)
USER = "admin"
ENV_FILE = Path(os.environ.get("OAEV_LAB_ENV") or Path.home() / ".oaev-lab" / "splunk-lab.env")
FMT = "%Y-%m-%dT%H:%M:%S"
FINDINGS = []      # (group, check, "same" | "differs" | "limit", detail)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)   # the lab uses its own certificate


def note(group, check, verdict, detail):
    FINDINGS.append((group, check, verdict, detail))
    print(f"   [{verdict:<7}] {check}: {detail}")


def read_secrets():
    values = {}
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


class Lab:
    """The lab Splunk: its management port and its event collector. Local only."""

    def __init__(self):
        for url in (MANAGEMENT, COLLECTOR):
            if not url.startswith("https://127.0.0.1:"):
                raise SystemExit(f"refusing {url}: the lab check only talks to 127.0.0.1")
        secrets = read_secrets()
        self.password = secrets["SPLUNK_PASSWORD"]
        self.hec_token = secrets["SPLUNK_HEC_TOKEN"]
        self.session = requests.Session()
        self.session.auth = (USER, self.password)
        self.session.verify = False
        self.sent = 0

    def get(self, path, **params):
        return self.session.get(MANAGEMENT + path, params={"output_mode": "json", **params}, timeout=30)

    def post(self, path, **data):
        return self.session.post(MANAGEMENT + path, data={"output_mode": "json", **data}, timeout=60)

    def version(self):
        return self.get("/services/server/info").json()["entry"][0]["content"]["version"]

    def ensure_index(self, name):
        if self.get(f"/services/data/indexes/{name}").status_code == 404:
            self.post("/services/data/indexes", name=name).raise_for_status()

    def search(self, spl):
        """A plain admin search, for the lab's own plumbing (not the collector's path)."""
        r = self.post("/services/search/jobs", search="search " + spl, exec_mode="oneshot", count="0")
        r.raise_for_status()
        return r.json().get("results", [])

    def send(self, rows):
        """Send synthetic rows through the event collector, each with its own time."""
        if not rows:
            return
        body = ""
        for row in rows:
            fields = {}
            for key, value in row.items():
                if key in ("_time", "index", "sourcetype", "source"):
                    continue
                target = fields
                *parents, leaf = key.split(".")       # "event.CompositeId" is a nested key in real data
                for parent in parents:
                    target = target.setdefault(parent, {})
                target[leaf] = value
            when = datetime.strptime(row["_time"], FMT).replace(tzinfo=timezone.utc).timestamp()
            body += json.dumps({
                "time": when, "index": row["index"], "sourcetype": row["sourcetype"],
                "source": row.get("source") or "oaev-lab-synthetic",
                "host": str(row.get("dest_host") or "oaev-lab").split(".")[0],
                "event": fields})
        r = requests.post(COLLECTOR + "/services/collector/event", data=body.encode("utf-8"), verify=False,
                          headers={"Authorization": "Splunk " + self.hec_token}, timeout=30)
        if r.status_code != 200:
            raise SystemExit(f"the lab event collector refused the synthetic events: HTTP {r.status_code} {r.text[:200]}")
        self.sent += len(rows)

    def settle(self):
        """Wait until what was sent can be searched: send one last marked event and look for it."""
        token = "oaevlabsettle" + uuid.uuid4().hex
        self.send([{"_time": datetime.now(timezone.utc).strftime(FMT), "index": "main",
                    "sourcetype": "oaev:lab:settle", "note": token}])
        deadline = time.time() + 90
        while time.time() < deadline:
            if self.search(f'index=main sourcetype="oaev:lab:settle" "{token}" earliest=-15m | head 1'):
                time.sleep(1.0)
                return
            time.sleep(1.0)
        raise SystemExit("the lab Splunk did not make the synthetic events searchable within 90 s")


LAB = Lab()
import sandbox  # noqa: E402  (the sandbox's ants, wired to the lab below)
from ants.intel import Technique, Threat  # noqa: E402
from ants.models import COULD_NOT_CHECK, DETECTED, MISSED, PREVENTED, Step  # noqa: E402

SPLUNK_ENV = {"SPLUNKES_BASE_URL": MANAGEMENT, "SPLUNKES_USERNAME": USER,
              "SPLUNKES_PASSWORD": LAB.password, "SPLUNKES_VERIFY_SSL": "false"}


def lab_ants(**overrides):
    """The sandbox's ants, with both Splunk readers pointed at the lab Splunk.

    The simulated agent still writes its synthetic rows to the sandbox's list;
    before the Splunk observer looks, the new rows are sent to the lab Splunk.
    """
    # Its own working folder: each set of ants has its own gatekeeper key and audit log.
    ants = sandbox.Ants(work=Path(tempfile.mkdtemp(prefix="oaev-lab-")),
                        splunk_env={**SPLUNK_ENV, **overrides})
    state = {"forwarded": 0}
    has_baseline = int((LAB.search('index=telemetry source="baseline" earliest=-24h | stats count')
                        or [{"count": 0}])[0]["count"]) >= 60

    def forward():
        rows = sandbox.TELEMETRY.splunk_rows[state["forwarded"]:]
        state["forwarded"] = len(sandbox.TELEMETRY.splunk_rows)
        LAB.send([r for r in rows if not (has_baseline and r.get("source") == "baseline")])
        LAB.settle()

    observe = ants.splunk.observe

    def observe_after_forwarding(steps, agentless):
        forward()
        return observe(steps, agentless)

    ants.splunk.observe = observe_after_forwarding
    ants.forward = forward
    return ants


# ----------------------------------------------------------------------------
# wire: what the collector assumes about Splunk's own answers
# ----------------------------------------------------------------------------
def check_wire():
    ants = lab_ants()            # loading the Splunk reader puts the collector on the import path
    from src.services.exception import (SplunkESAPIError, SplunkESAuthenticationError,
                                        SplunkESIndexNotFoundError, SplunkESQueryError)

    client = ants.splunk.service.client_api
    try:
        client.ensure_index_available()
        note("wire", "index check, index exists", "same", "GET /services/data/indexes/main answered 200")
    except Exception as e:
        note("wire", "index check, index exists", "differs", f"{type(e).__name__}: {e}")

    missing = lab_ants(SPLUNKES_ALERTS_INDEX="oaev_no_such_index").splunk.service.client_api
    try:
        missing.ensure_index_available()
        note("wire", "index check, index missing", "differs", "a missing index was not reported")
    except SplunkESIndexNotFoundError:
        note("wire", "index check, index missing", "same", "404, read as 'data source missing'")
    except Exception as e:
        note("wire", "index check, index missing", "differs", f"{type(e).__name__}: {e}")
    now = int(time.time())
    try:
        rows = client.run_search(f"index=oaev_no_such_index sourcetype=* earliest={now - 600} latest={now} "
                                 f"| table _time | head 5")
        note("wire", "search of a missing index", "same",
             f"{len(rows)} rows and no error, so the index check is what stops a false Missed")
    except Exception as e:
        note("wire", "search of a missing index", "differs", f"{type(e).__name__}: {e}")

    wrong = lab_ants(SPLUNKES_PASSWORD="not-the-password-" + uuid.uuid4().hex[:8]).splunk.service.client_api
    try:
        wrong.run_search(f"index=main sourcetype=* earliest={now - 600} latest={now} | table _time | head 1")
        note("wire", "wrong password", "differs", "the search was accepted")
    except SplunkESAuthenticationError:
        note("wire", "wrong password", "same", "401, read as 'sign-in rejected'")
    except Exception as e:
        note("wire", "wrong password", "differs", f"{type(e).__name__}: {e}")

    try:
        client.run_search(f"index=main sourcetype=* earliest={now - 600} latest={now} | where like(")
        note("wire", "search Splunk cannot parse", "differs", "it came back as an empty result")
    except (SplunkESAPIError, SplunkESQueryError) as e:
        note("wire", "search Splunk cannot parse", "same", f"reported as a failed search ({type(e).__name__})")
    except Exception as e:
        note("wire", "search Splunk cannot parse", "differs", f"{type(e).__name__}: {e}")
    lab_ants()          # put the right password back in the environment for the next group


# ----------------------------------------------------------------------------
# markers: where a step marker can sit in a real event and still be found
# ----------------------------------------------------------------------------
PLACEMENTS = [
    ("in a command line", lambda m: {"process": f"cmd.exe /c echo oaev-step-{m}"}, True),
    ("in the parent process name", lambda m: {"process": "cmd.exe /c echo hello",
                                               "parent_process_name": f"oaev-implant-{m}-agent-22222222-2222-2222-2222-222222222222"}, True),
    ("in a file name", lambda m: {"file_name": f"oaev-step-{m}.txt", "file_path": f"C:\\Users\\Public\\oaev-step-{m}.txt"}, True),
    ("in a looked-up hostname", lambda m: {"query": f"oaev-step-{m}.sim.invalid"}, True),
    ("without hyphens, after an underscore", lambda m: {"process": f"runner.exe payload_{m.replace('-', '')}.bin"}, True),
    ("without hyphens, glued inside a longer word", lambda m: {"process": f"runner.exe x{m.replace('-', '')}y"}, False),
    ("in upper case", lambda m: {"process": f"CMD.EXE /C ECHO OAEV-STEP-{m.upper()}"}, True),
]


def check_markers():
    ants = lab_ants()
    start = datetime.now(timezone.utc) - timedelta(minutes=4)
    steps, rows = [], []
    for label, make, _ in PLACEMENTS:
        marker = str(uuid.uuid4())
        steps.append(Step(id=marker, run_id="lab-markers", test_id="LAB-" + label[:24], title=label,
                          technique="T1059.003", action="echo_marker", command=f"echo oaev-step-{marker}",
                          host="WS-TEST-01", source_ip="10.0.0.5", target_ip="10.0.0.9",
                          expect={"splunk": "detection"}, start=start, end=start + timedelta(minutes=3)))
        rows.append({"_time": (start + timedelta(seconds=30)).strftime(FMT), "index": "main",
                     "sourcetype": "oaev:lab:alert", "dest_host": "ws-test-01.lab.local",
                     "rule_name": "Lab synthetic alert", **make(marker)})
    sandbox.TELEMETRY.splunk_rows.extend(rows)
    seen = {o.step_id: o for o in ants.splunk.observe(steps, set())}
    for step, (label, _, expected) in zip(steps, PLACEMENTS):
        o = seen[step.id]
        found = o.outcome == DETECTED
        if found == expected:
            note("markers", label, "same" if expected else "limit",
                 (f"found, matched in field '{o.field}'" if found
                  else "not found: Splunk searches whole words, and the marker is not a word of its own here"))
        else:
            note("markers", label, "differs",
                 f"expected {'a match' if expected else 'no match'}, got {o.outcome} ({o.reason})")
    return ants


# ----------------------------------------------------------------------------
# run: every ant, first run and repeat run, Splunk real and Falcon mock
# ----------------------------------------------------------------------------
def outcomes(report):
    return {s["test_id"]: s for s in report["steps"]}


def check_run():
    ants = lab_ants()
    expected = {"T-EXEC-001": DETECTED, "T-FILE-002": PREVENTED, "T-DNS-003": DETECTED, "T-NET-004": MISSED}
    for label in ("first run", "repeat run"):
        report = ants.run(sandbox.ALL_TESTS, [sandbox.HOST1], label=f"lab Splunk, {label}")
        got = outcomes(report)
        wrong = {t: got[t]["outcome"] for t in expected if got[t]["outcome"] != expected[t]}
        searches = report["splunk_searches"]
        note("run", f"{label}: outcomes", "differs" if wrong else "same",
             f"wrong: {wrong}" if wrong else "Detected, Prevented, Detected, Missed, as on the mock")
        # Repeat run: one narrow search for the three remembered tests, one wide for the one never found.
        want_searches = {"wide": 1, "narrow": 0} if label == "first run" else {"wide": 1, "narrow": 1}
        ok = all(searches[k] == v for k, v in want_searches.items())
        note("run", f"{label}: Splunk searches", "same" if ok else "differs",
             f"{searches['narrow']} narrow + {searches['wide']} wide"
             + ("" if ok else f", the mock gave {want_searches['narrow']} narrow + {want_searches['wide']} wide"))
        if label == "first run":
            step = got["T-EXEC-001"]
            splunk = next((o for o in step["observations"] if o["source"] == "splunk"), {})
            evidence = splunk.get("evidence") or {}
            note("run", "Falcon alert copy in Splunk counted once",
                 "same" if step["sightings"] == 1 and evidence.get("falcon_alert_id") else "differs",
                 f"sightings {step['sightings']}; Falcon alert id read from Splunk: "
                 f"{'yes' if evidence.get('falcon_alert_id') else 'no'}; "
                 f"index {evidence.get('index')}, sourcetype {evidence.get('sourcetype')}, time {evidence.get('time')}")
            note("run", "audit log", "same" if report["audit_intact"] else "differs",
                 "chain verifies" if report["audit_intact"] else "chain broken")
    return ants


# ----------------------------------------------------------------------------
# detections: the detection engineer's proposals, on logs read from the lab
# ----------------------------------------------------------------------------
def check_detections():
    ants = lab_ants()
    picked = [("T1082", "System Information Discovery"), ("T1016", "System Network Configuration Discovery"),
              ("T1057", "Process Discovery"), ("T1087.001", "Account Discovery: Local Account"),
              ("T1018", "Remote System Discovery")]
    box = {}

    def build():
        threat = Threat(id="lab-selection", name="Lab discovery sweep", kind="selection",
                        description="Discovery steps the sandbox's mock defences mostly miss",
                        techniques=[Technique(id=t, name=n, tactic="discovery") for t, n in picked])
        draft = ants.builder.draft(threat)
        box["scenario"] = ants.builder.approve(draft["id"], "lab.operator")
        return ants.planner.use_scenario(box["scenario"])

    report = ants.run(build, [sandbox.HOST1], label="lab Splunk, discovery sweep", scenario=box)
    proposals = report["detection_proposals"]
    if not report["steps"] or not proposals:
        note("detections", "discovery sweep ran", "differs", f"no step was scored; not run: {report['not_run']}")
        return ants
    if proposals.get("error"):
        note("detections", "endpoint logs read from the lab", "differs", proposals["error"])
        return ants
    note("detections", "endpoint logs read from the lab", "same" if proposals["events_checked"] else "differs",
         f"{proposals['events_checked']} log entries read through the checked search")
    ready = [p for p in proposals["proposals"] if p["status"] == "ready for review"]
    note("detections", "a proposal is ready for review", "same" if ready else "differs",
         ", ".join(f"{p['title']} (catches {p['caught']} of {p['of']}, noise {p['noise']})" for p in proposals["proposals"])
         or "no proposal")
    client = ants.raw.service.client_api
    for p in proposals["proposals"]:
        try:
            rows = client.run_search(p["spl"])
        except Exception as e:
            note("detections", f"starting-point search runs: {p['title']}", "differs", f"{type(e).__name__}: {e}")
            continue
        hosts = sorted({str(r.raw.get("dest_host", "")).split(".")[0] for r in rows})
        hit = "ws-test-01" in hosts
        note("detections", f"starting-point search runs: {p['title']}",
             "same" if hit == bool(p["caught"]) else "differs",
             f"Splunk accepted it and returned {len(rows)} row(s), hosts {hosts or 'none'}; "
             f"the ant's own test said it catches {p['caught']} of {p['of']}")
    return ants


# ----------------------------------------------------------------------------
# reader: a least-privilege account, as a real deployment would use
# ----------------------------------------------------------------------------
READER, READER_ROLE, PRIVATE_INDEX = "svc_oaev_reader", "oaev_reader", "oaev_private"
LAB_INDEXES = ("telemetry", sandbox.MAIL_INDEX, sandbox.FIREWALL_INDEX)       # besides 'main'
READER_INDEXES = ("main", *LAB_INDEXES)


def ensure_reader():
    """A role that can only search the four lab indexes, and a user with only that role."""
    import secrets as _secrets
    values = read_secrets()
    if "SPLUNK_READER_PASSWORD" not in values:
        with open(ENV_FILE, "a", encoding="utf-8", newline=chr(10)) as out:
            out.write("SPLUNK_READER_PASSWORD=" + _secrets.token_urlsafe(24) + chr(10))
        values = read_secrets()
    password = values["SPLUNK_READER_PASSWORD"]
    LAB.ensure_index(PRIVATE_INDEX)
    allowed = [("srchIndexesAllowed", name) for name in READER_INDEXES]
    exists = LAB.get(f"/services/authorization/roles/{READER_ROLE}").status_code != 404
    r = LAB.session.post(
        MANAGEMENT + "/services/authorization/roles" + (f"/{READER_ROLE}" if exists else ""), timeout=30,
        data=[("output_mode", "json"), ("capabilities", "search"), ("srchIndexesDefault", "main"), *allowed]
        + ([] if exists else [("name", READER_ROLE)]))
    r.raise_for_status()
    if LAB.get(f"/services/authentication/users/{READER}").status_code == 404:
        LAB.post("/services/authentication/users", name=READER, password=password, roles=READER_ROLE).raise_for_status()
    else:
        LAB.post(f"/services/authentication/users/{READER}", password=password, roles=READER_ROLE).raise_for_status()
    return {"SPLUNKES_USERNAME": READER, "SPLUNKES_PASSWORD": password}


def check_reader():
    account = ensure_reader()
    ants = lab_ants(**account)
    from src.services.exception import SplunkESIndexNotFoundError
    client = ants.splunk.service.client_api
    try:
        client.ensure_index_available()
        note("reader", "index check, allowed index", "same", "the read-only account can confirm that 'main' exists")
    except Exception as e:
        note("reader", "index check, allowed index", "differs", f"{type(e).__name__}: {e}")
    try:
        lab_ants(**account, SPLUNKES_ALERTS_INDEX="oaev_no_such_index").splunk.service.client_api.ensure_index_available()
        note("reader", "index check, missing index", "differs", "a missing index was not reported")
    except SplunkESIndexNotFoundError:
        note("reader", "index check, missing index", "same", "reported as 'data source missing'")
    except Exception as e:
        note("reader", "index check, missing index", "differs", f"{type(e).__name__}: {e}")

    # An index that exists but that this account may not search.
    marker = str(uuid.uuid4())
    when = datetime.now(timezone.utc) - timedelta(minutes=2)
    LAB.send([{"_time": when.strftime(FMT), "index": PRIVATE_INDEX, "sourcetype": "oaev:lab:alert",
               "dest_host": "ws-test-01.lab.local", "process": f"cmd.exe /c echo oaev-step-{marker}"}])
    LAB.settle()
    private = lab_ants(**account, SPLUNKES_ALERTS_INDEX=PRIVATE_INDEX).splunk.service.client_api
    window = f"earliest={int(when.timestamp()) - 300} latest={int(when.timestamp()) + 300}"
    spl = f'index={PRIVATE_INDEX} sourcetype=* "{marker}" {window} | table _time, index | head 5'
    admin_rows = len(LAB.search(spl))
    try:
        private.ensure_index_available()
        checked = "passed"
    except SplunkESIndexNotFoundError:
        checked = "refused"
    except Exception as e:
        checked = f"{type(e).__name__}"
    try:
        reader_rows = len(private.run_search(spl))
    except Exception as e:
        reader_rows = f"{type(e).__name__}"
    safe = checked == "refused" or reader_rows not in (0,)
    note("reader", "index it may not search", "same" if safe else "differs",
         f"the event is there (admin sees {admin_rows}); the read-only account's index check {checked}, "
         f"its search returned {reader_rows} row(s)"
         + ("" if safe else ": an index the account cannot read looks like an empty one, which would be scored Missed"))

    r = requests.post(MANAGEMENT + "/services/data/indexes", auth=(READER, account["SPLUNKES_PASSWORD"]), verify=False,
                      data={"name": "oaev_should_not_exist", "output_mode": "json"}, timeout=30)
    note("reader", "cannot change Splunk", "same" if r.status_code in (401, 403) else "differs",
         f"creating an index with the read-only account answered HTTP {r.status_code}")
    if r.status_code in (200, 201):
        LAB.session.delete(MANAGEMENT + "/services/data/indexes/oaev_should_not_exist", timeout=30)

    ants = lab_ants(**account)
    report = ants.run(sandbox.ALL_TESTS, [sandbox.HOST1], label="lab Splunk, read-only account")
    got = {t: s["outcome"] for t, s in outcomes(report).items()}
    expected = {"T-EXEC-001": DETECTED, "T-FILE-002": PREVENTED, "T-DNS-003": DETECTED, "T-NET-004": MISSED}
    note("reader", "full run with the read-only account", "same" if got == expected else "differs",
         "Detected, Prevented, Detected, Missed" if got == expected else f"got {got}")
    lab_ants()          # back to the admin account for anything that follows


# ----------------------------------------------------------------------------
# gateways: email and firewall tests, read from mail gateway and firewall logs
# ----------------------------------------------------------------------------
def check_gateways():
    account = ensure_reader()
    ants = lab_ants(**account)
    tests = ["T-MAIL-005", "T-WEB-006", "T-NET-004"]
    # Source addresses used by this group only. A plain connection has no marker and is
    # matched on its addresses, so a firewall log left by another group on the same
    # address pair would be read as this step's. (That happened on the first lab run.)
    first, second = dict(sandbox.HOST1, source_ip="10.0.0.15"), dict(sandbox.HOST2, source_ip="10.0.0.16")

    ants.defences["T-NET-004"] = {"checkpoint": "drop"}
    report = ants.run(tests, [first], label="lab Splunk: the mail gateway quarantines, the firewall drops")
    got = outcomes(report)
    wrong = {t: got[t]["outcome"] for t in tests if got[t]["outcome"] != PREVENTED}
    note("gateways", "blocked email and requests read as Prevented", "differs" if wrong else "same",
         f"wrong: {wrong}" if wrong else "all three Prevented, from logs in the email and firewall indexes")
    for test, index, field in (("T-MAIL-005", sandbox.MAIL_INDEX, "msg.header.subject"),
                               ("T-WEB-006", sandbox.FIREWALL_INDEX, "resource")):
        splunk = next((o for o in got[test]["observations"] if o["source"] == "splunk"), {})
        evidence = splunk.get("evidence") or {}
        ok = (evidence.get("index"), splunk.get("field")) == (index, field)
        note("gateways", f"{test} tied through its marker", "same" if ok else "differs",
             f"index {evidence.get('index')}, sourcetype {evidence.get('sourcetype')}, field {splunk.get('field')}, "
             f"log says {evidence.get('verdict')}")
    weak = any("weak match" in f for f in got["T-NET-004"]["findings"])
    note("gateways", "plain dropped connection flagged as weak", "same" if weak else "differs",
         "matched on addresses only, so a person is asked to confirm it" if weak else f"findings: {got['T-NET-004']['findings']}")
    searches = report["splunk_searches"]
    note("gateways", "one search over three indexes", "same" if (searches["wide"], searches["narrow"]) == (1, 0) else "differs",
         f"{searches['narrow']} narrow + {searches['wide']} wide")

    # Let through, on the second host, for the same reason.
    ants.defences.update({"T-MAIL-005": {"proofpoint": "deliver"}, "T-WEB-006": {"checkpoint": "accept"},
                          "T-NET-004": {"checkpoint": "accept"}})
    report = ants.run(tests, [second], label="lab Splunk: both let the test through")
    got = outcomes(report)
    wrong = {t: (got[t]["outcome"], got[t]["reason"]) for t in tests
             if (got[t]["outcome"], got[t]["reason"]) != (MISSED, "seen_not_flagged")}
    note("gateways", "delivered email and accepted requests read as Missed", "differs" if wrong else "same",
         f"wrong: {wrong}" if wrong else "all three Missed: in the logs, let through, nothing raised")
    lab_ants()


def main():
    logging.basicConfig(level=logging.CRITICAL)
    print(f" LAB SPLUNK {LAB.version()} at {MANAGEMENT} (this machine only); Falcon is a mock")
    if sandbox.client_notice():
        print(" " + sandbox.client_notice())
    for name in LAB_INDEXES:
        LAB.ensure_index(name)
    sandbox.start(sandbox.FalconMock, sandbox.FALCON_PORT)
    groups = {"wire": check_wire, "markers": check_markers, "run": check_run, "detections": check_detections,
              "reader": check_reader, "gateways": check_gateways}
    for name, fn in groups.items():
        if GROUP in ("all", name):
            print("=" * 78 + f"\n {name}\n" + "=" * 78)
            fn()
    print("=" * 78)
    tally = {}
    for _, _, verdict, _ in FINDINGS:
        tally[verdict] = tally.get(verdict, 0) + 1
    print(f" {len(FINDINGS)} checks: {tally.get('same', 0)} as on the mock, {tally.get('differs', 0)} different, "
          f"{tally.get('limit', 0)} known limit(s) confirmed; {LAB.sent} synthetic events sent")
    out = os.environ.get("OAEV_LAB_REPORT")
    if out:
        Path(out).write_text(json.dumps([dict(zip(("group", "check", "verdict", "detail"), f)) for f in FINDINGS],
                                        indent=2), encoding="utf-8")
    sys.exit(1 if tally.get("differs") else 0)


if __name__ == "__main__":
    main()
