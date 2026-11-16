# Validation ants

The roles that sit around the collectors to run a detection-validation exercise end to end:
plan benign steps, gate them, run them, read each security tool, tie alerts to steps, and report.

Everything here runs **on mocks only**. The endpoint agent is simulated and executes nothing; Splunk and CrowdStrike
Falcon are mock servers. It is for authorised testing of systems the organisation owns.

```
intel -> scenario builder -> planner -> gatekeeper -> agent
      -> Splunk observer + Falcon observer -> analyst -> matcher -> detection engineer -> reporter
```

| Ant | File | What it does |
|---|---|---|
| Intel | `ants/intel.py` | Reads a threat scenario from OpenCTI as a STIX bundle and lists its ATT&CK techniques in tactic order. Read-only. |
| Scenario builder | `ants/scenario_builder.py` | Maps each technique to an action on the allow-list and writes a draft scenario with a coverage table. A person approves it before it can be planned. |
| Planner | `ants/planner.py`, `ants/catalogue.json` | Turns catalogue tests into steps. Each step gets a new marker (a UUID) and a command taken from the action allow-list. It cannot invent an action. |
| Gatekeeper | `ants/gatekeeper.py` | Decides whether a step may run, and keeps the audit log. See below. |
| Agent | `ants/agent_sim.py` | Sandbox stand-in for OpenAEV's endpoint agent. Asks the gatekeeper, then writes the synthetic telemetry the configured defences would produce. Runs no command. |
| Splunk observer | `ants/observers.py` | Adapter around the real `splunk-es` collector service: checked queries, location memory, step matching, four outcomes. |
| Falcon observer | `ants/observers.py` | Read-only reader of Falcon alerts (sign in, list ids, fetch alerts). Same three checks: time window, host, step marker. Reports `Prevented` from the alert's disposition, using the fork's `crowdstrike/pattern_disposition.py`. |
| Analyst | `ants/analyst.py` | After each run, writes one entry per step to a search-change log: how the test was searched, how it will be searched next time, and why. |
| Matcher | `ants/matcher.py` | Fuses the sources into one verdict per step, counts a forwarded Falcon alert once, applies learned rules, raises findings. |
| Detection engineer | `ants/detection_engineer.py`, `ants/detections.json` | For each missed step, tests a reviewed detection on the plain endpoint logs and writes a proposal for a person. Changes nothing in Splunk or Falcon. |
| Reporter | `ants/reporter.py` | Scorecard for the run and drift against the previous run. |

The four outcomes are the collector's: `Detected`, `Prevented`, `Missed`, `Could not check`. A step the gatekeeper
refused is `Not run`; it is listed and never scored.

## From an OpenCTI scenario to a tested scenario

1. **Intel ant** fetches a report from OpenCTI (`OpenCTIClient.report_bundle`) or takes a bundle you exported
   (`IntelAnt.from_bundle`). It reads the threat and the `attack-pattern` objects that carry a MITRE ATT&CK id.
2. **Scenario builder** looks up each technique in the action library (`ants/catalogue.json`):

   | Coverage | Meaning |
   |---|---|
   | `simulated` | A reviewed action behaves like the technique. |
   | `partial` | The real technique would change the system, so the action only runs the same tool read-only. |
   | `not simulated` | The technique cannot be done harmlessly (credential dumping, log removal, disabling a defence, destructive actions, real accounts, exploitation). |
   | `no action` | Nothing in the library covers it yet. |

   It never writes a command. Whether the ants can test a given scenario depends on how much of it the library
   covers; to cover more, add a reviewed action to the allow-list.
3. **A person approves the draft.** The approval is bound to the exact list of tests; the planner refuses a draft
   and refuses a scenario that changed after approval.
4. **The run** goes through the same planner, gatekeeper, observers, analyst, matcher and reporter as any other
   test. The report adds the coverage table and the same run scored per team: purple team (the whole chain), SecOps
   (endpoint steps), NetOps (network steps).

The library today has 13 actions covering 13 techniques. The sandbox's OpenCTI is a mock serving one synthetic,
illustrative bundle; it is not an authoritative profile of any named group. The GraphQL query used to fetch a report
has not been checked against a real OpenCTI. OpenAEV itself can also turn an OpenCTI bundle into a scenario
(`openaev-api`, STIX API); these ants do not use that path yet.

## Gatekeeper

A step runs only if all of these hold at the moment it is about to run:

1. The kill switch is off.
2. The host is on the scope list (full name, exact match) and the target address is on the allowed-targets list. The
   step id is a UUID and the addresses are plain IP addresses. The action is allowed, and the command is exactly what
   the allow-listed action produces for that step; the gatekeeper derives it itself.
3. The step carries a valid signature over its id, run, test, action, command, host, addresses, the approver and the
   approved time window. Any change after signing voids it; so does a different window.
4. Now is inside the approved window.
5. The step has not been authorised before, and the run is under its step limit. Both hold across restarts and across
   several gatekeeper processes sharing the same files.

Every decision goes to an audit log. Each entry is sealed with a keyed hash that covers the previous entry, and the
head of the log is kept in a sealed state file. An edited, removed, re-hashed or cut-off entry is detected, and while
the log does not verify, nothing is signed and nothing runs.

Limits to know: the state file sits next to the log, so someone who can delete both resets the replay memory; in real
use keep it on storage the run cannot rewrite. The signing key here is random per sandbox process; real key handling
is not part of this package.

## Analyst and the search-change log

The location memory already makes the next search go straight to where the logs were. The analyst makes that
visible and auditable. Per step it records one of:

| Change | Meaning |
|---|---|
| `learned` | First time found. Next run searches that index and sourcetype directly instead of the wide search. |
| `confirmed` | Found again in a remembered place. The narrow search stays. |
| `added` | Not in the remembered place, found somewhere else. The new place is searched as well from now on. |
| `dropped` | Found neither there nor by the wide search. The next run goes back to the wide search. |
| `none` | Never found, nothing remembered. |
| `unchecked` | Splunk could not be checked. Nothing is changed. |

Each entry names the search before, the search next time, the reason, and the evidence: index, sourcetype, the field
that carried the marker, the rule, and the delay between step and alert. The log is hash-chained (not keyed), so an
edited or removed entry is detected. The analyst follows fixed rules; no model writes or changes a query.

## Matcher

- **Marker first.** The observers tie alerts to steps by marker, host and time window.
- **Learned rules.** Only when a source reports `Missed`. If two different people have confirmed that a named rule is
  what detects this test in this source, an alert from that rule on the step's host in the step's window counts,
  unless the same rule also fired on that host in an equally long quiet window before the step. An alert that carries
  another step's marker, or that another step is already matched to, is never used. A learned-rule match is always
  flagged "needs confirmation".
- **Count once.** A Falcon alert and its forwarded copy in Splunk share the Falcon alert id and count as one
  detection.
- **Findings.** Log pipeline gap (in Falcon, not in Splunk), prevention gap (detected, not blocked), partly checked
  (one source could not be asked), weak match (a network step matched on addresses only).
- **Verdict.** `Prevented` if any source prevented it, else `Detected` if any saw it. If nothing saw it and any
  expected source could not be asked, the verdict is `Could not check`, not `Missed`.

## Reporter

Detection rate = (Detected + Prevented) / (Detected + Prevented + Missed). Unchecked and not-run steps are left out
and listed. Drift compares each (test, host) with its last scored run: Detected or Prevented before and Missed now is
a regression. A step that could not be checked, or was only partly checked, is never a regression and does not
overwrite the history.

## Run it

Use the `splunk-es` virtualenv (it has `pyoaev` and `requests`):

```shell
splunk-es/.venv/Scripts/python validation-ants/sandbox.py all        # 23 scenarios, pass/fail table
splunk-es/.venv/Scripts/python validation-ants/sandbox.py full_run   # one scenario with details
```

The scenarios cover a scenario fetched from OpenCTI and built into tests, what the builder refuses, a full run, a repeat run using the memory, the analyst's change log, every gatekeeper control
(scope, changed step, kill switch, window, replay, step limit, audit tampering, bypass attempts), Falcon failures,
the pipeline and prevention gaps, the learned rule with its quiet window, and drift. The demo page
(`splunk-es/harness/demo_server.py`) lists them under "All ants: full pipeline" and runs up to four of them side by
side, each in its own process with its own mock ports (`SANDBOX_PORT_BASE`).

The demo page also has an attack library: every action on the allow-list and every refused family, coloured by ATT&CK
tactic (`sandbox.py library` prints it; the names and tactics are the `techniques` table in `ants/catalogue.json`).
Attack types picked there run as `sandbox.py custom`, with the selection in `SANDBOX_CUSTOM`: the scenario builder
drafts the tests, the person who pressed Run is recorded as the approver, and the run goes through every ant. That
run shows a result; unlike the scenarios above it is not compared with an expected one.

## From Missed to Detected

A `Missed` step means no rule is watching for that technique. The detection engineer turns that into a tested
proposal:

1. It takes the run's missed steps and looks up reviewed detections for each technique in `ants/detections.json`.
   It never invents one.
2. It reads the plain endpoint logs for the run and for the 24 hours before, through the collector's checked search.
   These are the ordinary "this process started with this command line" records, kept in their own index, not alerts.
3. It strips every test marker from those logs and evaluates each detection on what is left, so a detection only
   counts when it catches the behaviour. A library entry that keys on the marker is refused when the library loads.
4. It reports, per detection: how many of the missed steps it catches, and how often it would also have fired on
   ordinary work in those 24 hours.

| Result | Meaning |
|---|---|
| `ready for review` | Catches every missed step it covers and did not fire on ordinary work. |
| `too noisy` | Catches the step, but also fired on ordinary work. Set aside. |
| `does not catch` | Did not match the step's own log entry. |
| `deployed, but did not fire` | A person recorded it as deployed and the step was still missed. |

Some missed steps get no proposal, with the reason: the step has no behaviour beyond the marker (a plain echo), the
library has no detection for that technique, or the step left no endpoint log.

**People decide.** `approve(proposal, person)` only works on a `ready for review` proposal.
`record_deployed(proposal, person)` only works after approval, and it records that a person deployed the rule; the
ant deploys nothing. In the sandbox, a stand-in for Splunk then raises an alert whenever a deployed detection matches
an endpoint log, so the re-run shows the step as `Detected` and the reporter lists it as an improvement.

**Stopping it (prevention) is advice only.** When Falcon saw a step but did not block it, the report says so and
explains that blocking is a Falcon policy change for a person to make once the detection has stayed quiet. The ants
never change Falcon.

The search text in a proposal is rendered from the same logic the ant tested, and it passes the collector's
validator. A lab Splunk Enterprise accepted every proposed search and returned the test host (see "Lab Splunk"
below), on synthetic logs where the command line is in a field called `process`. Your own logs may name that field
differently, so treat the search as a starting point for the reviewer. The noise figure comes from the sandbox's
synthetic day of admin activity, not from your environment.

The library has nine detections today: eight single-command ones and one that needs several discovery tools from the
same host within five minutes. In the sandbox the single-command ones come out `too noisy` and the combined one comes
out `ready for review`, which is the usual result in practice too.

## Playground: do the ants catch it?

The scenarios above check situations I chose. The playground checks the ants blind:

1. It picks random steps on random in-scope hosts.
2. Hidden from the ants, it decides what the defences do for each step: Falcon blocks it, Falcon only alerts, a
   Splunk rule fires, the copy does or does not reach Splunk, the alert does or does not carry the marker, or nothing
   reacts. In about one run in seven Falcon is down when the ants ask.
3. It mixes in decoys: an unrelated alert on the same host, an alert with another step's marker, the step's own
   marker on a different host, the step's own marker 40 minutes too early, an unrelated Falcon alert, and for network
   steps an unrelated connection between the same two addresses.
4. The ants run as usual. A referee, which knows the truth, then scores every verdict.

| Referee's call | Meaning |
|---|---|
| caught | A real, markable alert was there and the ants said Detected or Prevented, the right one of the two. |
| correct: nothing to catch | No defence reacted and the ants said Missed, whatever decoys were around. |
| correctly could not check | The only source that could have seen it was down, and the ants did not call it Missed. |
| not tied: the real alert has no marker | A defence did react, but its alert does not carry the marker. Known limit of marker matching. |
| false catch, flagged as weak | A network step matched an unrelated connection on the same addresses. Known limit; always flagged. |
| FALSE CATCH, MISSED A REAL ALERT, WRONG KIND, WRONG | The ants got it wrong. Any of these fails the run. |

```shell
splunk-es/.venv/Scripts/python validation-ants/sandbox.py playground            # one blind run, random seed
PLAYGROUND_SEED=7 splunk-es/.venv/Scripts/python validation-ants/sandbox.py playground   # repeat one
splunk-es/.venv/Scripts/python validation-ants/sandbox.py playground_many 100   # 100 blind runs, tally
```

Last tally of 100 blind runs (800 steps): 413 caught, 296 correct non-catches, 8 correctly could not check, 63 not
tied (no marker in the alert), 20 false catches flagged as weak (network steps), 0 wrong calls. The referee was also
checked against two deliberately broken ants (a Falcon observer that ignores the marker, a matcher that turns Could
not check into Missed); it reported wrong calls for both and none once they were restored.

The playground is still a simulation: the "defences" are the sandbox's own synthetic telemetry. It measures whether
the ants read that telemetry correctly, not whether your real tools detect anything.

## Librarian: a technique with no action

When a scenario names a technique the action library has no action for, the librarian ant (`ants/librarian.py`)
looks for a public test and drafts an action from it. It does not invent a test and it uses no model.

1. **Look up.** It reads a public library of attack tests from a local file in the layout of the Atomic Red Team
   index (`atomics/Indexes/index.yaml`). It never downloads anything.
2. **Filter.** Every public test for the technique is checked by fixed rules. The rules are an allow-list: a command
   passes only when every part of it is a known read-only tool used in a known read-only way (`whoami`, `netstat`,
   `net user` with at most one name, `reg query`, `sc query`, `schtasks /query`, `wmic ... get`, `netsh ... show`,
   and a short list of PowerShell `Get-` commands). A test is refused when it needs administrator rights, needs
   something installed first, needs cleaning up afterwards, writes a file, reaches another machine or the internet,
   touches passwords, or uses anything the checker does not recognise.
3. **Adapt.** The first test left gets the step marker and becomes a draft action. The draft keeps the public
   test's name and id, and the reason every other candidate was refused.
4. **Try.** The draft runs once in a throw-away sandbox: planned, signed by the gatekeeper, run by the simulated
   agent. This shows the action works with the other ants and leaves a marked log. It cannot show that the command
   is harmless; the agent is simulated. The rules and the person are what that rests on.
5. **Approve.** A person approves the draft exactly as it is. The approval is refused without a passed trial,
   without a name, or when the rules no longer pass. Approved actions are loaded with `Planner.add_actions`, and
   each time they are loaded the rules are checked again and a draft changed after its approval is dropped.

A technique in a refused family (credential dumping, log removal and so on) is never looked up, even when the public
library has a harmless-looking test for it. A technique with only tests that change something stays a gap: that is
where step 2 (a model drafting from harmless building blocks, with the same rules and the same approval) would
come in. It is not built.

```shell
splunk-es/.venv/Scripts/python validation-ants/sandbox.py librarian          # a scenario with gaps, before and after
splunk-es/.venv/Scripts/python validation-ants/sandbox.py librarian_rules    # 40 commands the rules allow or refuse
splunk-es/.venv/Scripts/python validation-ants/sandbox.py survey FILE        # how many gaps a library file would close
```

The sandbox uses `ants/sample_atomics.yaml`: 18 entries written for it, in the same layout, some unsafe on purpose.
It is not a copy of Atomic Red Team. With it, a scenario of ten techniques goes from 1 testable to 6: five drafts,
two techniques with only tests that change something, one not in the library, one refused family. How many gaps the
real Atomic Red Team index would close has not been measured: that needs the real file, which `survey` reads.

The rules are deliberately narrow. They will refuse harmless tests they do not recognise (most PowerShell, anything
with a pipe into a script block, anything that reads a file). Widening them is a reviewed change to the rule tables
in `librarian.py`, not something an ant does.

## Email and firewall tests

Two test types whose verdict comes from another tool's own logs, forwarded to Splunk. No new reader is needed: the
Splunk observer reads them.

| Test | What it does | Marker | Tool whose log decides |
|---|---|---|---|
| `T-MAIL-005` (`email_marker`, T1566.002) | One harmless, marked email to a dedicated test mailbox. Its only link points at a reserved address that cannot resolve. | In the subject | Mail gateway (Proofpoint) |
| `T-WEB-006` (`web_request_marker`, T1071.001) | One marked web request to an in-scope test server, through the firewall. | In the web address | Firewall (Check Point) |
| `T-NET-004` (`tcp_probe`, already there) | One plain connection. | None | Firewall, matched on addresses only |

How the log is read:

| The log says | Outcome |
|---|---|
| quarantined, blocked, dropped, rejected | `Prevented` |
| flagged but let through | `Detected`, with a "prevention gap" finding when the test expects a block |
| delivered, accepted | `Missed` (`seen_not_flagged`): the step is in the logs and nothing stopped or flagged it |
| nothing found | `Missed` |

- **Test mailboxes only.** The gatekeeper's scope has a list of test mailboxes (`allowed_mailboxes`). An email step
  is signed and run only when its command is exactly the allow-listed test email to one of them. Anything else is
  refused as out of scope, and a host with no test mailbox cannot be planned for an email test.
- **No real email is sent here.** In the sandbox the simulated agent only writes the log the mail gateway or the
  firewall would have written. Sending the real test email is for the endpoint stage.
- **A plain connection is still a weak match.** It has no marker, so any firewall log for the same address pair in
  the time window is read as its result. The finding says so and asks a person to confirm. The marked web request
  does not have this problem.
- **After a miss** the detection engineer proposes nothing for these two: what stops an email or a web request is
  the gateway's or the firewall's policy, which a person changes.
- The blind playground does not draw these two test types yet.
- Field and sourcetype names (`pps_messagelog`, `msg.header.subject`, `final_action`, `cp_log`, `resource`,
  `action`) are the add-ons' usual ones and are unverified against real Proofpoint or Check Point data.

```shell
splunk-es/.venv/Scripts/python validation-ants/sandbox.py gateways
```

## Lab Splunk: the same checks against a real Splunk Enterprise

The mock Splunk is something I wrote, so it can only prove what I assumed. `lab_splunk.py` repeats the important
checks against a real Splunk Enterprise in a container on this machine:

```shell
splunk-es/.venv/Scripts/python validation-ants/lab_splunk.py            # all groups
splunk-es/.venv/Scripts/python validation-ants/lab_splunk.py reader     # one group
```

- It talks to `127.0.0.1` only and refuses any other address, so it cannot be pointed at a real Splunk by mistake.
- Every event it sends is synthetic and made by the script, through the container's event collector with the
  event's own time. No real log is read or sent.
- The admin password, the event-collector token and the read-only account's password live in a file outside the
  repository (`OAEV_LAB_ENV`, default `~/.oaev-lab/splunk-lab.env`) and are never printed.
- Falcon stays a mock. Only Splunk is real.

Result on Splunk Enterprise 10.6.1.1 (2026-11-15), 36 checks:

| Group | What was checked | Result |
|---|---|---|
| wire | Index check for an index that exists and one that does not; a search of a missing index; a wrong password; a search Splunk cannot parse | As assumed. A missing index gives 404, and a search of it gives no rows and no error, so the index check is what stops a false `Missed`. |
| markers | A step marker in a command line, a parent process name, a file name, a looked-up hostname, without hyphens, in upper case | All found and tied to the right field. |
| markers | A marker glued inside a longer word (`x<marker>y`) | Not found. Splunk searches whole words. The mock found it; the mock now behaves like Splunk. |
| run | Every ant, first run and repeat run, four tests | Detected, Prevented, Detected, Missed, both times. 1 wide search on the first run; 1 narrow + 1 wide on the repeat run. The Falcon alert's copy in Splunk is counted once, and its alert id is read from the nested `event.CompositeId` field. |
| detections | The detection engineer reads the endpoint logs from the lab, tests the detections, and each proposed search is run by Splunk | Same proposals as on the mock. Splunk accepted every search and returned the test host. |
| reader | The same through an account whose only capability is `search`, limited to two indexes | Works, and that account cannot change Splunk (creating an index answers 403). |
| reader | An index that exists, but that the account's role may not search | **This was a hole.** The index check passed and the search returned nothing, which would have been scored `Missed`. The collector now reads the account's own roles and reports `Could not check` instead. |

| gateways | A quarantined test email, a dropped marked web request and a dropped plain connection, each log in its own index, read with the read-only account | All three `Prevented`, in one search over three indexes. The email is tied through the nested `msg.header.subject`, the web request through `resource`; the plain connection is flagged as a weak match. |
| gateways | The same three, delivered and accepted | All three `Missed` (`seen_not_flagged`). |
| gateways | First attempt | **This was a hole.** Every blocked step read as let through: the search did not ask Splunk for the `action` fields, and Splunk returns only the fields a search asks for. The mock returned whole rows, so it could not show this. The search now asks for them, and both mocks now return only the fields asked for. |

Also learned: Splunk gives the event time with milliseconds and a UTC offset (the collector already read that
correctly; the mock now answers the same way). A real Splunk also keeps earlier runs' logs, so a plain connection
test picked up the firewall log of a different test on the same address pair a few minutes before. That is the weak
match described above; the lab groups now use separate addresses.

What the lab does not show: your real sourcetypes and field names (they depend on the add-ons installed), a real
Falcon forwarding its alerts, search speed on real volumes, or a search head cluster. The lab is one small Splunk
with synthetic events.

## What this is not

- Run against a lab Splunk Enterprise with synthetic events (above), but not against your Splunk, a real Falcon
  tenant or a real host. How those behave is unverified.
- The Falcon observer is new and small. The fork's own `crowdstrike` collector is untouched: it still returns no
  alerts when the Falcon API fails, which leaves its expectations to expire as failed.
- A network step has no marker. An addresses-only match is flagged as weak, not checked against a quiet window.
- The learned-rule check cannot tell two unmarked alerts from the same rule apart; that is why it always asks for
  confirmation.
