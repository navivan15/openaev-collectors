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
(`splunk-es/harness/demo_server.py`) lists them under "All ants: full pipeline".

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
validator, but it has not been run by a real Splunk. Treat it as a starting point for the reviewer. The noise figure
comes from the sandbox's synthetic day of admin activity, not from your environment.

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

## What this is not

- Not run against a real Splunk, a real Falcon tenant or a real host. How those behave is unverified.
- The Falcon observer is new and small. The fork's own `crowdstrike` collector is untouched: it still returns no
  alerts when the Falcon API fails, which leaves its expectations to expire as failed.
- A network step has no marker. An addresses-only match is flagged as weak, not checked against a quiet window.
- The learned-rule check cannot tell two unmarked alerts from the same rule apart; that is why it always asks for
  confirmation.
