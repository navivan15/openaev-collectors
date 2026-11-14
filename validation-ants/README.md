# Validation ants

The roles that sit around the collectors to run a detection-validation exercise end to end:
plan benign steps, gate them, run them, read each security tool, tie alerts to steps, and report.

Everything here runs **on mocks only**. The endpoint agent is simulated and executes nothing; Splunk and CrowdStrike
Falcon are mock servers. It is for authorised testing of systems the organisation owns.

```
planner -> gatekeeper -> agent -> Splunk observer + Falcon observer -> analyst -> matcher -> reporter
```

| Ant | File | What it does |
|---|---|---|
| Planner | `ants/planner.py`, `ants/catalogue.json` | Turns catalogue tests into steps. Each step gets a new marker (a UUID) and a command taken from the action allow-list. It cannot invent an action. |
| Gatekeeper | `ants/gatekeeper.py` | Decides whether a step may run, and keeps the audit log. See below. |
| Agent | `ants/agent_sim.py` | Sandbox stand-in for OpenAEV's endpoint agent. Asks the gatekeeper, then writes the synthetic telemetry the configured defences would produce. Runs no command. |
| Splunk observer | `ants/observers.py` | Adapter around the real `splunk-es` collector service: checked queries, location memory, step matching, four outcomes. |
| Falcon observer | `ants/observers.py` | Read-only reader of Falcon alerts (sign in, list ids, fetch alerts). Same three checks: time window, host, step marker. Reports `Prevented` from the alert's disposition, using the fork's `crowdstrike/pattern_disposition.py`. |
| Analyst | `ants/analyst.py` | After each run, writes one entry per step to a search-change log: how the test was searched, how it will be searched next time, and why. |
| Matcher | `ants/matcher.py` | Fuses the sources into one verdict per step, counts a forwarded Falcon alert once, applies learned rules, raises findings. |
| Reporter | `ants/reporter.py` | Scorecard for the run and drift against the previous run. |

The four outcomes are the collector's: `Detected`, `Prevented`, `Missed`, `Could not check`. A step the gatekeeper
refused is `Not run`; it is listed and never scored.

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
splunk-es/.venv/Scripts/python validation-ants/sandbox.py all        # 18 scenarios, pass/fail table
splunk-es/.venv/Scripts/python validation-ants/sandbox.py full_run   # one scenario with details
```

The scenarios cover a full run, a repeat run using the memory, the analyst's change log, every gatekeeper control
(scope, changed step, kill switch, window, replay, step limit, audit tampering, bypass attempts), Falcon failures,
the pipeline and prevention gaps, the learned rule with its quiet window, and drift. The demo page
(`splunk-es/harness/demo_server.py`) lists them under "All ants: full pipeline".

## What this is not

- Not run against a real Splunk, a real Falcon tenant or a real host. How those behave is unverified.
- The Falcon observer is new and small. The fork's own `crowdstrike` collector is untouched: it still returns no
  alerts when the Falcon API fails, which leaves its expectations to expire as failed.
- A network step has no marker. An addresses-only match is flagged as weak, not checked against a quiet window.
- The learned-rule check cannot tell two unmarked alerts from the same rule apart; that is why it always asks for
  confirmation.
