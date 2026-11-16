# Scenarios: every check, what it shows, how to run it

There are three sets of checks. The first two need nothing but Python. The third needs a lab Splunk container.

| Set | Command (from the repository root) | Count | Needs |
|---|---|---|---|
| Ants sandbox | `splunk-es/.venv/Scripts/python validation-ants/sandbox.py all` | 28 scenarios | Python only |
| Collector harness | `cd splunk-es` then `.venv/Scripts/python harness/mock_e2e_harness.py all` | 40 scenarios | Python only |
| Lab Splunk | `splunk-es/.venv/Scripts/python validation-ants/lab_splunk.py` | 36 checks in 6 groups | The lab container (see [SETUP.md](SETUP.md)) |

Each command prints a pass/fail table and exits non-zero when a result is not the expected one. To see one
scenario in detail, give its name in place of `all`. Every scenario can also be run from the demo page
([FRONT-END.md](FRONT-END.md)).

Last full result (2026-11-15): sandbox 28 of 28, harness 40 of 40, lab 36 of 36, and 100 blind playground runs with
no wrong call.

## 1. Ants sandbox (`validation-ants/sandbox.py`)

All ants wired together on mock Splunk, mock Falcon and mock OpenCTI.

### Whole runs

| Scenario | What it shows | Expected result |
|---|---|---|
| `threat_scenario` | A report from the mock OpenCTI is built into tests, approved and run | 14 techniques, 11 tests built (9 full, 2 partial), 3 not testable |
| `full_run` | The four base tests through every ant | 2 Detected, 1 Prevented, 1 Missed; rate 75%; one Splunk search for all four |
| `repeat_run` | The second run uses the location memory | 1 narrow search for the 3 remembered tests, 1 wide for the other |
| `search_changes` | The analyst's log across runs | learned, confirmed, added, dropped, each with its reason; an edited log is detected |
| `gateways` | A marked test email and marked web requests, read from mail gateway and firewall logs in Splunk | Blocked reads as Prevented; delivered reads as Missed; the plain connection is flagged as a weak match |
| `drift` | A test that was Detected and is now Missed | Reported as a regression; `Could not check` is "unknown", not a regression |

### Scenario builder, librarian, drafter

| Scenario | What it shows | Expected result |
|---|---|---|
| `scenario_guards` | What the scenario builder refuses | 9 refusals: broken sources, unapproved draft, nameless approval, change after approval, action off the allow-list |
| `librarian` | A scenario with techniques the library has no action for | 9 gaps: 5 drafts from harmless public tests, tried, approved by a person, then run |
| `librarian_rules` | The rules that decide what is read-only | 49 commands: 15 allowed, 34 refused |
| `drafter` | The model is called when no public test fits | 4 gaps, 7 model calls, 2 drafts pass, 1 never harmless, 1 declined |

### Gatekeeper

| Scenario | What it shows | Expected result |
|---|---|---|
| `gate_out_of_scope` | A host not on the scope list | Both steps refused; nothing ran there |
| `gate_tampered` | A step changed after signing | Changed host: bad signature. Changed command: not allow-listed |
| `gate_kill_switch` | The kill switch engaged mid-run | 2 steps ran, the remaining 2 refused |
| `gate_outside_window` | A time window that ended yesterday | Both steps refused, nothing scored |
| `gate_replay_and_limit` | A replayed step, an unsigned step, a step limit | All refused |
| `gate_hardening` | 11 bypass attempts: injection, look-alike hosts, replay after a restart and more | All refused and logged |
| `audit_tamper` | An edited, removed, cut-off or re-hashed audit entry | All detected; no step runs while the log is broken |

### Observers and matcher

| Scenario | What it shows | Expected result |
|---|---|---|
| `falcon_down` | Falcon answers with an error | The Falcon-only step is `Could not check`; the other is Detected from Splunk and flagged partly checked |
| `falcon_auth` | Falcon rejects the sign-in | Same |
| `falcon_unreachable` | The connection to Falcon drops | Same |
| `pipeline_gap` | Falcon saw it, Splunk has no copy | Log pipeline gap reported |
| `prevention_gap` | Expected Prevented, got Detected | Prevention gap reported |
| `learned_rule` | A rule two people confirmed detects an unmarked alert | Used and flagged; not used when the rule also fired in the quiet window before |
| `matcher_hardening` | A learned rule cannot borrow another step's alert | Refused; a partly checked run is not a regression |

### Detection engineer

| Scenario | What it shows | Expected result |
|---|---|---|
| `detection_loop` | Missed, proposal, approval, re-run | 4 missed, 1 rule ready (catches 4 of 4, no noise in 24 h), 4 single-command rules set aside as too noisy; Detected after a person deploys |
| `detection_guards` | What the detection engineer refuses | A marker-keyed rule, non-plain terms; nothing proposed for marker-only steps |

### Blind check

| Scenario | What it shows | Expected result |
|---|---|---|
| `playground` | Random steps, hidden defences, decoy alerts, a referee | No wrong call |

```shell
PLAYGROUND_SEED=7 splunk-es/.venv/Scripts/python validation-ants/sandbox.py playground   # repeat one run
splunk-es/.venv/Scripts/python validation-ants/sandbox.py playground_many 100            # 100 runs, tally
```

### Parked

| Scenario | What it shows | Expected result |
|---|---|---|
| `reversible` | Change-and-undo tests on a dedicated test machine | See "Parked" in [STATUS.md](STATUS.md) |

### Other commands

```shell
splunk-es/.venv/Scripts/python validation-ants/sandbox.py library        # print the attack library
splunk-es/.venv/Scripts/python validation-ants/sandbox.py survey FILE    # how many gaps a public test file would close
```

## 2. Collector harness (`splunk-es/harness/mock_e2e_harness.py`)

The real `splunk-es` collector code against a mock Splunk and a mock OpenAEV in one process. Each scenario checks
one outcome.

| Group | Scenarios | Expected |
|---|---|---|
| Basic outcomes | `detected`, `token`, `marker_match`, `marker_file`, `marker_dns` | `Detected`, matched by step marker |
| | `not_detected`, `marker_absent` | `Missed` (`marker_absent`) |
| | `time_window_miss` | `Missed` (`outside_time_window`) |
| | `wrong_host` | `Missed` (`wrong_host`) |
| | `prevention` | `Could not check` (`no_verdict_in_logs`): an alert does not say whether the step was blocked |
| Matches without a marker | `ip_only`, `ipv6`, `ip_bleed`, `implant_url` | `Detected` by the older fallback. `ip_bleed` is a known limit: a stale alert sharing the address pair still counts |
| Late alert | `late_alert` | `Detected` after a second search |
| Could not check | `auth_fail` | `auth_failed` |
| | `cnc_unreachable`, `cnc_wide_conn`, `cnc_narrow_conn` | `source_unreachable` |
| | `cnc_missing_index`, `cnc_unreadable_index` | `data_source_missing` |
| | `cnc_search_error` | `search_failed` |
| | `query_refused` | `query_refused`: a template containing `\| delete` is never sent |
| Gateway logs | `gw_email_blocked`, `gw_alert_allowed`, `gw_two_indexes` | `Detected` |
| | `gw_fw_prevented` | `Prevented` |
| | `gw_email_delivered` | `Missed` (`seen_not_flagged`) |
| | `gw_fw_not_blocked` | `Missed` (`not_blocked`) |
| Location memory | `memory_narrow_hit`, `memory_late_first_run`, `memory_wide_fallback`, `memory_miss`, `memory_expired`, `memory_periodic_wide` | Narrow search on a repeat run; wide search when the remembered place is empty, expired, or on every fifth run |
| Search cost | `batched_markers` | 3 steps cost 1 search |
| | `not_yet_due` | A step still inside its alert delay costs 0 searches |
| Trace | `falcon_id` | The trace names the index, sourcetype, field and Falcon alert id |
| Safety of searches | `validator_rules` | 15 searches refused, 3 accepted |
| | `template_proving` | An unproven or unsafe template is refused; a new one is saved only after a mock run |

```shell
cd splunk-es
.venv/Scripts/python harness/mock_e2e_harness.py marker_match      # one scenario with the full wire trace
.venv/Scripts/python -m pytest -q -p no:logging                     # the collector's unit tests
```

The unit tests give 102 passed and 1 failed. The failure
(`tests/test_create_collector.py::test_collector_config_missing_required_values`) was there before this work and
is unrelated to it.

## 3. Lab Splunk (`validation-ants/lab_splunk.py`)

The same logic against a real Splunk Enterprise in a container on this machine, with synthetic events only. It
refuses any address other than `127.0.0.1`.

| Group | What is checked |
|---|---|
| `wire` | The index check for an index that exists and one that does not; a search of a missing index; a wrong password; a search Splunk cannot parse |
| `markers` | A step marker in a command line, a parent process name, a file name, a looked-up hostname, without hyphens, in upper case; a marker glued inside a longer word is not found (Splunk searches whole words) |
| `run` | Every ant, first run and repeat run, four tests; the forwarded Falcon alert counted once |
| `detections` | The detection engineer reads endpoint logs from the lab; Splunk runs each proposed search |
| `reader` | The same through a search-only account; that account cannot change Splunk; an index it may not search reports `Could not check` |
| `gateways` | A quarantined test email, a dropped marked web request and a dropped plain connection, each in its own index |

```shell
splunk-es/.venv/Scripts/python validation-ants/lab_splunk.py            # all groups
splunk-es/.venv/Scripts/python validation-ants/lab_splunk.py reader     # one group
```

The lab found two real faults that the mock could not show. Both are fixed and both now have a mock scenario
(`cnc_unreadable_index`, and the gateway scenarios). The full findings table is in the
[README](../README.md), section "Lab Splunk".
