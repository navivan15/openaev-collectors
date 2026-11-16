# The ants: what each one is and where its code lives

An "ant" here is a small piece of Python with one job and fixed rules. **The ants are code, not AI models.** There
are no model files in this repository. One ant, the drafter, can ask a model for help; today it is wired to a
scripted stand-in, so nothing here calls a real model (see [COPILOT.md](COPILOT.md)).

All paths are relative to the repository root.

## The roster

Seventeen ants appear on the demo page's ant map. Thirteen live in `validation-ants/ants/`; three are parts of the
`splunk-es` collector that the Splunk observer reuses; one (the referee) is part of the sandbox.

| # | Ant | Code | Job | Rule it never breaks | Uses a model |
|---|---|---|---|---|---|
| 1 | Intel | `validation-ants/ants/intel.py` | Reads a threat scenario from OpenCTI (a STIX bundle) and lists its ATT&CK techniques in tactic order | Reads only | No |
| 2 | Scenario builder | `validation-ants/ants/scenario_builder.py` | Maps each technique to an allow-listed action and writes a draft scenario with a coverage table | Never writes a command. A person approves the draft | No |
| 3 | Librarian | `validation-ants/ants/librarian.py` | For a technique with no action, looks up a public test in a local file and drafts an action from it | Only read-only commands pass. A person approves each draft | No |
| 4 | Drafter | `validation-ants/ants/drafter.py` | When the librarian finds nothing, asks a model for one read-only command | The answer goes through the librarian's rules. A person approves | **Yes** (stand-in today) |
| 5 | Planner | `validation-ants/ants/planner.py` | Turns tests into steps; gives each step a new marker (a UUID) | Commands come only from the action allow-list | No |
| 6 | Gatekeeper | `validation-ants/ants/gatekeeper.py` | Signs steps that are in scope, refuses the rest, keeps a sealed audit log | Nothing runs without its signature | No |
| 7 | Agent | `validation-ants/ants/agent_sim.py` | Stand-in for OpenAEV's endpoint agent | **Runs no command.** It writes the logs the defences would produce | No |
| 8 | Location memory | `splunk-es/src/services/location_memory.py` | Remembers where each test's logs were found last time | An empty remembered place is re-checked with a wide search before anything is called Missed | No |
| 9 | Query writer | `splunk-es/src/services/query_writer.py` | Writes the Splunk search from proven templates | Never from free text | No |
| 10 | Validator | `splunk-es/src/services/spl_validator.py` | Refuses any search that is not read-only | A refused search is never sent | No |
| 11 | Splunk observer | `validation-ants/ants/observers.py` (`SplunkObserver`) | Wraps the real `splunk-es` collector service; ties alerts and gateway logs to steps | A broken connection is `Could not check`, never `Missed` | No |
| 12 | Falcon observer | `validation-ants/ants/observers.py` (`FalconObserver`) | Reads CrowdStrike Falcon alerts | Reads only | No |
| 13 | Analyst | `validation-ants/ants/analyst.py` | Records how each search changed between runs, and why | Its log is hash-chained | No |
| 14 | Matcher | `validation-ants/ants/matcher.py` | Joins what the tools saw into one verdict per step | A forwarded alert counts once; a match without a marker is flagged | No |
| 15 | Detection engineer | `validation-ants/ants/detection_engineer.py` | Tests or builds a detection for each missed step | Proposes only; never changes Splunk or Falcon | No |
| 16 | Reporter | `validation-ants/ants/reporter.py` | Scores the run and compares it with the last one | Unchecked and not-run steps are left out of the score | No |
| 17 | Referee | `validation-ants/sandbox.py` (playground) | Knows the hidden truth of a blind run and scores the ants | Fails the run on any wrong call | No |

## Data files the ants read

| File | What it holds | Who reads it |
|---|---|---|
| `validation-ants/ants/catalogue.json` | The action allow-list (15 actions), the technique table (22 techniques with names and tactics), the 7 refused technique families, and 6 ready-made tests | Planner, scenario builder, gatekeeper |
| `validation-ants/ants/detections.json` | 9 reviewed detections, keyed on behaviour (never on the marker) | Detection engineer |
| `validation-ants/ants/sample_atomics.yaml` | 18 public-test entries written for the sandbox, in the layout of the Atomic Red Team index. Not a copy of Atomic Red Team | Librarian (sandbox only) |
| `validation-ants/ants/reversible.json` | 9 change-and-undo actions. Off by default. See "Parked" in [STATUS.md](STATUS.md) | Planner, when a run switches them on |
| `splunk-es/src/services/query_templates.json` | The proven search templates | Query writer |
| The location memory file (`SPLUNKES_MEMORY_PATH`, written at run time) | Where each test's logs were found | Location memory |

## Code map

The main class or function of each file, so the next person (or session) can find its way in.

| File | Start here |
|---|---|
| `ants/models.py` | `Step`, `Plan`, `Observation`, `StepVerdict`; the outcome names `DETECTED`, `PREVENTED`, `MISSED`, `COULD_NOT_CHECK`, `NOT_RUN` |
| `ants/intel.py` | `IntelAnt.from_bundle(bundle)`, `OpenCTIClient(base_url, token).report_bundle(report_id)` |
| `ants/scenario_builder.py` | `ScenarioBuilder.draft(threat)`, `.approve(scenario_id, by)`, `tests_digest(tests)` |
| `ants/librarian.py` | `check_command(command, executor)`, `check_test(test)`, `Librarian(index_path, actions, not_simulated, store_dir)` with `find`, `new_draft`, `fill_gaps`, `record_trial`, `approve`, `approved_actions`, `survey` |
| `ants/drafter.py` | `Drafter(librarian, model, model_name)` with `request`, `read_answer`, `draft` |
| `ants/planner.py` | `Planner(catalogue_path, reversible=False)` with `add_actions`, `use_scenario`, `plan`, `plan_pairs` |
| `ants/gatekeeper.py` | `Gatekeeper(scope, actions, key, audit_path, kill_switch_path)` with `sign_plan`, `authorise`, `verify_audit`, `engage_kill_switch`, `record_cleanup`, `clear_host` |
| `ants/agent_sim.py` | `SimulatedAgent.run(step)` |
| `ants/observers.py` | `SplunkObserver.observe(steps, agentless_actions)`, `FalconHttpClient`, `FalconObserver.observe(...)` |
| `ants/analyst.py` | `SearchAnalyst.record(...)`, `.verify_log()` |
| `ants/matcher.py` | `Matcher.fuse(steps, observations, ...)`, `RuleBook.confirm(test_id, source, rule_name, by)` |
| `ants/detection_engineer.py` | `DetectionEngineer.propose(verdicts)`, `.approve`, `.record_deployed`; `derive_terms`, `evaluate`, `render_spl` |
| `ants/reporter.py` | `Reporter.report(run_id, verdicts, ...)`, `team_views` |
| `ants/pipeline.py` | `run_validation(...)`: one run, start to end |
| `ants/reversible.py` | `check_reversible(action, payload)`, `load_reversible()` |
| `sandbox.py` | `Ants` (all the ants wired together on mocks), the mock Splunk, Falcon and OpenCTI servers, and the 28 scenarios |
| `lab_splunk.py` | The same checks against a real Splunk Enterprise in a local container |

## How the ants are wired together

`validation-ants/sandbox.py`, class `Ants`, builds every ant and connects them. It is the one place to read to see
what each ant is given: the gatekeeper's scope (allowed hosts, targets, mailboxes, time window, step limit), the
Splunk observer's settings (the same `SPLUNKES_*` settings the real collector uses), and the defences the simulated
agent pretends are in place.

A real deployment would replace three things in that class and keep the rest: the mock Splunk address, the mock
Falcon address, and the simulated agent. Those are listed in [COPILOT.md](COPILOT.md) under "The other connection
points".

## Adding to the ants

| To add | Change | Guard that checks it |
|---|---|---|
| A new harmless action | `ants/catalogue.json`, `actions` and `techniques` | The planner refuses an action for a refused family; the gatekeeper derives the command itself |
| A reviewed detection | `ants/detections.json` | Refused at load when it keys on the marker or uses non-plain terms |
| A wider librarian rule | The rule tables in `ants/librarian.py` | `sandbox.py librarian_rules` (49 commands that must be allowed or refused) |
| A new ant on the map | `ROSTER` and `ANT_EDGES` in `splunk-es/harness/demo/index.html` | See [FRONT-END.md](FRONT-END.md) |
| A new scenario | A function `s_<name>` and a line in `SCENARIOS` in `sandbox.py` | `sandbox.py all` |

After any change run the three suites in [SETUP.md](SETUP.md), section "Check that everything works".
