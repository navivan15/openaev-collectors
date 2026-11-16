# The whole flow: from a scenario to a scored report

This is what happens in one validation run, in order, and who does each part. Everything below runs on mocks today:
the endpoint agent is simulated and runs no command, and Splunk, CrowdStrike Falcon and OpenCTI are mock servers
inside the sandbox.

## The picture

```
                       a person approves              a person approves
                              |                              |
 threat report --> Intel --> Scenario builder --> Planner --> Gatekeeper --> Agent (simulated)
                              |    ^                                           |
                  no action?  v    | approved action                           v  logs and alerts
                           Librarian --> Drafter (model)             Splunk         Falcon
                                                                        |              |
              Location memory --> Query writer --> Validator --> Splunk observer   Falcon observer
                                                                        |              |
                                                          Analyst <-----+--> Matcher <-+
                                                                               |
                                                                      Detection engineer
                                                                               |
                                                                            Reporter
```

## Three ways a run starts

| Start | What goes in | Where |
|---|---|---|
| A threat scenario | A report from OpenCTI, as a STIX bundle | `sandbox.py threat_scenario`; the "Scenario from OpenCTI" tile on the demo page |
| A pick from the attack library | A list of ATT&CK techniques and hosts chosen on the demo page | The "Attack library" view; runs as `sandbox.py custom` with the pick in `SANDBOX_CUSTOM` |
| Ready-made tests | Test ids from `ants/catalogue.json` (`T-EXEC-001` and so on) | `sandbox.py full_run` |

All three end in the same plan and go through the same ants from the planner on.

## Step by step

### 1. A scenario comes in (Intel)

The intel ant fetches a report from OpenCTI, or takes a bundle a person exported. It keeps the threat's name and
every attack pattern that carries a MITRE ATT&CK id, in tactic order. A pattern with no id is left out and counted.

### 2. The scenario becomes tests (Scenario builder)

Each technique is looked up in the action library (`ants/catalogue.json`). The result is a draft scenario with a
coverage table:

| Coverage | Meaning |
|---|---|
| `simulated` | A reviewed action behaves like the technique |
| `partial` | The real technique would change the system, so the action only runs the same tool read-only |
| `not simulated` | The technique cannot be done harmlessly (credential dumping, log removal, disabling a defence, destructive actions, real accounts, exploitation). Always refused |
| `no action` | Nothing in the library covers it yet. This is a gap |

### 3. Gaps get filled, or stay gaps (Librarian, then Drafter)

For each `no action` technique:

1. The **librarian** looks for a public test in a local file. Fixed rules decide whether a test is read-only. The
   first test that passes becomes a draft action.
2. If the librarian finds nothing, the **drafter** asks a model for one read-only command. The answer goes through
   the same rules. Three answers at most.
3. Every draft is tried once in a throw-away sandbox.
4. **A person approves each draft.** Only then can the planner use it.

A technique that gets no draft stays a gap and is listed in the report as not tested. Nothing is invented to hide it.

**Not joined up yet.** Today this step runs in its own scenarios (`sandbox.py librarian`, `sandbox.py drafter`).
A run started from an OpenCTI scenario or from the attack library lists the gaps and carries on without them. The
small change that joins the two is described in [COPILOT.md](COPILOT.md).

### 4. A person approves the scenario

The approval is bound to the exact list of tests. The planner refuses a draft, and refuses a scenario that changed
after it was approved.

### 5. Tests become steps (Planner)

One step per test per host. Each step gets a new marker, a UUID that appears in the command as
`oaev-step-<uuid>`. The marker is how an alert is later tied to exactly this step. The command is taken from the
allow-listed action; the planner cannot write one.

### 6. Each step is checked and signed (Gatekeeper)

A step runs only if all of these hold at the moment it is about to run:

1. The kill switch is off.
2. The host, the target address and the mailbox are on the scope lists, and the command is exactly what the
   allow-listed action produces.
3. The step carries a valid signature. Any change after signing voids it.
4. Now is inside the approved time window.
5. The step has not run before, and the run is under its step limit.

Every decision goes to a sealed audit log. A refused step is `Not run`: listed, never scored.

### 7. The step runs (Agent)

In this repository the agent is a stand-in. It asks the gatekeeper once more, then writes the logs and alerts that
the configured defences would have produced. **It executes nothing.** In real use this is OpenAEV's own endpoint
agent on a test machine.

### 8. The tools are read (Splunk observer, Falcon observer)

- **Splunk.** The location memory says where this test's logs were found before. The query writer builds a search
  from proven templates: a narrow one for remembered places, a wide one otherwise. The validator refuses anything
  that is not read-only. The observer sends the search and ties rows to steps by three checks: marker, host, time
  window. Mail gateway and firewall logs are read the same way; their `action` field says blocked or let through.
- **Falcon.** The observer signs in, lists alerts since the run started, and applies the same three checks. An
  alert's disposition says whether Falcon blocked the step.

Each source answers with one of four outcomes per step.

| Outcome | Meaning |
|---|---|
| `Detected` | An alert tied to the step was found |
| `Prevented` | The tool blocked the step |
| `Missed` | The source was asked, answered, and had nothing |
| `Could not check` | The source could not be asked (sign-in failed, unreachable, index missing or not readable, search refused) |

`Could not check` is never turned into `Missed`. That rule is the reason several of the scenarios exist.

### 9. The searches are written down (Analyst)

Per step the analyst records how the test was searched, how it will be searched next time, and why: `learned`,
`confirmed`, `added`, `dropped`, `none` or `unchecked`. This is what makes the second run cheaper than the first,
and auditable.

### 10. One verdict per step (Matcher)

The matcher joins the sources. `Prevented` if any source prevented it, else `Detected` if any saw it. A Falcon alert
and its forwarded copy in Splunk count once. It raises findings: log pipeline gap (in Falcon, not in Splunk),
prevention gap (seen, not blocked), partly checked, weak match (a network step matched on addresses only).

### 11. Missed steps get a proposal (Detection engineer)

For each `Missed` step the detection engineer tests a reviewed detection on the plain endpoint logs: does it catch
the step, and how often would it have fired on ordinary work in the 24 hours before. When the library has no
detection it builds a simple one from the test's own command. The result is a proposal for a person:
`ready for review`, `too noisy` or `does not catch`. The ant deploys nothing.

### 12. The run is scored (Reporter)

Detection rate = (Detected + Prevented) / (Detected + Prevented + Missed). The report also has the coverage table,
the same run per team (purple team, SecOps, NetOps), the findings, and drift against the last run: Detected before
and Missed now is a regression.

### 13. The loop

A person approves a proposal and deploys the rule in Splunk themselves, then records that they did. The next run
shows the step as `Detected`, and the reporter lists it as an improvement.

## What a person does, and what the ants never do

| A person | The ants never |
|---|---|
| Approves a scenario | Run a step the gatekeeper did not sign |
| Approves a new action drafted by the librarian or the drafter | Write a command of their own |
| Sets the scope: hosts, targets, mailboxes, time window, step limit | Change anything in Splunk or Falcon |
| Engages or releases the kill switch | Deploy a detection |
| Approves a detection proposal and deploys it | Turn `Could not check` into `Missed` |
| Confirms a learned rule (two different people) | Send a search the validator refused |

## Where this stops today

The flow is complete on mocks. The steps that still need a real system are listed in [STATUS.md](STATUS.md) under
"Not proven", and the places where a real system or a model plugs in are in [COPILOT.md](COPILOT.md).
