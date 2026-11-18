# Status and hand-over

Where the work stands, what is proven, what is not, and how to pick it up again. Last updated 2026-11-18.

## What this is

An in-house way to check that security tools notice attacker behaviour, built on OpenAEV (open source, Apache-2.0).
Harmless, marked test steps are run on machines the organisation owns; the "ants" then read Splunk Enterprise and
CrowdStrike Falcon to see whether each step was detected, blocked or missed, and report it. It is for authorised
testing only.

## Where it lives

| | |
|---|---|
| Repository | `github.com/navivan15/openaev-collectors` (private) |
| Branch | `work`. Not `main` |
| Local copy | `%USERPROFILE%\Downloads\Code\openaev-collectors` |
| The ants | `validation-ants/` |
| The Splunk collector they build on | `splunk-es/` |
| The front end | `splunk-es/harness/demo/index.html`, `splunk-es/harness/demo_server.py` |

## Documents

| Document | What it answers |
|---|---|
| [../README.md](../README.md) | What each ant does, in depth, with every known limit |
| [SETUP.md](SETUP.md) | How to get from a fresh copy to everything running |
| [FLOW.md](FLOW.md) | What happens in one run, start to end |
| [SCENARIOS.md](SCENARIOS.md) | Every check, what it shows, how to run it |
| [ANTS.md](ANTS.md) | Each ant, its code file, and a map of the code |
| [FRONT-END.md](FRONT-END.md) | The demo page: attack library, sandbox, ant map |
| [COPILOT.md](COPILOT.md) | Where a model connects, and where real systems connect |
| `splunk-es/README.md` | The Splunk collector itself: settings, matching, outcomes |

## What is built

| Part | State |
|---|---|
| Splunk collector: step-marker matching, four outcomes, location memory, checked searches, gateway logs | Built, tested on mocks and on a lab Splunk |
| Ants: intel, scenario builder, planner, gatekeeper, simulated agent, Splunk and Falcon observers, analyst, matcher, detection engineer, reporter | Built, tested on mocks |
| Librarian: drafts an action from a harmless public test | Built, tested on mocks; measured against the real Atomic Red Team index |
| Drafter: asks a model when no public test fits | Built, tested with a scripted stand-in. No real model connected |
| Email and firewall tests (Proofpoint and Check Point logs read from Splunk) | Built, tested on mocks and on a lab Splunk |
| Blind playground with a referee | Built; 100 runs, no wrong call |
| Front end: attack library, sandbox job board, ant map | Built |
| Lab Splunk checks | Built; 36 of 36 on Splunk Enterprise 10.6.1.1 |

## Proven, and how

| Claim | Evidence |
|---|---|
| The ants read synthetic telemetry correctly | Sandbox 28 of 28; 100 blind runs with decoys, 0 wrong calls |
| The collector gives the right outcome for each case | Harness 40 of 40 |
| The searches behave the same on a real Splunk Enterprise | Lab 36 of 36, synthetic events only |
| The install steps in SETUP.md work on a clean Python environment | Run once on 2026-11-15 in a new environment: 28 of 28, 40 of 40, and the unit tests at 102 passed with the 1 old failure |
| A search-only Splunk account is enough, and cannot change Splunk | Lab group `reader` |
| The ants run on a machine that has no OpenAEV client (`pyoaev`) | 2026-11-18, in an environment without it: sandbox 28 of 28, 100 blind runs with 0 wrong calls. The stand-in was compared with the real client (versions 2.260704.0 and 3.261116.1) on 25,000 cases: no differences |
| The newest OpenAEV client works as well as the pinned one | 2026-11-18, `pyoaev 3.261116.1`: sandbox 28 of 28, harness 40 of 40, unit tests 102 passed with the 1 old failure |

## Not proven

Each of these is unknown until it is tried on the real thing.

| Unknown | Why it matters |
|---|---|
| Real sourcetype and field names at work (Falcon data in Splunk, Proofpoint, Check Point) | The searches name fields. The names used are the add-ons' usual ones |
| A real Falcon tenant | The Falcon observer has only read a mock |
| A real OpenCTI | The query used to fetch a report is unchecked |
| Any real model | The drafter has only talked to a scripted stand-in |
| A real endpoint | The agent is simulated. No test command has run on any machine, including this PC |
| Search speed on real volumes, a search head cluster | The lab is one small Splunk |
| Noise of a proposed detection in the real environment | The noise figure comes from a synthetic day of activity |

## Known limits, by design

- A plain network connection has no marker. A match on addresses only is flagged as weak, for a person to confirm.
- Splunk searches whole words, so a marker glued inside a longer word is not found.
- A defence whose alert does not carry the marker is not tied to its step.
- Built detections are simple: a first idea for a rule, not a finished one.
- The blind playground does not draw the email and firewall test types.
- Without the OpenAEV client the ants use a stand-in. It cannot report to an OpenAEV platform, and the
  collector, its harness and its unit tests still need the real client.

## Parked

The change-and-undo tests (`ants/reversible.json`, `ants/reversible.py`, the `reversible` scenario) are in the
code and off by default. The owner set this request aside on 2026-11-15. They are kept as they are: not to be
extended, switched on or used until the owner decides. None of their commands has ever been run on a real machine.

## Rules the work has followed

These are the owner's rules and they still hold.

1. **Mocks only on this PC.** No real Splunk, no real Falcon tenant, no employer hosts or data.
2. **Never connect to an employer system from this PC.**
3. **Benign simulations only.** No real malware. Nothing from a downloaded public test library is ever run; it is
   read as data.
4. **The ants never change Splunk or Falcon.** They read and they propose.
5. **No model writes a Splunk search.** Search templates are data in the repository.
6. **Secrets stay out of the repository and out of chat.** The lab passwords live in `~/.oaev-lab/splunk-lab.env`.
7. **Push only when the owner says so.** Never touch `.github/workflows`.
8. **People approve.** Scenarios, new actions, detections and learned rules each need a named person.

## Waiting on the owner

| Item | What is needed |
|---|---|
| Proofpoint and Check Point in Splunk | The sourcetype names used at work. Names only, no data |
| The 14 drafts from the real public test library | A person's approval, one by one. All are discovery techniques |
| A real model for the drafter | Which Copilot can be called, and the employer's rules for it. See [COPILOT.md](COPILOT.md) |
| Joining the librarian and drafter to the main run | A go-ahead. Small change, described in COPILOT.md |
| A real endpoint test with OpenAEV's agent | Deliberately last. Needs dedicated test machines and authorisation |

## Not in the repository

| Thing | Where | Recreate it by |
|---|---|---|
| Python environment | `splunk-es/.venv/` | SETUP.md, Level 1 |
| Lab settings (passwords) | `~/.oaev-lab/splunk-lab.env` | SETUP.md, Level 3 |
| Lab Splunk container | Docker in WSL2, name `oaev-lab-splunk` | `validation-ants/lab/lab_up.sh` |
| Real Atomic Red Team index | `~/.oaev-lab/atomic-red-team/index.yaml` | Download from the Atomic Red Team project |

## History

| Commit | What it added |
|---|---|
| `384e822` | Sandbox demo page on the mock harness |
| `67dcea5` | Planner, gatekeeper, observers, analyst, matcher, reporter |
| `0a8670f` | Intel ant and scenario builder |
| `333bf3d` | Blind playground with a referee |
| `a205434` | Detection engineer |
| `c52661c` | Demo page rebuilt: attack library by attack type, job board with live steps |
| `7c0affd` | Lab Splunk check; fix for an index the account may not search |
| `a9a6618` | Email and firewall tests |
| `c760921` | Librarian ant and the ant map |
| `b32ef0c` | Drafter ant, built detections, ant avatars with hover |
| `17684a8` | Librarian measured against the real Atomic Red Team index; rules tightened |
| `bf25015` | Change-and-undo tests (parked) |
| `eb511ba`, `32bd7cc` | These documents; line endings for the lab script |
| `bac84ac` | The ants run without the OpenAEV client, using a stand-in (`ants/oaev_standin.py`) |

## To continue in a new session

Paste this, then say what you want next:

```
Continue the OpenAEV validation-ants work.
Repo: %USERPROFILE%\Downloads\Code\openaev-collectors, branch work
(GitHub: navivan15/openaev-collectors, private).
First read validation-ants/docs/STATUS.md and follow its rules.
Then run the three checks in validation-ants/docs/SETUP.md and tell me the result.
Next I want: <say it here>
```

If the copy on the PC is gone, clone the repository first and follow SETUP.md, Level 1.

### On a machine where the OpenAEV client cannot be installed

For example, a machine whose packages come from a company store that does not carry `pyoaev`. Paste this
instead:

```
Set up the OpenAEV validation ants on this machine.
Repo: navivan15/openaev-collectors (private), branch work.
First read validation-ants/docs/STATUS.md and follow its rules.
Then follow validation-ants/docs/SETUP.md, section
"If the OpenAEV client cannot be installed".
Do not install pyoaev: the ants use a built-in stand-in when it is missing.
Install only requests, pydantic, pydantic-settings and pyyaml,
through the company package store.
Run only: validation-ants/sandbox.py all
Expected first line: OpenAEV client: built-in stand-in (pyoaev is not installed)
Expected last line: 28/28 scenarios passed
Skip the collector harness and pytest. They need the real client and fail here;
that is expected.
Mocks only. Connect to nothing real.
```

Do not work around the package store to get `pyoaev`. If it is wanted later, ask for it to be added.
