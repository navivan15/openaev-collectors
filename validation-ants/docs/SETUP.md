# Setup: from a fresh copy to everything running

Written for Windows 11, which is where this was built. Commands are for PowerShell unless marked otherwise, and are
run from the repository root.

There are three levels. Each one is complete on its own.

| Level | What you get | Needs | Time |
|---|---|---|---|
| 1. Python only | All 28 + 40 mock scenarios and the unit tests | Python 3.11 to 3.13 | About 5 minutes |
| 2. Front end | The demo page: attack library, sandbox, ant map | Level 1 | 1 minute |
| 3. Lab Splunk | 36 checks against a real Splunk Enterprise | Level 1, plus WSL2 with Docker | About 20 minutes the first time |

**Nothing in any level touches a real system.** Level 1 and 2 use mock servers on `127.0.0.1`. Level 3 uses a
Splunk container on `127.0.0.1` with events the script makes up.

## Level 1: Python only

### 1. Get the code

```powershell
git clone https://github.com/navivan15/openaev-collectors.git
cd openaev-collectors
git checkout work
```

The repository is private. All of this work is on the branch `work`, not on `main`.

### 2. Make the Python environment

The ants reuse the `splunk-es` collector's environment, so it is made inside `splunk-es`.

```powershell
cd splunk-es
py -3.12 -m venv .venv
.\.venv\Scripts\python -m pip install "pyoaev==2.260704.0" "requests~=2.33.0" "pydantic>=2.11.7" "pydantic-settings>=2.11.0" pyyaml "pytest>=9" "polyfactory>=2.22.2"
cd ..
```

`pyoaev` is OpenAEV's own Python client; the collector code needs it even on mocks. The `.venv` folder is not
committed, so this step is needed on every fresh copy.

The newest client also works: `pyoaev 3.261116.1` gives the same results as the pinned `2.260704.0` on every
mock check (tried 2026-11-18). Python 3.11 is the oldest version `pyoaev` supports; only 3.12 was tried here.

#### If the OpenAEV client cannot be installed

On a machine where `pyoaev` is not available (for example, a company package store that does not carry it),
leave it out. The ants then use a small stand-in for it that is part of this repository
(`ants/oaev_standin.py`).

```powershell
cd splunk-es
py -3.12 -m venv .venv
.\.venv\Scripts\python -m pip install "requests~=2.33.0" "pydantic>=2.11.7" "pydantic-settings>=2.11.0" pyyaml
cd ..
.\splunk-es\.venv\Scripts\python validation-ants\sandbox.py all
```

Expected: the first line says `OpenAEV client: built-in stand-in (pyoaev is not installed)`, and the last line
says `28/28 scenarios passed`.

| Works without the client | Still needs the real client |
|---|---|
| All 28 ants scenarios (`sandbox.py all`) | The collector harness (`mock_e2e_harness.py`, 40 scenarios) |
| The blind playground (`sandbox.py playground_many 100`) | The collector's unit tests (`pytest`) |
| The demo page server starts and shows the attack library | The collector itself, and anything that reports to a real OpenAEV |

Not tried without the client: running a job from the demo page, and the lab Splunk checks. Both go through
the same code as the 28 scenarios, so they are expected to work.

The stand-in is our own code, not a copy of the client. It covers only the five pieces the ants borrow, and it
cannot talk to an OpenAEV platform. Where the real client is installed, the real client is always used. On a
machine that has the real client, this compares the two piece by piece:

```powershell
.\splunk-es\.venv\Scripts\python validation-ants\check_standin.py
```

Expected last line: `no differences`.

### 3. Check that everything works

```powershell
.\splunk-es\.venv\Scripts\python validation-ants\sandbox.py all
```

Expected last line: `28/28 scenarios passed`.

```powershell
cd splunk-es
.\.venv\Scripts\python harness\mock_e2e_harness.py all
.\.venv\Scripts\python -m pytest -q -p no:logging
cd ..
```

Expected: `40/40 scenarios passed`, then `102 passed` and `1 failed`. That one failure
(`test_collector_config_missing_required_values`) was there before this work. The unit tests take about three
minutes.

```powershell
.\splunk-es\.venv\Scripts\python validation-ants\sandbox.py playground_many 100
```

Expected: a tally with no wrong calls. This takes a few minutes.

What each scenario checks is in [SCENARIOS.md](SCENARIOS.md).

## Level 2: the front end

```powershell
cd splunk-es
.\.venv\Scripts\python harness\demo_server.py 8140
```

Then open <http://127.0.0.1:8140>. The server listens on this machine only and answers only its own page. Leave the
window open; close it to stop the server. What the page shows is in [FRONT-END.md](FRONT-END.md).

The server reads the scenario list and the attack library once, when it starts. After a change to
`ants/catalogue.json` or to a scenario list, stop it and start it again.

## Level 3: the lab Splunk

This is optional. It exists because a mock can only prove what its author assumed; the lab found two real faults.

### What you need

- WSL2 with a Linux distribution (Ubuntu was used) and Docker inside it.
- A few GB of free disk for the Splunk image.
- To accept Splunk's licence terms for the container image. That is your decision to make, not a default.

### 1. Make the settings file, outside the repository

The lab script reads its passwords from a file that is never committed: `~/.oaev-lab/splunk-lab.env` in your
Windows user folder (or the path in the `OAEV_LAB_ENV` variable). It holds these lines:

| Line | What it is |
|---|---|
| `SPLUNK_PASSWORD=` | The lab admin password. Make up a long random one |
| `SPLUNK_HEC_TOKEN=` | The event collector token. A random UUID |
| `SPLUNK_START_ARGS=--accept-license` | Accepts Splunk's licence |
| `SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com` | Accepts Splunk's general terms |
| `SPLUNK_READER_PASSWORD=` | Leave this line out. The lab script adds it the first time it makes the read-only account |

Use these for the lab only. Never put a real Splunk password in this file.

### 2. Keep WSL awake

WSL shuts down when nothing is using it, and that stops the container. Open one terminal and leave it running:

```powershell
wsl -d Ubuntu -- sleep 86400
```

### 3. Start the container

In a second terminal (replace `<you>` with your Windows user name):

```powershell
wsl -d Ubuntu -- bash /mnt/c/Users/<you>/Downloads/Code/openaev-collectors/validation-ants/lab/lab_up.sh /mnt/c/Users/<you>/.oaev-lab/splunk-lab.env
```

Wait for `state=running health=healthy`. The first start downloads the image and takes several minutes. Later
starts are `wsl -d Ubuntu -- docker start oaev-lab-splunk`.

The container listens on this machine only:

| Port | What |
|---|---|
| `127.0.0.1:8000` | Splunk's web page |
| `127.0.0.1:8089` | Management (where searches are sent) |
| `127.0.0.1:18088` | Event collector (where the script sends its made-up events) |

Run this from PowerShell, not from Git Bash: Git Bash rewrites the `/mnt/c/...` paths.

### 4. Run the lab checks

```powershell
.\splunk-es\.venv\Scripts\python validation-ants\lab_splunk.py
```

Expected: 36 checks, none marked `differs`. The script creates the indexes it needs (`telemetry`, `email`,
`netfw`), the read-only role `oaev_reader` and the account `svc_oaev_reader`, all inside the lab container.

### 5. Stop it

```powershell
wsl -d Ubuntu -- docker stop oaev-lab-splunk
```

Then close the `sleep` terminal.

## Settings in one place

| Setting | Used by | Meaning |
|---|---|---|
| `SANDBOX_PORT_BASE` | `sandbox.py` | First of three mock ports (default 18189) |
| `SANDBOX_CUSTOM` | `sandbox.py custom` | The attack-library pick, as JSON |
| `PLAYGROUND_SEED` | `sandbox.py playground` | Repeat one blind run |
| `OAEV_FORCE_STANDIN` | the ants | Set to `1` to use the stand-in for the OpenAEV client even where the real client is installed (for testing the stand-in) |
| `HARNESS_SPLUNK_PORT`, `HARNESS_OPENAEV_PORT` | `mock_e2e_harness.py` | Mock ports (defaults 18089, 18080) |
| `HARNESS_EVENTS_STREAM` | both | A file the run writes its events to, one JSON line each; the demo page reads it |
| `OAEV_LAB_ENV` | `lab_splunk.py` | Path of the lab settings file |
| `OAEV_LAB_REPORT` | `lab_splunk.py` | Write the lab findings to this JSON file |
| `SPLUNKES_*` | the `splunk-es` collector | The collector's own settings; see `splunk-es/README.md` |

## Things that tripped me up, so they do not trip you

| Symptom | Cause | Fix |
|---|---|---|
| The lab container shows `Exited (255)` | WSL shut down while idle | Keep the `sleep` terminal open, then `docker start` |
| `/mnt/c/...` becomes `C:/Program Files/Git/mnt/c/...` | Git Bash rewrote the path | Use PowerShell for `wsl` commands |
| The demo page does not show a new action | The server read the library at start | Restart `demo_server.py` |
| A lab check picks up another check's firewall log | A real Splunk keeps earlier runs' logs, and a plain connection has no marker | Known limit; the lab groups use separate addresses |
| A Python script written from a shell has its backslashes halved | A here-document in Git Bash | Write the file with an editor |

## What is not in the repository, on purpose

| Thing | Where it was | Why it is not committed |
|---|---|---|
| The Python environment | `splunk-es/.venv/` | Rebuilt with one command |
| The lab settings file | `~/.oaev-lab/splunk-lab.env` | It holds passwords |
| The real Atomic Red Team index | `~/.oaev-lab/atomic-red-team/index.yaml` | 6.8 MB of someone else's data; download it again from the Atomic Red Team project when needed. It is read as data and nothing in it is ever run |
