# Where Copilot (or any model) connects

**Short answer: one place.** Sixteen of the seventeen ants are fixed rules and use no model. One ant, the drafter,
asks a model for help, and only when the librarian found no public test for a technique. Today that slot holds a
scripted stand-in, so nothing in this repository calls a real model.

**No real model has been connected or tried.** Whether a particular Copilot gives usable answers, or declines to
write such commands at all, is untested.

## The one slot

| | |
|---|---|
| The ant | Drafter, `validation-ants/ants/drafter.py` |
| The slot | The `model` argument of `Drafter(librarian, model, model_name)` |
| What `model` must be | Any Python function that takes the request text and returns the answer text: `def model(text: str) -> str` |
| Where it is filled today | `validation-ants/sandbox.py`, function `s_drafter`: `model = ScriptedModel(MODEL_SCRIPT)` |
| The stand-in | `ScriptedModel` in `sandbox.py`: it answers from a fixed list so a run is repeatable |
| What shows it on the page | The "AI drafter" ant on the ant map, and the "Call the AI drafter" tile |

To connect Copilot, write one function that sends the text to it and returns its reply, and pass that function in
place of `ScriptedModel(MODEL_SCRIPT)`. Nothing else in the ants changes.

## What the model is sent, and what comes back

| | |
|---|---|
| Sent | The ATT&CK technique's id and public name, inside a fixed request (the `REQUEST` text in `drafter.py`). Example: `T1053.005 (Scheduled Task)` |
| Never sent | A scenario name, a host name, a log line, a search, a result, anything from Splunk or Falcon |
| Asked for | One Windows command that uses the same built-in tool as the technique, in a form that only reads |
| Expected back | A small JSON object: `{"command": "...", "why": "..."}`, or `{"command": null, "why": "..."}` to decline |

Because only a public technique id and name go out, no employer data reaches the model through this slot.

## What stops a bad answer

The model is treated as an untrusted source of text.

1. **The answer is data.** Anything that is not the JSON asked for is thrown away (`Drafter.read_answer`).
2. **Same rules as a public test.** The command goes through `librarian.check_command`: an allow-list of read-only
   tools in read-only forms. A refused answer goes back with the reasons, three answers at most (`MAX_TRIES`).
3. **Never asked** about a refused family (credential dumping, log removal and so on), a refused tactic
   (credential access, collection, exfiltration), or a technique the library already covers.
4. **A sandbox trial**, then **a person approves** the draft exactly as it is.
5. **Checked again on every load.** A draft changed after its approval is dropped.

The model cannot approve anything, cannot add to the allow-list, and cannot reach the planner or the gatekeeper.

## Three ways to connect it

Which one fits depends on which Copilot your employer has and what it allows. I have not checked any of them.

### A. Chat window only (works today, no new code, no API key)

For a Copilot that only has a chat window.

1. `Drafter.request(technique, name)` returns the text to paste into the chat.
2. Paste the reply into `Drafter.read_answer(answer)`. It returns the checked command, the model's reason, and any
   problems found by the rules.

```python
from ants.drafter import Drafter

text = Drafter(librarian, model=None, model_name="copilot chat").request("T1053.005", "Scheduled Task")
print(text)                      # paste this into the chat
command, why, problems = Drafter.read_answer(reply_from_the_chat)
```

That checks one answer. To go the whole way to a draft (sandbox trial, approval) with a person as the wire, give
the drafter a function that shows the text and waits for the pasted reply:

```python
def by_hand(text: str) -> str:
    """Untested sketch. The reply has to be pasted on one line."""
    print(text)
    return input("Paste the reply: ")

drafter = Drafter(librarian, by_hand, "Copilot chat, by hand")
result = drafter.draft("T1053.005", "Scheduled Task", "persistence")
```

This is the slowest way and the easiest to get approved.

### B. A model with an API

For a model your employer lets you call from code. The function is the whole integration:

```python
import os
import requests

def copilot(text: str) -> str:
    """Untested sketch. The address, the request shape and the reply shape depend on the service."""
    reply = requests.post(
        os.environ["OAEV_MODEL_URL"],
        headers={"Authorization": "Bearer " + os.environ["OAEV_MODEL_KEY"]},
        json={"messages": [{"role": "user", "content": text}]},
        timeout=60,
    )
    reply.raise_for_status()
    return reply.json()["choices"][0]["message"]["content"]

drafter = Drafter(librarian, copilot, "name of the model")
```

This sketch has never been run. A function that raises an error is handled: the drafter reports
`model not reachable` and the technique stays a gap.

### C. A model your employer hosts

The same as B with a different address. Preferable when the employer wants requests to stay inside its network.

## Rules for the key

- The key and the address come from the environment (`OAEV_MODEL_URL`, `OAEV_MODEL_KEY` in the sketch). Never write
  them into a file in the repository.
- Do not connect an employer's model from a personal PC. Do it on a machine the employer approved.
- Use a key that can do nothing else.

## Questions to ask at work before connecting anything

1. Which Copilot do we have, and can it be called from code or only used through its chat window?
2. Is it allowed to be used for security testing content? Some services refuse requests that mention attack
   techniques, even defensive ones.
3. Does the request leave our network, and is that acceptable for a request holding only a public technique id?
4. Who issues the key, and where may it be stored?

## One more piece of wiring before the model is used in a real run

Today the librarian and the drafter are called from their own scenarios (`sandbox.py librarian` and
`sandbox.py drafter`). A run that starts from an OpenCTI scenario or from a pick in the attack library lists a
technique without an action as `no action` and stops there; it does not call the librarian or the drafter by
itself.

To fill gaps as part of a normal run, one step has to be added where the scenario builder reports its gaps:

```
scenario builder --> gaps --> librarian.fill_gaps(gaps) --> still a gap? --> drafter.draft(...) -->
sandbox trial --> a person approves --> Planner.add_actions(librarian.approved_actions()) --> build again
```

Every piece of that chain exists and is tested on its own (`s_librarian` and `s_drafter` in `sandbox.py` do
exactly this). Joining it to the main run is a small change and has not been made.

## Where a model is not used, on purpose

| Ant | Why no model |
|---|---|
| Query writer, validator | The owner's rule: no model writes a Splunk search. Searches come from proven templates |
| Gatekeeper | What may run is decided by fixed rules and a signature |
| Splunk and Falcon observers, matcher | A verdict must be repeatable and explainable from the marker, the host and the time |
| Planner | A command comes only from the allow-list |
| Reporter | The score is arithmetic |

## Places a model could help later (ideas only, not built, not decided)

Each would have to follow the drafter's pattern: the answer is data, fixed rules check it, a person approves it.

| Idea | What the model would do | The catch |
|---|---|---|
| Detection engineer | Suggest plain words to look for in a missed step's logs. The ant would still test them on the logs and write the search itself | Today the engineer builds these from the test's own command with no model |
| Intel | Read a threat report that has no ATT&CK ids and suggest which techniques it describes | The report text would be sent to the model |
| Reporter | Write a plain-language summary of a run | Results would be sent to the model, which is employer data |

## The other connection points (real systems, not models)

For completeness: these are the places where a real system replaces a mock. None of them is connected. None of
them should be connected from a personal PC.

| System | Where in the code | What it needs | State |
|---|---|---|---|
| Splunk Enterprise | The `SPLUNKES_*` settings given to `SplunkObserver` (see `splunk-es/README.md`): address, a search-only account or a token, `SPLUNKES_ALERTS_INDEX`, `SPLUNKES_LOG_SOURCETYPES` | An account whose only capability is `search`, limited to the indexes it must read | Proven on a lab Splunk with synthetic events. Real sourcetype and field names are unverified |
| CrowdStrike Falcon | `FalconHttpClient(base_url, client_id, client_secret)` in `ants/observers.py` | An API client that can only read alerts | Mock only |
| OpenCTI | `OpenCTIClient(base_url, token)` in `ants/intel.py` | A read-only token | Mock only. The GraphQL query has not been checked against a real OpenCTI |
| The endpoint agent | `SimulatedAgent` in `ants/agent_sim.py`, built in the `Ants` class in `sandbox.py` | OpenAEV's own agent on dedicated test machines | Not started. This is the step where commands would really run, and it is deliberately last |
| OpenAEV | `OPENAEV_URL`, `OPENAEV_TOKEN` for the `splunk-es` collector | A running OpenAEV platform | The collector is tested against a mock OpenAEV |
| Mail gateway and firewall | No connection of their own: their logs are read from Splunk | Their logs forwarded to Splunk | Sourcetype and field names are the add-ons' usual ones, unverified |
