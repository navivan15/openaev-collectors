"""Scenario builder ant: turns a threat's techniques into a draft test scenario.

For each ATT&CK technique the intel ant found, it looks for an action on the
allow-list (catalogue.json) that is mapped to exactly that technique:

* simulated     - an action exists and behaves like the technique.
* partial       - an action exists but only runs the same tool read-only,
                  because the real technique would change the system.
* not simulated - the technique is on the "cannot be done harmlessly" list.
* no action     - nothing in the library covers it yet.

It never writes a command. Covering more techniques means adding a reviewed
action to the allow-list, not making the builder more inventive.

The result is a **draft**. Nobody can plan it until a person approves it, and
the approval is bound to the exact list of tests: a scenario edited after
approval is refused by the planner. The gatekeeper still checks every step.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .intel import Threat


class ScenarioError(ValueError):
    """The scenario cannot be built, approved or used."""


def tests_digest(tests: list[dict[str, Any]]) -> str:
    return hashlib.sha256(json.dumps(tests, sort_keys=True).encode()).hexdigest()


class ScenarioBuilder:
    def __init__(self, actions: dict[str, dict[str, Any]], not_simulated: dict[str, str],
                 store_dir: Path | str) -> None:
        self.actions = actions
        self.not_simulated = not_simulated
        self.store_dir = Path(store_dir)

    def _path(self, scenario_id: str) -> Path:
        if not re.match(r"^[a-z0-9][a-z0-9\-]{0,60}$", scenario_id):
            raise ScenarioError(f"'{scenario_id}' is not a scenario id")
        return self.store_dir / f"{scenario_id}.json"

    def draft(self, threat: Threat) -> dict[str, Any]:
        """Build a draft scenario and its coverage table. Saves it as a draft."""
        slug = re.sub(r"[^a-z0-9]+", "-", threat.name.lower()).strip("-")[:40] or "scenario"
        tests: list[dict[str, Any]] = []
        coverage: list[dict[str, Any]] = []
        for tech in threat.techniques:
            row = {"technique": tech.id, "name": tech.name, "tactic": tech.tactic}
            action_id = next((name for name, a in self.actions.items()
                              if tech.id in a.get("techniques", [])), None)
            parent = tech.id.split(".", 1)[0]
            if action_id:
                action = self.actions[action_id]
                partial = action.get("fidelity") == "partial"
                tests.append({
                    "id": f"{slug}-{tech.id}", "title": f"{tech.id} {tech.name}",
                    "technique": tech.id, "tactic": tech.tactic, "action": action_id,
                    "expect": dict(action.get("expect") or {"splunk": "detection"}),
                })
                coverage.append({**row, "status": "partial" if partial else "simulated",
                                 "action": action_id, "why": action["description"]})
            elif tech.id in self.not_simulated or parent in self.not_simulated:
                coverage.append({**row, "status": "not simulated", "action": None,
                                 "why": self.not_simulated.get(tech.id)
                                 or self.not_simulated[parent]})
            else:
                coverage.append({**row, "status": "no action", "action": None,
                                 "why": "No reviewed action in the library covers this "
                                        "technique yet."})
        if not tests:
            raise ScenarioError("No technique of this threat has a reviewed action")
        scenario = {
            "id": slug, "name": threat.name, "status": "draft",
            "source": {"opencti_id": threat.id, "kind": threat.kind},
            "created": datetime.now(timezone.utc).isoformat(),
            "tests": tests, "coverage": coverage,
            "skipped_patterns": list(threat.skipped),
        }
        self.save(scenario)
        return scenario

    def save(self, scenario: dict[str, Any]) -> None:
        self.store_dir.mkdir(parents=True, exist_ok=True)
        self._path(scenario["id"]).write_text(json.dumps(scenario, indent=2), encoding="utf-8")

    def load(self, scenario_id: str) -> dict[str, Any]:
        path = self._path(scenario_id)
        if not path.exists():
            raise ScenarioError(f"There is no scenario '{scenario_id}'")
        return json.loads(path.read_text(encoding="utf-8"))

    def approve(self, scenario_id: str, by: str) -> dict[str, Any]:
        """A person approves the draft exactly as it is now."""
        if not by or not by.strip():
            raise ScenarioError("An approval needs a person")
        scenario = self.load(scenario_id)
        for test in scenario["tests"]:
            if test.get("action") not in self.actions:
                raise ScenarioError(f"Test {test.get('id')} uses an action that is not "
                                    f"on the allow-list")
        scenario.update(status="approved", approved_by=by.strip(),
                        approved_at=datetime.now(timezone.utc).isoformat(),
                        approved_digest=tests_digest(scenario["tests"]))
        self.save(scenario)
        return scenario
