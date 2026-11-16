"""Planner ant: turns catalogue tests into a plan of benign, marked steps.

The planner only chooses from the catalogue. It cannot invent an action: every
step's command comes from the action allow-list in catalogue.json with the
step marker filled in. It does not approve anything; that is the gatekeeper.
"""

from __future__ import annotations

import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Plan, Step

CATALOGUE_PATH = Path(__file__).with_name("catalogue.json")


MAILBOX_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}$")


class PlanningError(ValueError):
    """The request cannot be turned into a plan."""


class Planner:
    def __init__(self, catalogue_path: Path | str = CATALOGUE_PATH, reversible: bool = False) -> None:
        data = json.loads(Path(catalogue_path).read_text(encoding="utf-8"))
        self.actions: dict[str, dict[str, Any]] = data["actions"]
        self.technique_names: dict[str, Any] = dict(data.get("techniques", {}))
        if reversible:
            # Change-and-undo actions are off unless a run switches them on. Loading
            # them checks every one against the rules in reversible.py.
            from .reversible import load_reversible

            extra, names = load_reversible()
            for action_id in extra:
                if action_id in self.actions:
                    raise PlanningError(f"Action '{action_id}' is defined twice")
            self.actions.update(extra)
            self.technique_names.update(names)
        self.not_simulated: dict[str, str] = data.get("not_simulated", {})
        self.tests: dict[str, dict[str, Any]] = {t["id"]: t for t in data["tests"]}
        for test in self.tests.values():
            if test["action"] not in self.actions:
                raise PlanningError(
                    f"Test {test['id']} uses action '{test['action']}', which is "
                    f"not on the allow-list"
                )

    def add_actions(self, actions: dict[str, dict[str, Any]]) -> list[str]:
        """Put actions a person approved (see librarian.py) on the allow-list.

        The planner only checks their shape. Whether they are harmless, and that
        a person approved exactly these, is the librarian's job before it hands
        them over. Returns the ids added.
        """
        added = []
        for action_id, action in actions.items():
            if not re.match(r"^[a-z0-9_]{3,64}$", str(action_id)):
                raise PlanningError(f"'{action_id}' is not an action id")
            if action_id in self.actions:
                raise PlanningError(f"Action '{action_id}' is already in the library")
            techniques = action.get("techniques") or []
            if not techniques or "{marker}" not in str(action.get("command") or ""):
                raise PlanningError(f"Action '{action_id}' has no technique or no marker")
            for technique in techniques:
                if technique in self.not_simulated or technique.split(".", 1)[0] in self.not_simulated:
                    raise PlanningError(
                        f"Action '{action_id}' is for {technique}, a family the ants refuse")
            self.actions[action_id] = action
            added.append(action_id)
        return added

    def use_scenario(self, scenario: dict[str, Any]) -> list[str]:
        """Make an approved scenario's tests plannable. Returns their ids in order.

        Refuses a draft, and refuses a scenario whose tests changed after it
        was approved.
        """
        from .scenario_builder import tests_digest

        if scenario.get("status") != "approved" or not scenario.get("approved_by"):
            raise PlanningError(f"Scenario '{scenario.get('id')}' has not been approved")
        if scenario.get("approved_digest") != tests_digest(scenario.get("tests") or []):
            raise PlanningError(f"Scenario '{scenario.get('id')}' was changed after approval")
        ids = []
        for test in scenario["tests"]:
            if test.get("action") not in self.actions:
                raise PlanningError(f"Test {test.get('id')} uses an action that is not "
                                    f"on the allow-list")
            self.tests[test["id"]] = test
            ids.append(test["id"])
        return ids

    def catalogue(self) -> list[dict[str, Any]]:
        return [
            {**t, "what_it_does": self.actions[t["action"]]["description"]}
            for t in self.tests.values()
        ]

    def plan(self, test_ids: list[str], hosts: list[dict[str, str]]) -> Plan:
        """One step per test per host. ``hosts``: name, source_ip, target_ip."""
        if not test_ids or not hosts:
            raise PlanningError("A plan needs at least one test and one host")
        return self.plan_pairs([(t, h) for h in hosts for t in test_ids])

    def plan_pairs(self, pairs: list[tuple[str, dict[str, str]]]) -> Plan:
        """One step per (test, host) pair, in the order given."""
        if not pairs:
            raise PlanningError("A plan needs at least one test and one host")
        run_id = str(uuid.uuid4())
        steps: list[Step] = []
        for test_id, host in pairs:
            test_ids = [test_id]
            if not re.match(r"^[A-Za-z0-9]([A-Za-z0-9\-.]{0,251}[A-Za-z0-9])?$",
                            str(host.get("name", ""))):
                raise PlanningError(f"'{host.get('name')}' is not a host name")
            for key in ("source_ip", "target_ip"):
                try:
                    if str(ipaddress.ip_address(str(host.get(key)))) != host.get(key):
                        raise ValueError
                except ValueError:
                    raise PlanningError(f"{key} '{host.get(key)}' is not an IP address")
            for test_id in test_ids:
                test = self.tests.get(test_id)
                if test is None:
                    raise PlanningError(f"Unknown test '{test_id}'")
                action = self.actions[test["action"]]
                marker = str(uuid.uuid4())
                mailbox = str(host.get("mailbox") or "")
                if "{mailbox}" in action["command"] and not MAILBOX_RE.match(mailbox):
                    raise PlanningError(
                        f"Test {test_id} sends an email, and '{host['name']}' has no "
                        f"test mailbox to send it to"
                    )
                steps.append(
                    Step(
                        id=marker,
                        run_id=run_id,
                        test_id=test_id,
                        title=test["title"],
                        technique=test["technique"],
                        action=test["action"],
                        command=action["command"].format(
                            marker=marker, target_ip=host["target_ip"], mailbox=mailbox
                        ),
                        host=host["name"],
                        source_ip=host["source_ip"],
                        target_ip=host["target_ip"],
                        expect=dict(test["expect"]),
                        agentless=bool(action.get("agentless")),
                        channel=str(action.get("category") or "endpoint"),
                        reversible=bool(action.get("reversible")),
                        cleanup=(action["cleanup"].format(marker=marker)
                                 if action.get("reversible") else None),
                        verify=(action["verify"].format(marker=marker)
                                if action.get("reversible") else None),
                    )
                )
        return Plan(run_id=run_id, created=datetime.now(timezone.utc), steps=steps)
