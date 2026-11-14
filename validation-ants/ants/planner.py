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


class PlanningError(ValueError):
    """The request cannot be turned into a plan."""


class Planner:
    def __init__(self, catalogue_path: Path | str = CATALOGUE_PATH) -> None:
        data = json.loads(Path(catalogue_path).read_text(encoding="utf-8"))
        self.actions: dict[str, dict[str, Any]] = data["actions"]
        self.tests: dict[str, dict[str, Any]] = {t["id"]: t for t in data["tests"]}
        for test in self.tests.values():
            if test["action"] not in self.actions:
                raise PlanningError(
                    f"Test {test['id']} uses action '{test['action']}', which is "
                    f"not on the allow-list"
                )

    def catalogue(self) -> list[dict[str, Any]]:
        return [
            {**t, "what_it_does": self.actions[t["action"]]["description"]}
            for t in self.tests.values()
        ]

    def plan(self, test_ids: list[str], hosts: list[dict[str, str]]) -> Plan:
        """One step per test per host. ``hosts``: name, source_ip, target_ip."""
        if not test_ids or not hosts:
            raise PlanningError("A plan needs at least one test and one host")
        run_id = str(uuid.uuid4())
        steps: list[Step] = []
        for host in hosts:
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
                steps.append(
                    Step(
                        id=marker,
                        run_id=run_id,
                        test_id=test_id,
                        title=test["title"],
                        technique=test["technique"],
                        action=test["action"],
                        command=action["command"].format(
                            marker=marker, target_ip=host["target_ip"]
                        ),
                        host=host["name"],
                        source_ip=host["source_ip"],
                        target_ip=host["target_ip"],
                        expect=dict(test["expect"]),
                        agentless=bool(action.get("agentless")),
                    )
                )
        return Plan(run_id=run_id, created=datetime.now(timezone.utc), steps=steps)
