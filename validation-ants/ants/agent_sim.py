"""Simulated endpoint agent for the sandbox. It executes nothing.

In a real deployment this role is OpenAEV's own endpoint agent. Here it only
does two things: ask the gatekeeper for permission, and, if granted, write the
synthetic telemetry that the configured "defences" would have produced for
that step (a Falcon alert, a forwarded copy in Splunk, a Splunk rule hit).
No command is run and no host is touched.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .gatekeeper import Gatekeeper
from .models import Step, implant_name

FMT = "%Y-%m-%dT%H:%M:%S"
RAW_INDEX = "telemetry"   # plain endpoint logs; alerts are in the collector's alerts index
# Falcon pattern_disposition bits (see crowdstrike/pattern_disposition.py)
DISPOSITION_DETECT_ONLY = 0
DISPOSITION_PROCESS_BLOCKED = 2048


@dataclass
class Telemetry:
    """What the mock Splunk and the mock Falcon will answer with."""

    splunk_rows: list[dict[str, Any]] = field(default_factory=list)
    falcon_alerts: list[dict[str, Any]] = field(default_factory=list)


class SimulatedAgent:
    def __init__(
        self,
        gatekeeper: Gatekeeper,
        telemetry: Telemetry,
        defences: dict[str, dict[str, Any]],
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ) -> None:
        self.gatekeeper = gatekeeper
        self.telemetry = telemetry
        self.defences = defences
        self._now = now
        self._counter = 0

    def run(self, step: Step) -> dict[str, Any]:
        """Run one step. Raises gatekeeper.Refused when it is not allowed."""
        entry = self.gatekeeper.authorise(step)  # the only way in
        # Sandbox clock: the step ran a few minutes ago, so its alerts are due.
        step.start = self._now() - timedelta(minutes=4)
        step.end = self._now() - timedelta(minutes=1)
        # A profile for the exact test wins; otherwise the one for its action.
        profile = (self.defences[step.test_id] if step.test_id in self.defences
                   else self.defences.get("action:" + step.action, {}))
        self._emit(step, profile)
        return entry

    def _emit(self, step: Step, profile: dict[str, Any]) -> None:
        assert step.start is not None
        self._counter += 1
        alert_time = (step.start + timedelta(seconds=profile.get("delay", 30))).strftime(FMT)
        marked = profile.get("marker_in_alert", True)
        command = step.command if marked else step.command.split(step.id)[0] + "..."
        parent = implant_name(step.id) if marked else "explorer.exe"
        fqdn = f"{step.host.lower()}.lab.local"

        # The plain endpoint log. It exists whether or not any rule fires, it is not
        # an alert, and it lives in its own index, away from the alerts.
        if not step.agentless:
            self.telemetry.splunk_rows.append({
                "_time": (step.start + timedelta(seconds=5)).strftime(FMT),
                "index": RAW_INDEX, "sourcetype": "XmlWinEventLog:Sysmon", "EventCode": "1",
                "dest_host": fqdn, "process": step.command,
                "parent_process_name": implant_name(step.id),
            })

        falcon = profile.get("falcon")
        composite = f"cid0a1b2c:ind:{step.id[:8]}:{4000 + self._counter}-10357-{self._counter}"
        if falcon in ("detect", "prevent"):
            name = profile.get("falcon_rule", "Suspicious command line")
            self.telemetry.falcon_alerts.append({
                "id": f"ind:{step.id[:8]}:{self._counter}",
                "composite_id": composite,
                "display_name": name,
                "filename": "cmd.exe",
                "cmdline": command,
                "parent_details": {"filename": parent, "cmdline": parent},
                "grandparent_details": {"filename": "services.exe"},
                "device": {"hostname": step.host},
                "pattern_disposition": (DISPOSITION_PROCESS_BLOCKED if falcon == "prevent"
                                        else DISPOSITION_DETECT_ONLY),
                "created_timestamp": alert_time + "Z",
                "updated_timestamp": alert_time + "Z",
            })
            if profile.get("forward", True):
                self.telemetry.splunk_rows.append({
                    "_time": alert_time, "index": "main",
                    "sourcetype": "crowdstrike:events:sensor",
                    "dest_host": fqdn, "event.CompositeId": composite,
                    "rule_name": name, "process": command, "parent_process_name": parent,
                })

        rule = profile.get("splunk_rule")
        if rule:
            row = {
                "_time": alert_time, "index": "main", "sourcetype": rule["sourcetype"],
                "dest_host": fqdn, "rule_name": rule["rule_name"],
            }
            if rule.get("field"):
                row[rule["field"]] = command
            if rule.get("ips"):
                row.update({"src_ip": step.source_ip, "dst_ip": step.target_ip})
            self.telemetry.splunk_rows.append(row)
            if profile.get("noise_before"):
                # The same rule also fires on this host when no test is running.
                quiet = step.start - timedelta(minutes=4)
                noise = dict(row, _time=quiet.strftime(FMT))
                if rule.get("field"):
                    noise[rule["field"]] = "routine admin task"
                self.telemetry.splunk_rows.append(noise)
