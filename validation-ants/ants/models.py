"""Shared data shapes for the validation ants."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from dataclasses import field as _field
from datetime import datetime
from typing import Any

# The four outcomes. Same words as the splunk-es collector's Outcome enum.
DETECTED = "Detected"
PREVENTED = "Prevented"
MISSED = "Missed"
COULD_NOT_CHECK = "Could not check"
# Not an outcome: the step never ran, so there is nothing to score.
NOT_RUN = "Not run"

# How the simulated implant is named; the step id sits where OpenAEV puts the
# inject id, so the collectors read it as the step marker.
AGENT_ID = "22222222-2222-2222-2222-222222222222"


def implant_name(step_id: str) -> str:
    return f"oaev-implant-{step_id}-agent-{AGENT_ID}"


@dataclass
class Step:
    """One benign test step on one host."""

    id: str  # the step marker (a UUID, new for every run)
    run_id: str
    test_id: str  # stable id of the test in the catalogue
    title: str
    technique: str
    action: str  # key of a benign action on the allow-list
    command: str  # what the agent is asked to do; carries the marker
    host: str
    source_ip: str
    target_ip: str
    expect: dict[str, str] = _field(default_factory=dict)  # source -> detection|prevention
    agentless: bool = False  # no agent on the host, so no marker in telemetry
    signature: str | None = None  # set by the gatekeeper
    signed_by: str | None = None
    start: datetime | None = None  # set when the agent runs it
    end: datetime | None = None

    def signed_fields(self) -> dict[str, Any]:
        """The fields a signature covers. Changing any of them voids it."""
        return {
            k: getattr(self, k)
            for k in ("id", "run_id", "test_id", "action", "command", "host",
                      "source_ip", "target_ip")
        }

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Plan:
    run_id: str
    created: datetime
    steps: list[Step]


@dataclass
class Observation:
    """What one telemetry source says about one step."""

    step_id: str
    source: str  # "splunk" | "falcon"
    outcome: str
    reason: str | None = None
    method: str | None = None  # step_marker | legacy | learned_rule
    field: str | None = None
    search_path: str | None = None
    needs_confirmation: bool = False
    evidence: dict[str, Any] = _field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class StepVerdict:
    """The fused result for one step across all sources."""

    step: Step
    outcome: str
    reason: str | None
    observations: list[Observation]
    sightings: int = 0  # distinct detections after counting forwarded alerts once
    findings: list[str] = _field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step.id,
            "test_id": self.step.test_id,
            "title": self.step.title,
            "host": self.step.host,
            "outcome": self.outcome,
            "reason": self.reason,
            "sightings": self.sightings,
            "findings": self.findings,
            "observations": [o.to_dict() for o in self.observations],
        }
