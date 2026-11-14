"""Matcher ant: fuses what the observers saw into one verdict per step.

Order of trust:

1. **Step marker** (done by the observers): an alert carrying the marker.
2. **Learned rule**: only when a source reports Missed. If purple team has
   confirmed, at least ``min_confirmations`` times, that a named rule is what
   detects this test in this source, an alert from that rule on the step's
   host inside the step's window counts - unless the same rule also fired on
   that host in the quiet window before the step, in which case it is treated
   as background noise. A learned-rule match is always flagged for
   confirmation; it never becomes a trusted rule by itself.

It also counts one detection once: a Falcon alert and its forwarded copy in
Splunk share the Falcon alert id.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from .models import (
    COULD_NOT_CHECK,
    DETECTED,
    MISSED,
    PREVENTED,
    Observation,
    Step,
    StepVerdict,
)

Candidates = Callable[[list[str], datetime, datetime], list[dict[str, Any]]]
_UUID = r"[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}"
_MARKER_RE = re.compile(r"oaev-(?:step|implant)-(" + _UUID + ")", re.IGNORECASE)


def _foreign_marker(candidate: dict[str, Any], step: Step) -> bool:
    """True when the alert carries the marker of a different step."""
    own = step.id.replace("-", "").lower()
    found = [m.replace("-", "").lower()
             for m in _MARKER_RE.findall(str(candidate.get("text") or ""))]
    return any(m != own for m in found)


def _alert_key(candidate: dict[str, Any]) -> str:
    e = candidate.get("evidence") or {}
    return str(e.get("falcon_alert_id")
               or (e.get("index"), e.get("sourcetype"), e.get("rule_name"), e.get("time"),
                   tuple(candidate.get("hosts") or [])))


def _short(host: str) -> str:
    return host.strip().lower().split(".", 1)[0]


class RuleBook:
    """Rules confirmed by purple team as the detection for a test in a source."""

    def __init__(self, path: Path | str, min_confirmations: int = 2) -> None:
        self.path = Path(path)
        self.min_confirmations = min_confirmations
        self.rules: dict[str, list[dict[str, Any]]] = {}
        if self.path.exists():
            self.rules = json.loads(self.path.read_text(encoding="utf-8")).get("rules", {})

    @staticmethod
    def _key(test_id: str, source: str) -> str:
        return f"{test_id}|{source}"

    def confirm(self, test_id: str, source: str, rule_name: str, by: str) -> int:
        """Record one human confirmation. Returns the rule's confirmation count."""
        if not rule_name or not by:
            raise ValueError("A confirmation needs a rule name and a person")
        entries = self.rules.setdefault(self._key(test_id, source), [])
        entry = next((e for e in entries if e["rule_name"] == rule_name), None)
        if entry is None:
            entry = {"rule_name": rule_name, "confirmations": 0, "confirmed_by": []}
            entries.append(entry)
        if by not in entry["confirmed_by"]:      # one person counts once
            entry["confirmed_by"].append(by)
        entry["confirmations"] = len(entry["confirmed_by"])
        entry["last_confirmed"] = datetime.now(timezone.utc).date().isoformat()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"version": 1, "rules": self.rules}, indent=2),
                             encoding="utf-8")
        return int(entry["confirmations"])

    def trusted(self, test_id: str, source: str) -> set[str]:
        return {e["rule_name"] for e in self.rules.get(self._key(test_id, source), [])
                if e["confirmations"] >= self.min_confirmations}


class Matcher:
    def __init__(self, rulebook: RuleBook, before: timedelta = timedelta(minutes=1),
                 after: timedelta = timedelta(minutes=5),
                 quiet_gap: timedelta = timedelta(minutes=1)) -> None:
        self.rulebook = rulebook
        self.before, self.after, self.quiet_gap = before, after, quiet_gap

    # -- learned rules -------------------------------------------------------

    def _apply_learned_rule(self, step: Step, obs: Observation,
                            candidates: Candidates | None,
                            claimed: set[str]) -> Observation:
        trusted = self.rulebook.trusted(step.test_id, obs.source)
        if obs.outcome != MISSED or not trusted or candidates is None:
            return obs
        if not (step.start and step.end):
            return obs
        window = (step.start - self.before, step.end + self.after)
        # The quiet window is as long as the match window, so the comparison is fair.
        span = max(window[1] - window[0], timedelta(minutes=5))
        quiet = (window[0] - self.quiet_gap - span, window[0] - self.quiet_gap)
        try:
            found = candidates([step.host], quiet[0], window[1])
        except Exception as e:
            # Without a complete list the quiet window cannot be judged: stay Missed.
            obs.evidence["learned_rule_rejected"] = f"the alerts around the step could not be listed ({e})"
            return obs
        host = _short(step.host)
        mine = [c for c in found if c.get("rule_name") in trusted
                and host in (c.get("hosts") or []) and c.get("time")]
        in_quiet = [c for c in mine if quiet[0] <= c["time"] < quiet[1]]
        # An alert that carries another step's marker, or that another step has
        # already been matched to, is not evidence for this step.
        in_window = [c for c in mine if window[0] <= c["time"] <= window[1]
                     and not _foreign_marker(c, step) and _alert_key(c) not in claimed]
        if not in_window:
            return obs
        if in_quiet:
            obs.evidence["learned_rule_rejected"] = (
                f"rule '{in_quiet[0]['rule_name']}' also fired on this host in the "
                f"quiet window before the step"
            )
            return obs
        hit = in_window[0]
        claimed.add(_alert_key(hit))
        return Observation(
            step_id=step.id, source=obs.source,
            outcome=PREVENTED if hit["evidence"].get("prevented") else DETECTED,
            method="learned_rule", needs_confirmation=True, search_path=obs.search_path,
            evidence={**hit["evidence"], "replaced_reason": obs.reason},
        )

    # -- fusion ------------------------------------------------------------------

    def fuse(self, steps: list[Step], observations: list[Observation],
             candidates: dict[str, Candidates]) -> list[StepVerdict]:
        by_step: dict[str, list[Observation]] = {}
        for obs in observations:
            by_step.setdefault(obs.step_id, []).append(obs)
        # Alerts already tied to a step by its marker cannot be claimed by another.
        claimed = {str(o.evidence.get("falcon_alert_id")) for o in observations
                   if o.outcome in (DETECTED, PREVENTED) and o.evidence.get("falcon_alert_id")}
        verdicts = []
        for step in steps:
            seen = by_step.get(step.id, [])
            # A source that was expected but gave no answer was not checked.
            for source in step.expect:
                if not any(o.source == source for o in seen):
                    seen.append(Observation(step.id, source, COULD_NOT_CHECK, "no_observer"))
            obs_list = [self._apply_learned_rule(step, o, candidates.get(o.source), claimed)
                        for o in seen]
            verdicts.append(self._verdict(step, obs_list))
        return verdicts

    @staticmethod
    def _verdict(step: Step, obs_list: list[Observation]) -> StepVerdict:
        hits = [o for o in obs_list if o.outcome in (DETECTED, PREVENTED)]
        # Count once: a Falcon alert and its forwarded copy share an id.
        ids = {o.evidence.get("falcon_alert_id") or f"{o.source}:{o.step_id}" for o in hits}
        by_source = {o.source: o for o in obs_list}
        findings: list[str] = []
        falcon, splunk = by_source.get("falcon"), by_source.get("splunk")
        if falcon and splunk and falcon.outcome in (DETECTED, PREVENTED) \
                and splunk.outcome == MISSED:
            findings.append("log pipeline gap: Falcon raised an alert that was not found in Splunk")
        for o in obs_list:
            if step.expect.get(o.source) == "prevention" and o.outcome == DETECTED:
                findings.append(f"prevention gap: {o.source} detected the step but did not block it")
            if o.needs_confirmation:
                findings.append(f"needs confirmation: {o.source} match came from a learned rule "
                                f"('{o.evidence.get('rule_name')}'), not from the marker")
            if o.method == "legacy" and o.outcome == DETECTED and step.agentless:
                findings.append(f"weak match: {o.source} matched on addresses only, "
                                f"with no step marker; confirm it by hand")
            if o.evidence.get("learned_rule_rejected"):
                findings.append(f"learned rule not used in {o.source}: "
                                f"{o.evidence['learned_rule_rejected']}")
        unchecked = [o for o in obs_list if o.outcome == COULD_NOT_CHECK]
        if hits and unchecked:
            findings.append("partly checked: " + ", ".join(
                f"{o.source} could not be checked ({o.reason})" for o in unchecked))

        if any(o.outcome == PREVENTED for o in obs_list):
            outcome, reason = PREVENTED, None
        elif hits:
            outcome, reason = DETECTED, None
        elif unchecked or not obs_list:
            # No source saw it, and at least one could not be asked: unknown, not a miss.
            outcome = COULD_NOT_CHECK
            reason = unchecked[0].reason if unchecked else "no_observer"
        else:
            outcome, reason = MISSED, obs_list[0].reason
        return StepVerdict(step=step, outcome=outcome, reason=reason,
                           observations=obs_list, sightings=len(ids), findings=findings)
