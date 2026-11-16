"""Reporter ant: scorecard for a run, and drift against the previous run.

* **Scorecard.** Counts per outcome and per source. The detection rate is
  (Detected + Prevented) / (Detected + Prevented + Missed): steps that could
  not be checked or were not run are left out of the rate and listed.
* **Drift.** Each (test, host) is compared with the last run in which it got
  a scored outcome. Detected or Prevented before and Missed now is a
  regression. A step that could not be checked is never a regression.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import COULD_NOT_CHECK, DETECTED, MISSED, NOT_RUN, PREVENTED, Step, StepVerdict

SCORED = (DETECTED, PREVENTED, MISSED)
# Which steps each team looks at. Purple team sees the whole chain.
# Which kinds of test each team owns. Email tests sit with SecOps.
TEAM_PROFILES = {"Purple team": None, "SecOps": ("endpoint", "email"), "NetOps": ("network",)}


def team_views(report: dict[str, Any], category_of_test: dict[str, str]) -> list[dict[str, Any]]:
    """The same run, scored for each team's part of it."""
    views = []
    for team, category in TEAM_PROFILES.items():
        steps = [s for s in report["steps"]
                 if category is None or category_of_test.get(s["test_id"]) in category]
        seen = sum(1 for s in steps if s["outcome"] in (DETECTED, PREVENTED))
        scored = sum(1 for s in steps if s["outcome"] in SCORED)
        views.append({
            "team": team, "steps": len(steps), "seen": seen,
            "missed": sum(1 for s in steps if s["outcome"] == MISSED),
            "unchecked": sum(1 for s in steps if s["outcome"] == COULD_NOT_CHECK),
            "detection_rate": round(seen / scored, 3) if scored else None,
            "findings": sum(len(s["findings"]) for s in steps),
        })
    return views
RANK = {MISSED: 0, DETECTED: 1, PREVENTED: 2}


class Reporter:
    def __init__(self, history_path: Path | str) -> None:
        self.history_path = Path(history_path)
        self.history: dict[str, dict[str, Any]] = {}
        if self.history_path.exists():
            self.history = json.loads(self.history_path.read_text(encoding="utf-8"))

    @staticmethod
    def _key(step: Step) -> str:
        return f"{step.test_id}|{step.host.strip().lower()}"

    def report(self, run_id: str, verdicts: list[StepVerdict],
               not_run: list[tuple[Step, str, str]]) -> dict[str, Any]:
        totals = {DETECTED: 0, PREVENTED: 0, MISSED: 0, COULD_NOT_CHECK: 0,
                  NOT_RUN: len(not_run)}
        per_source: dict[str, dict[str, int]] = {}
        drift: list[dict[str, Any]] = []
        today = datetime.now(timezone.utc).date().isoformat()
        for v in verdicts:
            totals[v.outcome] += 1
            for o in v.observations:
                row = per_source.setdefault(o.source, {DETECTED: 0, PREVENTED: 0,
                                                       MISSED: 0, COULD_NOT_CHECK: 0})
                row[o.outcome] += 1
            previous = self.history.get(self._key(v.step))
            partly = any(o.outcome == COULD_NOT_CHECK for o in v.observations)
            if partly and v.outcome in SCORED:
                # One source could not be asked, so this is not comparable with the
                # last run: no regression is reported and the history is kept.
                if previous and previous["outcome"] != v.outcome:
                    drift.append({"test_id": v.step.test_id, "title": v.step.title,
                                  "host": v.step.host, "was": previous["outcome"],
                                  "now": v.outcome + " (partly checked)",
                                  "kind": "unknown", "last_run": previous["on"]})
            elif v.outcome in SCORED:
                if previous and previous["outcome"] != v.outcome:
                    was, now = previous["outcome"], v.outcome
                    kind = ("regression" if RANK[now] < RANK[was] else "improvement")
                    if was == PREVENTED and now == DETECTED:
                        kind = "weaker"
                    drift.append({"test_id": v.step.test_id, "title": v.step.title,
                                  "host": v.step.host, "was": was, "now": now,
                                  "kind": kind, "last_run": previous["on"]})
                self.history[self._key(v.step)] = {"outcome": v.outcome, "on": today,
                                                   "run_id": run_id}
            elif previous:
                drift.append({"test_id": v.step.test_id, "title": v.step.title,
                              "host": v.step.host, "was": previous["outcome"],
                              "now": v.outcome, "kind": "unknown",
                              "last_run": previous["on"]})
        self.history_path.parent.mkdir(parents=True, exist_ok=True)
        self.history_path.write_text(json.dumps(self.history, indent=2), encoding="utf-8")

        scored = totals[DETECTED] + totals[PREVENTED] + totals[MISSED]
        return {
            "run_id": run_id,
            "on": today,
            "totals": totals,
            "scored_steps": scored,
            "detection_rate": (round((totals[DETECTED] + totals[PREVENTED]) / scored, 3)
                               if scored else None),
            "per_source": per_source,
            "steps": [v.to_dict() for v in verdicts],
            "not_run": [{"step_id": s.id, "test_id": s.test_id, "title": s.title,
                         "host": s.host, "reason": reason, "detail": detail}
                        for s, reason, detail in not_run],
            "findings": [{"test_id": v.step.test_id, "host": v.step.host, "finding": f}
                         for v in verdicts for f in v.findings],
            "drift": drift,
            "regressions": [d for d in drift if d["kind"] in ("regression", "weaker")],
        }
