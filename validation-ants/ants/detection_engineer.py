"""Detection engineer ant: for each missed step, tests a reviewed detection and
writes a proposal for a person.

What it does, per run:

1. Takes the steps the run scored as Missed.
2. Looks up reviewed detections for each step's ATT&CK technique in
   detections.json. It never invents one.
3. Reads the plain endpoint logs around the run and for the day before
   (through the collector's checked search), strips every test marker from
   them, and evaluates each detection on what is left. So a detection only
   counts when it catches the *behaviour*.
4. Records for each detection: which missed steps it catches, and how often it
   would also have fired on ordinary activity in the day before (noise).
5. Writes a proposal: ready for review, too noisy, or does not catch.

What it never does: change Splunk or Falcon. A proposal moves on only when a
person approves it, and it counts as deployed only when a person records that
they deployed it. Blocking (prevention) is only ever advice here.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from .models import MISSED, Step, StepVerdict

LIBRARY_PATH = Path(__file__).with_name("detections.json")
MARKER_TEXT_RE = re.compile(
    r"oaev-(?:step|implant)-[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}"
    r"(?:-agent-[0-9a-f\-]{36})?", re.IGNORECASE)
_TERM_RE = re.compile(r"^[A-Za-z0-9 /\-._]+$")


class DetectionError(ValueError):
    """A detection or a proposal step was refused."""


def strip_markers(text: str) -> str:
    """Remove every test marker, so a detection cannot lean on it."""
    return MARKER_TEXT_RE.sub(" ", text or "")


def _has(text: str, terms: list[str]) -> bool:
    low = text.lower()
    return all(t.lower() in low for t in terms)


def evaluate(detection: dict[str, Any], events: list[dict[str, Any]]) -> set[int]:
    """Indexes of the events a detection fires on. Events: time, host, text."""
    if detection["kind"] == "single":
        return {i for i, e in enumerate(events) if _has(e["text"], detection["all"])}
    hits: set[int] = set()
    by_host: dict[str, list[tuple[datetime, int, int]]] = {}
    for i, e in enumerate(events):
        tool = next((n for n, terms in enumerate(detection["tools"]) if _has(e["text"], terms)), None)
        if tool is not None and e.get("time"):
            by_host.setdefault(e.get("host") or "", []).append((e["time"], i, tool))
    span = timedelta(seconds=int(detection["within_seconds"]))
    for rows in by_host.values():
        rows.sort()
        for start, (t0, _, _) in enumerate(rows):
            window = [r for r in rows[start:] if r[0] - t0 <= span]
            if len({tool for _, _, tool in window}) >= int(detection["min_distinct"]):
                hits.update(i for _, i, _ in window)
    return hits


def render_spl(detection: dict[str, Any], index: str) -> str:
    """A starting-point search for the reviewer, built from the same logic."""
    def clause(terms: list[str]) -> str:
        return " ".join(f'process="*{t}*"' for t in terms)

    base = f'index={index} sourcetype="{detection["sourcetype"]}"'
    if detection["kind"] == "single":
        return (f"{base} {clause(detection['all'])} earliest=-15m latest=now "
                f"| stats count by dest_host, process")
    tools = " OR ".join(f"({clause(t)})" for t in detection["tools"])
    minutes = max(1, int(detection["within_seconds"]) // 60)
    return (f"{base} ({tools}) earliest=-{minutes}m latest=now "
            f"| stats dc(process) as tools, count by dest_host "
            f"| where tools >= {int(detection['min_distinct'])}")


class DetectionEngineer:
    def __init__(
        self,
        raw_events: Callable[[list[str], datetime, datetime], list[dict[str, Any]]],
        validate_spl: Callable[[str], None],
        raw_index: str,
        store_path: Path | str,
        library_path: Path | str = LIBRARY_PATH,
        baseline: timedelta = timedelta(hours=24),
        max_noise: int = 0,
    ) -> None:
        data = json.loads(Path(library_path).read_text(encoding="utf-8"))
        self.detections: list[dict[str, Any]] = data["detections"]
        self.no_behaviour: dict[str, str] = data.get("no_behaviour", {})
        self.raw_events = raw_events
        self.raw_index = raw_index
        self.store_path = Path(store_path)
        self.baseline = baseline
        self.max_noise = max_noise
        for det in self.detections:
            terms = det.get("all") or [t for tool in det.get("tools", []) for t in tool]
            if not terms:
                raise DetectionError(f"{det.get('id')}: a detection needs something to look for")
            for term in terms:
                if "oaev" in term.lower():
                    raise DetectionError(
                        f"{det['id']}: a detection must key on the behaviour, not on the "
                        f"test marker")
                if not _TERM_RE.match(term):
                    raise DetectionError(f"{det['id']}: term '{term}' is not a plain term")
            det["spl"] = render_spl(det, raw_index)
            validate_spl(det["spl"])            # same validator as every collector search

    # -- store ----------------------------------------------------------------

    def _load(self) -> dict[str, dict[str, Any]]:
        if not self.store_path.exists():
            return {}
        return json.loads(self.store_path.read_text(encoding="utf-8"))

    def _save(self, store: dict[str, dict[str, Any]]) -> None:
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self.store_path.write_text(json.dumps(store, indent=2, default=str), encoding="utf-8")

    def deployed(self) -> list[dict[str, Any]]:
        """Detections a person has recorded as deployed."""
        store = self._load()
        return [d for d in self.detections if store.get(d["id"], {}).get("status") == "deployed"]

    def approve(self, proposal_id: str, by: str) -> dict[str, Any]:
        store = self._load()
        proposal = store.get(proposal_id)
        if not proposal:
            raise DetectionError(f"There is no proposal '{proposal_id}'")
        if not by or not by.strip():
            raise DetectionError("An approval needs a person")
        if proposal["status"] != "ready for review":
            raise DetectionError(f"Proposal '{proposal_id}' is '{proposal['status']}', "
                                 f"not ready for review")
        proposal.update(status="approved", approved_by=by.strip(),
                        approved_at=datetime.now(timezone.utc).isoformat())
        self._save(store)
        return proposal

    def record_deployed(self, proposal_id: str, by: str) -> dict[str, Any]:
        """A person records that they deployed the approved rule. The ant deploys nothing."""
        store = self._load()
        proposal = store.get(proposal_id)
        if not proposal or proposal["status"] != "approved":
            raise DetectionError(f"Proposal '{proposal_id}' has not been approved")
        if not by or not by.strip():
            raise DetectionError("A deployment record needs a person")
        proposal.update(status="deployed", deployed_by=by.strip(),
                        deployed_at=datetime.now(timezone.utc).isoformat())
        self._save(store)
        return proposal

    # -- proposing ---------------------------------------------------------------

    def propose(self, verdicts: list[StepVerdict]) -> dict[str, Any]:
        """Test the library's detections for every missed step. Returns the write-up."""
        advice = [{"test_id": v.step.test_id, "host": v.step.host,
                   "advice": "Falcon saw this step but did not block it. Blocking is a change "
                             "to the Falcon prevention policy that a person makes once the "
                             "detection has stayed quiet on normal work. The ants do not "
                             "change Falcon."}
                  for v in verdicts if any(f.startswith("prevention gap") for f in v.findings)]
        missed = [v.step for v in verdicts if v.outcome == MISSED]
        out: dict[str, Any] = {"proposals": [], "no_proposal": [], "advice": advice,
                               "events_checked": 0, "error": None}
        if not missed:
            return out
        now = datetime.now(timezone.utc)
        try:
            found = self.raw_events(sorted({s.host for s in missed}), now - self.baseline, now)
        except Exception as e:
            # No logs, no test, no proposal. Better none than an untested one.
            out["error"] = f"The endpoint logs could not be read, so nothing was proposed: {e}"
            return out
        events = [{"time": c.get("time"), "host": (c.get("hosts") or [""])[0],
                   "raw": str(c.get("text") or ""), "text": strip_markers(str(c.get("text") or "")),
                   "is_test": bool(MARKER_TEXT_RE.search(str(c.get("text") or "")))}
                  for c in found]
        out["events_checked"] = len(events)

        store = self._load()
        covers: dict[str, list[Step]] = {}
        own: dict[str, list[int]] = {}
        for step in missed:
            marker = step.id.lower()
            own[step.id] = [i for i, e in enumerate(events)
                            if marker in e["raw"].lower()
                            or marker.replace("-", "") in e["raw"].lower()]
            candidates = [d for d in self.detections if step.technique in d["techniques"]]
            if step.action in self.no_behaviour:
                reason = self.no_behaviour[step.action]
            elif not candidates:
                reason = f"No reviewed detection for {step.technique} in the library yet."
            elif not own[step.id]:
                reason = "The step left no endpoint log to test a rule against."
            else:
                for det in candidates:
                    covers.setdefault(det["id"], []).append(step)
                continue
            out["no_proposal"].append({"test_id": step.test_id, "host": step.host,
                                       "technique": step.technique, "why": reason})

        for det in self.detections:
            steps = covers.get(det["id"])
            if not steps:
                continue
            hits = evaluate(det, events)
            caught = [s for s in steps if any(i in hits for i in own[s.id])]
            noise = [i for i in hits if not events[i]["is_test"]]
            already = store.get(det["id"], {}).get("status")
            if already == "deployed":
                status = "deployed, but did not fire"
            elif len(caught) < len(steps):
                status = "does not catch"
            elif len(noise) > self.max_noise:
                status = "too noisy"
            else:
                status = "ready for review"
            proposal = {
                "id": det["id"], "title": det["title"], "kind": det["kind"], "why": det["why"],
                "spl": det["spl"], "status": status,
                "covers": [{"test_id": s.test_id, "technique": s.technique, "host": s.host,
                            "caught": s in caught} for s in steps],
                "caught": len(caught), "of": len(steps),
                "noise": len(noise), "noise_examples": sorted({events[i]["text"].strip()[:80]
                                                               for i in noise})[:3],
                "baseline_hours": int(self.baseline.total_seconds() // 3600),
            }
            out["proposals"].append(proposal)
            if already not in ("approved", "deployed"):
                store[det["id"]] = dict(proposal)
        out["proposals"].sort(key=lambda p: (p["status"] != "ready for review", -p["caught"]))
        self._save(store)
        return out
