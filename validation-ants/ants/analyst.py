"""Analyst ant: reads what the Splunk observer found and writes down every
change to how a test will be searched next time, and why.

After each run it compares the location memory before and after, per step,
and records one entry per step in a search-change log:

* learned   - first time found: next run searches that index and sourcetype
              directly instead of the wide search.
* confirmed - found again in a remembered place: the narrow search stays.
* added     - not in the remembered place, found somewhere else: the new
              place is searched as well from now on.
* dropped   - found neither in the remembered place nor by the wide search:
              the next run goes back to the wide search.
* none      - never found, nothing remembered: the wide search stays.
* unchecked - Splunk could not be checked: nothing is changed.

Each entry names the evidence it is based on (index, sourcetype, the field
that carried the step marker, the rule, the delay between step and alert).
The log is hash-chained like the gatekeeper's audit log, so an edited or
removed entry is detectable. The analyst follows fixed rules; no model
decides anything here.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import COULD_NOT_CHECK, DETECTED, Observation, Step

WIDE = "wide search: configured index, all configured sourcetypes, the step's full time window"


def _key(step: Step) -> str:
    host = step.host.strip().lower().split(".", 1)[0]
    return f"asset:{host}|expectation:{step.test_id.lower()}"


def _places(memory: dict[str, Any], key: str) -> list[dict[str, Any]]:
    return list((memory.get(key) or {}).get("locations") or [])


def _where(places: list[dict[str, Any]]) -> set[tuple[Any, Any]]:
    return {(p.get("index"), p.get("sourcetype")) for p in places}


def _narrow(places: list[dict[str, Any]]) -> str:
    where = " OR ".join(sorted({f'index={p["index"]} sourcetype="{p["sourcetype"]}"'
                                for p in places}))
    return f"narrow search: ({where}) with the step marker, tight time window"


class SearchAnalyst:
    def __init__(self, log_path: Path | str) -> None:
        self.log_path = Path(log_path)

    def read_log(self) -> list[dict[str, Any]]:
        if not self.log_path.exists():
            return []
        return [json.loads(line) for line in
                self.log_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def verify_log(self) -> tuple[bool, int | None]:
        prev, seq = "0" * 64, 0
        for entry in self.read_log():
            seq += 1
            body = {k: v for k, v in entry.items() if k != "hash"}
            digest = hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
            if entry.get("prev") != prev or entry.get("hash") != digest or entry.get("seq") != seq:
                return False, entry.get("seq", seq)
            prev = entry["hash"]
        return True, None

    def _append(self, entries: list[dict[str, Any]]) -> None:
        log = self.read_log()
        prev = log[-1]["hash"] if log else "0" * 64
        seq = log[-1]["seq"] if log else 0
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as f:
            for entry in entries:
                seq += 1
                entry.update(seq=seq, prev=prev)
                entry["hash"] = hashlib.sha256(
                    json.dumps(entry, sort_keys=True, default=str).encode()).hexdigest()
                prev = entry["hash"]
                f.write(json.dumps(entry, default=str) + "\n")

    def record(self, run_id: str, steps: list[Step], observations: list[Observation],
               before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
        """Write one search-change entry per step the Splunk observer looked for."""
        by_step = {o.step_id: o for o in observations if o.source == "splunk"}
        entries = []
        for step in steps:
            obs = by_step.get(step.id)
            if obs is None:
                continue
            key = _key(step)
            was, now = _places(before, key), _places(after, key)
            newest = now[0] if now else {}
            evidence = {k: newest.get(k) for k in
                        ("index", "sourcetype", "field", "rule_name", "delay_seconds")} if now else {}
            found = (f'index={newest.get("index")} sourcetype="{newest.get("sourcetype")}"'
                     + (f', marker in field {newest["field"]}' if newest.get("field") else "")
                     + (f', rule "{newest["rule_name"]}"' if newest.get("rule_name") else "")
                     + (f', {newest["delay_seconds"]} s after the step started'
                        if newest.get("delay_seconds") is not None else "")) if now else ""
            if obs.outcome == COULD_NOT_CHECK:
                change, why = "unchecked", (
                    f"Splunk could not be checked ({obs.reason}), so nothing was learned "
                    f"and nothing was changed.")
            elif obs.outcome == DETECTED and not was:
                change, why = "learned", f"The detection was found at {found}."
            elif obs.outcome == DETECTED and _where(now) - _where(was):
                change, why = "added", (
                    f"The detection was not in the remembered place; the {obs.search_path} "
                    f"search found it at {found}.")
            elif obs.outcome == DETECTED:
                change, why = "confirmed", (
                    f"Found again in a remembered place by the {obs.search_path} search: "
                    f"{found}.")
            elif was and not now:
                change, why = "dropped", (
                    "The detection was found neither in the remembered place nor by the "
                    "wide search, so the remembered place is no longer trusted.")
            else:
                change, why = "none", "Nothing was found, so there is nothing to narrow to."
            entries.append({
                "at": datetime.now(timezone.utc).isoformat(),
                "run_id": run_id, "test_id": step.test_id, "host": step.host,
                "change": change,
                "searched_this_run": (obs.search_path or "not searched"),
                "search_before": _narrow(was) if was else WIDE,
                "search_next": _narrow(now) if now else WIDE,
                "why": why,
                "evidence": evidence,
            })
        if entries:
            self._append(entries)
        return entries
