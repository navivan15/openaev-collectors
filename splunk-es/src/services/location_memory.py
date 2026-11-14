"""Remember where each test's detection was found, so the next run looks there first.

A small local JSON file. For each test key it keeps up to ``MAX_LOCATIONS``
places a detection was found: index, sourcetype, the field that carried the
step marker, the rule name, the delay between step start and alert, and the
date it was last proven.

The memory only ever makes a search *narrower*; it never decides an outcome
on its own. Three guards keep it honest:

1. **Narrow miss -> wide search.** A step not found in the remembered place is
   searched wide before it may be called Missed (enforced by the caller).
2. **Periodic wide search.** Every ``wide_every``-th run of a key skips the
   memory and searches wide, so a detection that moved, or a new one, is seen.
3. **Expiry.** A location older than ``ttl`` is dropped and must be found by a
   wide search again before it is trusted.

The file holds names from your environment (index, sourcetype, rule and asset
identifiers). Keep it local; it is not meant to be committed.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

LOG_PREFIX = "[SplunkESLocationMemory]"
MAX_LOCATIONS = 5

LOOKUP_HIT = "hit"
LOOKUP_NONE = "none"
LOOKUP_EXPIRED = "expired"
LOOKUP_PERIODIC_WIDE = "periodic_wide"


def _now() -> datetime:
    return datetime.now(timezone.utc)


class LocationMemory:
    """File-backed memory of detection locations, keyed by test."""

    def __init__(
        self,
        path: str | Path | None,
        ttl: timedelta = timedelta(days=30),
        wide_every: int = 5,
        now: Callable[[], datetime] = _now,
    ) -> None:
        """Open (or start) the memory file. ``path`` None/empty disables it."""
        self.logger = logging.getLogger(__name__)
        self.path = Path(path) if path else None
        self.ttl = ttl
        self.wide_every = max(1, int(wide_every))
        self._now = now
        self._entries: dict[str, dict[str, Any]] = {}
        self._load()

    @property
    def enabled(self) -> bool:
        """False when no file is configured."""
        return self.path is not None

    def _load(self) -> None:
        if not self.path or not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            entries = data.get("entries", {})
            if isinstance(entries, dict):
                # Keep only well-formed entries; a hand-edited file must not
                # be able to break a run.
                self._entries = {
                    str(key): entry
                    for key, entry in entries.items()
                    if isinstance(entry, dict)
                    and isinstance(entry.get("locations"), list)
                    and all(isinstance(loc, dict) for loc in entry["locations"])
                }
        except (OSError, ValueError, AttributeError) as e:
            # A broken memory file must never break a run: start empty.
            self.logger.warning(f"{LOG_PREFIX} Ignoring unreadable memory file: {e}")
            self._entries = {}

    def _save(self) -> None:
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(
                json.dumps({"version": 1, "entries": self._entries}, indent=2),
                encoding="utf-8",
            )
            os.replace(tmp, self.path)
        except OSError as e:
            self.logger.warning(f"{LOG_PREFIX} Could not save memory file: {e}")

    def _fresh(self, location: dict[str, Any]) -> bool:
        if not location.get("index") or not location.get("sourcetype"):
            return False
        try:
            proven = datetime.fromisoformat(str(location.get("proven_at")))
        except ValueError:
            return False
        if proven.tzinfo is None:
            proven = proven.replace(tzinfo=timezone.utc)
        return self._now() - proven <= self.ttl

    # -- reading -------------------------------------------------------------

    def lookup(self, key: str | None) -> tuple[list[dict[str, Any]], str]:
        """Return (locations to search narrowly, why).

        The list is empty unless the reason is ``hit``.
        """
        if not self.enabled or not key:
            return [], LOOKUP_NONE
        entry = self._entries.get(key)
        if not entry or not entry.get("locations"):
            return [], LOOKUP_NONE
        fresh = [loc for loc in entry["locations"] if self._fresh(loc)]
        if not fresh:
            # Guard 3: expired entries are re-proven by a wide search.
            return [], LOOKUP_EXPIRED
        if int(entry.get("narrow_runs_since_wide", 0)) >= self.wide_every - 1:
            # Guard 2: time for a wide search even though the entry is valid.
            return [], LOOKUP_PERIODIC_WIDE
        return fresh, LOOKUP_HIT

    def usual_delay(self, key: str | None) -> float | None:
        """Largest remembered step-to-alert delay for a key, in seconds."""
        entry = self._entries.get(key or "")
        if not entry:
            return None
        delays = [
            float(loc["delay_seconds"])
            for loc in entry.get("locations", [])
            if self._fresh(loc) and loc.get("delay_seconds") is not None
        ]
        return max(delays) if delays else None

    # -- writing -------------------------------------------------------------

    def record(
        self,
        key: str | None,
        *,
        index: str,
        sourcetype: str,
        field: str | None,
        rule_name: str | None,
        delay_seconds: float | None,
        search_path: str,
    ) -> None:
        """Remember where a detection was found (or refresh the entry)."""
        if not self.enabled or not key or not index or not sourcetype:
            return
        entry = self._entries.setdefault(
            key, {"locations": [], "narrow_runs_since_wide": 0}
        )
        now = self._now()
        location = {
            "index": index,
            "sourcetype": sourcetype,
            "field": field,
            "rule_name": rule_name,
            "delay_seconds": (
                round(delay_seconds, 1) if delay_seconds is not None else None
            ),
            "found_on": now.date().isoformat(),
            "proven_at": now.isoformat(),
        }
        others = [
            loc
            for loc in entry["locations"]
            if (loc.get("index"), loc.get("sourcetype")) != (index, sourcetype)
            and self._fresh(loc)
        ]
        entry["locations"] = ([location] + others)[:MAX_LOCATIONS]
        if search_path == "narrow":
            entry["narrow_runs_since_wide"] = (
                int(entry.get("narrow_runs_since_wide", 0)) + 1
            )
        else:
            entry["narrow_runs_since_wide"] = 0
        self._save()

    def forget(self, key: str | None) -> None:
        """Drop a key after neither the narrow nor the wide search found it."""
        if self.enabled and key and key in self._entries:
            del self._entries[key]
            self._save()

    def snapshot(self) -> dict[str, dict[str, Any]]:
        """A copy of the entries (for logs and tests)."""
        return json.loads(json.dumps(self._entries))
