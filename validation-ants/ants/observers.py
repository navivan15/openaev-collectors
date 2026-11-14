"""Observer ants: one read-only reader per telemetry source.

* SplunkObserver - an adapter around the real ``splunk-es`` collector service
  (query writer, validator, location memory, step matching). It builds the
  same expectation objects OpenAEV would send and reads the results back.
* FalconObserver - reads CrowdStrike Falcon alerts through a small read-only
  client and ties them to steps with the same three checks (time window,
  host, step marker). It can also report Prevented.

Both return the four outcomes and never turn a broken connection into Missed.
Both can also list the alerts on a host in a time range ("candidates") for the
learned-rule matcher.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests  # type: ignore[import-untyped]

from .models import (
    COULD_NOT_CHECK,
    DETECTED,
    MISSED,
    PREVENTED,
    Observation,
    Step,
    implant_name,
)

REPO = Path(__file__).resolve().parents[2]
FMT = "%Y-%m-%dT%H:%M:%S"


def _short(host: str) -> str:
    return host.strip().lower().split(".", 1)[0]


def _parse(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Splunk
# ---------------------------------------------------------------------------
class SplunkObserver:
    name = "splunk"

    def __init__(self, env: dict[str, str], splunk_dir: Path | None = None) -> None:
        """Load the real splunk-es collector service with the given settings."""
        splunk_dir = splunk_dir or REPO / "splunk-es"
        if str(splunk_dir) not in sys.path:
            sys.path.insert(0, str(splunk_dir))
        os.environ.update(env)
        # Import order matters: the collector package has a circular import.
        import src.collector.collector  # noqa: F401
        from pyoaev.apis.inject_expectation.model import DetectionExpectation
        from pyoaev.helpers import OpenAEVDetectionHelper
        from src.services.expectation_service import SplunkESExpectationService
        from src.services.utils import SplunkESConfig

        import logging

        self._expectation_cls = DetectionExpectation
        self.service = SplunkESExpectationService(SplunkESConfig().load)
        self.helper = OpenAEVDetectionHelper(
            logger=logging.getLogger("ants.splunk"),
            relevant_signatures_types=self.service.get_supported_signatures(),
        )
        self.searches: dict[str, int] = {"narrow": 0, "wide": 0, "candidates": 0}

    def _expectation(self, step: Step, agentless: bool) -> Any:
        assert step.start and step.end
        signatures = [
            {"type": "source_ipv4_address", "value": step.source_ip},
            {"type": "target_ipv4_address", "value": step.target_ip},
        ]
        if not agentless:
            signatures += [
                {"type": "parent_process_name", "value": implant_name(step.id)},
                {"type": "target_hostname_address", "value": step.host},
            ]
        signatures += [
            {"type": "start_date", "value": step.start.strftime(FMT)},
            {"type": "end_date", "value": step.end.strftime(FMT)},
        ]
        return self._expectation_cls(
            inject_expectation_id=step.id,
            inject_expectation_signatures=signatures,
            api_client=None,
        )

    def observe(self, steps: list[Step], agentless_actions: set[str]) -> list[Observation]:
        mine = [s for s in steps if s.expect.get(self.name)]
        if not mine:
            return []
        expectations = [self._expectation(s, s.action in agentless_actions) for s in mine]
        # Unlike OpenAEV, the planner knows which test a step belongs to, so the
        # location memory can be keyed by the real test id.
        self.service.set_expectation_metadata({
            s.id: {"inject_expectation_asset": _short(s.host),
                   "inject_expectation_name": s.test_id} for s in mine})
        results = {r.expectation_id: r
                   for r in self.service.handle_batch_expectations(expectations, self.helper)}
        cycle = self.service.last_cycle or {}
        self.searches["narrow"] += cycle.get("narrow_searches", 0)
        self.searches["wide"] += cycle.get("wide_searches", 0)

        out = []
        for step in mine:
            r = results.get(step.id)
            if r is None:  # deferred by the collector: its alerts are not due yet
                out.append(Observation(step.id, self.name, COULD_NOT_CHECK, "not_due"))
                continue
            item = (r.matched_alerts or [{}])[0]
            source = item.get("_alert_source") or {}
            out.append(Observation(
                step_id=step.id, source=self.name, outcome=r.outcome.value,
                reason=r.outcome_reason, method=r.match_method, field=r.match_field,
                search_path=r.search_path,
                evidence={
                    "index": source.get("index"), "sourcetype": source.get("sourcetype"),
                    "rule_name": source.get("rule_name"),
                    "falcon_alert_id": source.get("falcon_alert_id"),
                    "time": item.get("_alert_time"),
                } if r.outcome.value == DETECTED else {"message": r.error_message},
            ))
        return out

    def memory_snapshot(self) -> dict[str, Any]:
        """The collector's location memory right now (for the analyst)."""
        return self.service._get_memory().snapshot()

    def candidates(self, hosts: list[str], earliest: datetime,
                   latest: datetime) -> list[dict[str, Any]]:
        """Alerts naming these hosts in a time range, via one checked search."""
        self.searches["candidates"] += 1
        out = []
        items = self.service.candidate_alerts(hosts, earliest, latest)
        limit = int(getattr(self.service.config.splunk_es, "search_limit", 1000))
        if len(items) >= limit:
            # Newest rows come first, so a cut-off list has lost the quiet window.
            raise RuntimeError("the candidate search hit its row limit")
        for item in items:
            source = item.get("_alert_source") or {}
            out.append({
                "time": _parse(item.get("_alert_time")),
                "hosts": [_short(h) for h in item.get("_alert_hosts") or []],
                "rule_name": source.get("rule_name"),
                "text": " ".join(str(v) for v in (item.get("_alert_marker_fields") or {}).values()),
                "evidence": {"index": source.get("index"),
                             "sourcetype": source.get("sourcetype"),
                             "rule_name": source.get("rule_name"),
                             "falcon_alert_id": source.get("falcon_alert_id"),
                             "time": item.get("_alert_time")},
            })
        return out


# ---------------------------------------------------------------------------
# CrowdStrike Falcon
# ---------------------------------------------------------------------------
class FalconError(Exception):
    reason = "search_failed"


class FalconAuthError(FalconError):
    reason = "auth_failed"


class FalconUnreachable(FalconError):
    reason = "source_unreachable"


class FalconHttpClient:
    """Read-only Falcon Alerts client: sign in, list alert ids, fetch alerts."""

    def __init__(self, base_url: str, client_id: str, client_secret: str,
                 timeout: int = 20) -> None:
        self.base_url = base_url.rstrip("/")
        self._credentials = {"client_id": client_id, "client_secret": client_secret}
        self.timeout = timeout
        self.calls = 0

    def _call(self, method: str, path: str, **kwargs: Any) -> Any:
        self.calls += 1
        try:
            response = requests.request(method, self.base_url + path,
                                        timeout=self.timeout, **kwargs)
        except (requests.ConnectionError, requests.Timeout) as e:
            raise FalconUnreachable(f"Falcon could not be reached: {e}") from e
        if response.status_code in (401, 403):
            raise FalconAuthError(f"Falcon rejected the sign-in ({response.status_code})")
        if response.status_code not in (200, 201):
            raise FalconError(f"Falcon answered {response.status_code}")
        return response.json()

    def alerts_since(self, start: datetime) -> list[dict[str, Any]]:
        token = self._call("POST", "/oauth2/token", data=self._credentials)["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        ids: list[str] = []
        while True:
            page = self._call(
                "GET", "/alerts/queries/alerts/v2", headers=headers,
                params={"filter": f"timestamp:>'{start.isoformat()}'+type:'ldt'",
                        "offset": len(ids), "limit": self.PAGE},
            )
            self._no_errors(page)
            got = page.get("resources") or []
            ids.extend(got)
            total = ((page.get("meta") or {}).get("pagination") or {}).get("total")
            if not got or total is None or len(ids) >= int(total):
                break
        alerts: list[dict[str, Any]] = []
        for i in range(0, len(ids), self.PAGE):
            body = self._call("POST", "/alerts/entities/alerts/v2", headers=headers,
                              json={"composite_ids": ids[i:i + self.PAGE]})
            self._no_errors(body)
            alerts.extend(body.get("resources") or [])
        if len(alerts) != len(ids):
            # A partial list must not be read as "nothing there".
            raise FalconError(f"Falcon returned {len(alerts)} of {len(ids)} alerts")
        return alerts

    PAGE = 500

    @staticmethod
    def _no_errors(body: dict[str, Any]) -> None:
        if body.get("errors"):
            raise FalconError(f"Falcon reported errors: {body['errors']}")


def _load_is_prevented() -> Any:
    """Use the fork's own crowdstrike disposition logic, loaded by file path."""
    path = REPO / "crowdstrike" / "crowdstrike" / "pattern_disposition.py"
    spec = importlib.util.spec_from_file_location("cs_pattern_disposition", path)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module.is_prevented


class FalconObserver:
    name = "falcon"
    MARKER_FIELDS = ("cmdline", "filename", "parent_details.filename",
                     "parent_details.cmdline", "grandparent_details.filename")

    def __init__(self, client: Any, before: timedelta = timedelta(minutes=1),
                 after: timedelta = timedelta(minutes=5),
                 lookback: timedelta = timedelta(minutes=30),
                 alert_delay: timedelta = timedelta(seconds=30)) -> None:
        self.client = client
        self.before, self.after, self.lookback = before, after, lookback
        self.alert_delay = alert_delay   # same meaning as SPLUNKES_ALERT_DELAY
        self.is_prevented = _load_is_prevented()
        self._alerts: list[dict[str, Any]] = []

    @staticmethod
    def _get(alert: dict[str, Any], dotted: str) -> str:
        value: Any = alert
        for part in dotted.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        return str(value) if value else ""

    def _marker_field(self, alert: dict[str, Any], step: Step) -> str | None:
        markers = (step.id.lower(), step.id.replace("-", "").lower())
        for name in self.MARKER_FIELDS:
            text = self._get(alert, name).lower()
            if any(m in text for m in markers):
                return name
        return None

    def observe(self, steps: list[Step], agentless_actions: set[str]) -> list[Observation]:
        mine = [s for s in steps if s.expect.get(self.name)]
        if not mine:
            return []
        try:
            earliest = min(s.start for s in mine if s.start) - self.before - self.lookback
            self._alerts = self.client.alerts_since(earliest)
        except FalconError as e:
            self._alerts = []
            return [Observation(s.id, self.name, COULD_NOT_CHECK, e.reason,
                                evidence={"message": str(e)}) for s in mine]

        out = []
        now = datetime.now(timezone.utc)
        for step in mine:
            assert step.start and step.end
            if now < step.end + self.alert_delay:
                # Too early to call it Missed: its alerts may not have arrived yet.
                out.append(Observation(step.id, self.name, COULD_NOT_CHECK, "not_due"))
                continue
            window = (step.start - self.before, step.end + self.after)
            hit, hit_field, rejections = None, None, []
            for alert in self._alerts:
                found = self._marker_field(alert, step)
                if not found:
                    continue
                when = _parse(alert.get("created_timestamp"))
                if when and not (window[0] <= when <= window[1]):
                    rejections.append("outside_time_window")
                elif _short(self._get(alert, "device.hostname")) != _short(step.host):
                    rejections.append("wrong_host")
                else:
                    hit, hit_field = alert, found
                    break
            if hit is None:
                on_host = [a for a in self._alerts
                           if _short(self._get(a, "device.hostname")) == _short(step.host)]
                reason = (rejections[0] if rejections
                          else "marker_absent" if on_host else "no_alerts")
                out.append(Observation(step.id, self.name, MISSED, reason))
                continue
            prevented = bool(self.is_prevented(int(hit.get("pattern_disposition", 0))))
            out.append(Observation(
                step_id=step.id, source=self.name,
                outcome=PREVENTED if prevented else DETECTED,
                method="step_marker", field=hit_field,
                evidence={"falcon_alert_id": hit.get("composite_id"),
                          "rule_name": hit.get("display_name"),
                          "time": hit.get("created_timestamp"),
                          "pattern_disposition": hit.get("pattern_disposition")},
            ))
        return out

    def candidates(self, hosts: list[str], earliest: datetime,
                   latest: datetime) -> list[dict[str, Any]]:
        wanted = {_short(h) for h in hosts}
        out = []
        for alert in self._alerts:
            when = _parse(alert.get("created_timestamp"))
            host = _short(self._get(alert, "device.hostname"))
            if host in wanted and when and earliest <= when <= latest:
                out.append({
                    "time": when, "hosts": [host], "rule_name": alert.get("display_name"),
                    "text": " ".join(self._get(alert, f) for f in self.MARKER_FIELDS),
                    "evidence": {"falcon_alert_id": alert.get("composite_id"),
                                 "rule_name": alert.get("display_name"),
                                 "time": alert.get("created_timestamp"),
                                 "prevented": bool(self.is_prevented(
                                     int(alert.get("pattern_disposition", 0))))},
                })
        return out
