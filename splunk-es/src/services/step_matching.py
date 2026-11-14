"""Tie a Splunk alert to the simulated test step (inject) that caused it.

A step is identified by three things the collector already knows:

* a **step marker** - the inject ID, which an agent-based step carries in its
  implant name (``oaev-implant-{inject}-agent-{agent}``). Scenario authors can
  also embed it in a command line, a dropped file name or a looked-up
  hostname (e.g. ``echo oaev-step-{inject}``). An alert containing the marker
  in one of those fields is tied to this step and no other.
* the **host** the step ran on - the ``target_hostname_address`` signature,
  compared with the alert's host fields; when either side has no hostname,
  the IP signatures are compared instead.
* a **time window** - from the step's ``start_date`` minus a small slack to its
  ``end_date`` plus a small slack.

This module holds the pure, side-effect-free pieces so they can be tested and
reused by later matcher components.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE
)
IMPLANT_RE = re.compile(
    r"oaev-implant-(" + UUID_RE.pattern + r")-agent-(" + UUID_RE.pattern + r")",
    re.IGNORECASE,
)

# Alert fields that may carry the step marker.
MARKER_FIELDS: tuple[str, ...] = (
    # command line / process
    "process",
    "command_line",
    "CommandLine",
    "cmdline",
    "process_command_line",
    "process_name",
    "parent_process",
    "parent_process_name",
    "ParentCommandLine",
    "Image",
    # file
    "file_name",
    "file_path",
    "TargetFilename",
    "object",
    "object_path",
    # hostname looked up / contacted by the step
    "query",
    "dns_query",
    "QueryName",
    "url_domain",
)

# Alert fields naming the host the activity happened on. Splunk's own ``host``
# metadata field is deliberately NOT used: for notable events it is the search
# head / forwarder, not the endpoint.
HOST_FIELDS: tuple[str, ...] = (
    "dest_host",
    "dest_nt_host",
    "hostname",
    "ComputerName",
    "Computer",
    "orig_host",
    "dvc_host",
    "device_hostname",
    "dvc",
    "dest",  # CIM endpoint models put the hostname here; IPs are skipped
)

# Keys the converter adds to each OAEV data item for step matching. They never
# collide with OpenAEV signature type names.
KEY_TIME = "_alert_time"
KEY_HOSTS = "_alert_hosts"
KEY_MARKER_FIELDS = "_alert_marker_fields"
KEY_SOURCE = "_alert_source"  # where the alert came from (index, sourcetype, ids)

# Fields that hold the CrowdStrike Falcon alert id when Falcon alerts are
# forwarded into Splunk. The `crowdstrike` collector identifies the same alert
# by its composite id, so keeping it lets a later step count a detection once.
FALCON_ALERT_ID_FIELDS: tuple[str, ...] = (
    "event.CompositeId",
    "CompositeId",
    "composite_id",
    "event.DetectId",
    "DetectId",
    "detect_id",
    "falcon_alert_id",
)

IP_KEYS = (
    "source_ipv4_address",
    "source_ipv6_address",
    "target_ipv4_address",
    "target_ipv6_address",
)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def parse_time(value: Any) -> datetime | None:
    """Parse a Splunk ``_time`` / OpenAEV date into an aware UTC datetime."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    text = str(value).strip()
    try:
        return datetime.fromtimestamp(float(text), tz=timezone.utc)
    except ValueError:
        pass
    parsed: datetime | None = None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        for fmt in ("%m/%d/%Y:%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _short_host(name: str) -> str:
    name = name.strip().lower()
    if _is_ip(name):
        return name
    return name.split(".", 1)[0]


def markers_from_parent_process(parent_process_names: list[str]) -> list[str]:
    """Derive step markers (inject IDs, dashed and compact) from implant names."""
    markers: list[str] = []
    for name in parent_process_names:
        m = IMPLANT_RE.search(name or "")
        if not m:
            continue
        inject = m.group(1).lower()
        for marker in (inject, inject.replace("-", "")):
            if marker not in markers:
                markers.append(marker)
    return markers


def extract_alert_hosts(
    raw: dict[str, Any], fields: tuple[str, ...] = HOST_FIELDS
) -> list[str]:
    """Hostnames named in an alert (IPs excluded)."""
    hosts: list[str] = []
    for f in fields:
        v = raw.get(f)
        values = v if isinstance(v, list) else [v]
        for item in values:
            if not item or not isinstance(item, str) or _is_ip(item):
                continue
            if item not in hosts:
                hosts.append(item)
    return hosts


def extract_alert_source(raw: dict[str, Any]) -> dict[str, str]:
    """Where an alert came from: index, sourcetype, rule and source alert id."""
    out: dict[str, str] = {}
    for key in ("index", "sourcetype", "source"):
        if raw.get(key):
            out[key] = str(raw[key])
    rule = raw.get("rule_name") or raw.get("signature")
    if rule:
        out["rule_name"] = str(rule)
    for f in FALCON_ALERT_ID_FIELDS:
        if raw.get(f):
            out["falcon_alert_id"] = str(raw[f])
            break
    return out


def extract_marker_fields(
    raw: dict[str, Any], fields: tuple[str, ...] = MARKER_FIELDS
) -> dict[str, str]:
    """Alert fields that may carry a step marker, flattened to strings."""
    out: dict[str, str] = {}
    for f in fields:
        v = raw.get(f)
        if v is None or v == "":
            continue
        out[f] = " ".join(map(str, v)) if isinstance(v, list) else str(v)
    return out


@dataclass
class StepContext:
    """What the collector knows about one simulated step."""

    markers: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    window_start: datetime | None = None
    window_end: datetime | None = None

    @classmethod
    def from_signatures(
        cls,
        signatures: list[dict[str, str]],
        before: timedelta,
        after: timedelta,
    ) -> "StepContext":
        parents, hostnames, ips = [], [], []
        start = end = None
        for sig in signatures:
            t, v = sig.get("type"), sig.get("value") or ""
            if t == "parent_process_name":
                parents.append(v)
            elif t == "target_hostname_address":
                hostnames.append(v)
            elif t in IP_KEYS:
                ips.append(v.strip().lower())
            elif t == "start_date":
                start = parse_time(v)
            elif t == "end_date":
                end = parse_time(v)
        return cls(
            markers=markers_from_parent_process(parents),
            hostnames=hostnames,
            ips=ips,
            window_start=start - before if start else None,
            window_end=end + after if end else None,
        )

    # -- individual checks -------------------------------------------------

    def in_time_window(self, item: dict[str, Any]) -> bool | None:
        """True/False when decidable; None when step or alert time is unknown."""
        if self.window_start is None and self.window_end is None:
            return None
        t = parse_time(item.get(KEY_TIME))
        if t is None:
            return None
        if self.window_start is not None and t < self.window_start:
            return False
        if self.window_end is not None and t > self.window_end:
            return False
        return True

    def hostname_check(self, item: dict[str, Any]) -> bool | None:
        """Compare hostnames; None when either side has none."""
        alert_hosts = item.get(KEY_HOSTS) or []
        if not self.hostnames or not alert_hosts:
            return None
        expected = {_short_host(h) for h in self.hostnames}
        return any(_short_host(h) in expected for h in alert_hosts)

    def ip_check(self, item: dict[str, Any]) -> bool | None:
        """Compare IPs; None when either side has none."""
        alert_ips: list[str] = []
        for key in IP_KEYS:
            entry = item.get(key)
            if isinstance(entry, dict):
                alert_ips.extend(str(x).strip().lower() for x in entry.get("data", []))
        if not self.ips or not alert_ips:
            return None
        return any(ip in self.ips for ip in alert_ips)

    def host_check(self, item: dict[str, Any]) -> bool | None:
        """Hostname decides when both sides have one, otherwise IPs."""
        by_name = self.hostname_check(item)
        if by_name is not None:
            return by_name
        return self.ip_check(item)

    def marker_found(self, item: dict[str, Any]) -> str | None:
        """Return the alert field holding the marker, or None."""
        if not self.markers:
            return None
        for f, value in (item.get(KEY_MARKER_FIELDS) or {}).items():
            low = value.lower()
            if any(m in low for m in self.markers):
                return f
        return None
