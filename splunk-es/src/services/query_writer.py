"""Build every search from checked templates, never from free text.

* Templates are data (``query_templates.json``). A template can only be used
  once it carries a ``proven`` stamp, and it only gets that stamp by being
  rendered, validated and run through a search function (the mock harness)
  via :meth:`TemplateStore.add` / :meth:`TemplateStore.prove_existing`.
* Placeholder values are built here from validated pieces only (IP addresses,
  inject IDs, index / sourcetype names matching a strict pattern), so nothing
  read from OpenAEV or from a Splunk row can inject SPL.
* Every rendered search is passed through :func:`validate_spl`.

No model writes SPL: the two shipped templates and the clause builders below
are the only source of search text.
"""

from __future__ import annotations

import ipaddress
import json
import re
import string
from datetime import date, datetime
from pathlib import Path
from typing import Any, Callable

from .exception import SplunkESValidationError
from .spl_validator import SplunkESQueryRefusedError, validate_spl
from .step_matching import (
    FALCON_ALERT_ID_FIELDS,
    HOST_FIELDS,
    MARKER_FIELDS,
    StepContext,
)

DEFAULT_TEMPLATES_PATH = Path(__file__).with_name("query_templates.json")

TEMPLATE_PLACEHOLDERS = {
    "index",
    "sourcetype_filter",
    "step_filter",
    "location_filter",
    "host_filter",
    "earliest",
    "latest",
    "fields",
    "limit",
}

_INDEX_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_\-.]*\*?$")
_SOURCETYPE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_\-.:/]*\*?$|^\*$")
_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-:]*$")
_MARKER_RE = re.compile(r"^[0-9a-f\-]{32,36}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-.]{0,252}$")

SRC_IP_FIELDS = ("src_ip", "src", "source_ip", "client_ip")
DST_IP_FIELDS = ("dst_ip", "dest", "dest_ip", "destination_ip", "server_ip")

_BASE_FIELDS = (
    "_time",
    "index",
    "sourcetype",
    "source",
    *SRC_IP_FIELDS,
    *DST_IP_FIELDS,
    "signature",
    "rule_name",
    "event_type",
    "severity",
    "url_path",
    "url",
    "path",
)


def is_safe_index(name: str) -> bool:
    """True when an index name can be placed in a search as-is."""
    return bool(name) and bool(_INDEX_RE.match(name))


def is_safe_sourcetype(name: str) -> bool:
    """True when a sourcetype name can be placed in a search as-is."""
    return bool(name) and bool(_SOURCETYPE_RE.match(name))


def is_safe_field(name: str) -> bool:
    """True when a field name can be recorded / shown as-is."""
    return bool(name) and bool(_FIELD_RE.match(name))


def table_fields() -> str:
    """The field list every template selects (dotted names quoted)."""
    seen: list[str] = []
    for name in (
        *_BASE_FIELDS,
        *MARKER_FIELDS,
        *HOST_FIELDS,
        *FALCON_ALERT_ID_FIELDS,
    ):
        if name not in seen:
            seen.append(name)
    return ", ".join(f'"{n}"' if "." in n else n for n in seen)


def _epoch(moment: datetime) -> int:
    return int(moment.timestamp())


def _quoted_ips(ips: list[str]) -> str:
    out = []
    for ip in ips:
        ipaddress.ip_address(ip)  # raises ValueError on anything that is not an IP
        out.append(f'"{ip}"')
    return ",".join(out)


def _marker_terms(markers: list[str]) -> list[str]:
    terms = []
    for marker in markers:
        if not _MARKER_RE.match(marker):
            raise SplunkESQueryRefusedError(
                "Search refused: step marker is not an inject ID"
            )
        if f'"{marker}"' not in terms:
            terms.append(f'"{marker}"')
    return terms


def _ip_clause(step: StepContext) -> str | None:
    """IP-pair filter for a step that has no marker."""
    parts = []
    if step.source_ips:
        ips = _quoted_ips(step.source_ips)
        parts.append("(" + " OR ".join(f"{f} IN ({ips})" for f in SRC_IP_FIELDS) + ")")
    if step.target_ips:
        ips = _quoted_ips(step.target_ips)
        parts.append("(" + " OR ".join(f"{f} IN ({ips})" for f in DST_IP_FIELDS) + ")")
    return "(" + " ".join(parts) + ")" if parts else None


def step_clauses(steps: list[StepContext]) -> list[str]:
    """Search clauses covering every step: one marker clause + IP-only clauses."""
    clauses: list[str] = []
    markers: list[str] = []
    for step in steps:
        if step.markers:
            markers.extend(m for m in step.markers if m not in markers)
        else:
            clause = _ip_clause(step)
            if clause and clause not in clauses:
                clauses.append(clause)
    terms = _marker_terms(markers)
    if terms:
        clauses.insert(0, "(" + " OR ".join(terms) + ")")
    return clauses


class TemplateStore:
    """Loads the query templates and only hands out proven ones."""

    def __init__(self, path: Path | str | None = None) -> None:
        """Load templates from ``path`` (default: the file shipped in the repo)."""
        self.path = Path(path) if path else DEFAULT_TEMPLATES_PATH
        self._data: dict[str, Any] = {"version": 1, "templates": []}
        if self.path.exists():
            self._data = json.loads(self.path.read_text(encoding="utf-8"))

    # -- reading -------------------------------------------------------------

    def _find(self, template_id: str) -> dict[str, Any] | None:
        for template in self._data.get("templates", []):
            if template.get("id") == template_id:
                return template
        return None

    def ids(self, proven_only: bool = True) -> list[str]:
        """Template ids, by default only the ones allowed for use."""
        return [
            t["id"]
            for t in self._data.get("templates", [])
            if t.get("proven") or not proven_only
        ]

    def render(self, template_id: str, **values: Any) -> str:
        """Render a proven template and validate the result."""
        template = self._find(template_id)
        if template is None:
            raise SplunkESQueryRefusedError(
                f"Search refused: unknown query template '{template_id}'"
            )
        if not template.get("proven"):
            raise SplunkESQueryRefusedError(
                f"Search refused: query template '{template_id}' has not been "
                f"proven against the mock"
            )
        return self._render(template["spl"], values)

    # -- writing -------------------------------------------------------------

    @staticmethod
    def _render(spl_template: str, values: dict[str, Any]) -> str:
        used = {
            name
            for _, name, _, _ in string.Formatter().parse(spl_template)
            if name is not None
        }
        unknown = used - TEMPLATE_PLACEHOLDERS
        if unknown:
            raise SplunkESQueryRefusedError(
                f"Template refused: unknown placeholders {sorted(unknown)}. "
                f"Allowed: {sorted(TEMPLATE_PLACEHOLDERS)}"
            )
        missing = used - set(values)
        if missing:
            raise SplunkESQueryRefusedError(
                f"Template refused: no value for placeholders {sorted(missing)}"
            )
        spl = " ".join(spl_template.format(**values).split())
        validate_spl(spl)
        return spl

    def check(self, template: dict[str, Any]) -> str:
        """Render a template with sample values and validate it. Returns the SPL."""
        for key in ("id", "purpose", "spl"):
            if not template.get(key):
                raise SplunkESQueryRefusedError(f"Template refused: missing '{key}'")
        return self._render(template["spl"], SAMPLE_VALUES)

    def _stamp(
        self, template: dict[str, Any], run_search: Callable[[str], Any], against: str
    ) -> dict[str, Any]:
        sample_spl = self.check(template)
        rows = run_search(sample_spl)  # must not raise
        proven = dict(template)
        proven["proven"] = {
            "against": against,
            "on": date.today().isoformat(),
            "sample_rows": len(rows) if hasattr(rows, "__len__") else 0,
        }
        return proven

    def add(
        self,
        template: dict[str, Any],
        run_search: Callable[[str], Any] | None,
        against: str = "mock",
    ) -> dict[str, Any]:
        """Prove a new template by running it, then save it for use.

        Raises:
            SplunkESQueryRefusedError: no search function was given, the
                template uses a refused command / placeholder, or it does not
                name index, sourcetype and a time window.

        """
        if run_search is None:
            raise SplunkESQueryRefusedError(
                "Template refused: it must be run against the mock before it "
                "can be saved"
            )
        proven = self._stamp(template, run_search, against)
        templates = [
            t for t in self._data.get("templates", []) if t.get("id") != proven["id"]
        ]
        templates.append(proven)
        self._data["templates"] = templates
        self._save()
        return proven

    def prove_existing(
        self, run_search: Callable[[str], Any], against: str = "mock"
    ) -> list[str]:
        """(Re-)prove every template in the file and save the stamps."""
        self._data["templates"] = [
            self._stamp(
                {k: v for k, v in t.items() if k != "proven"}, run_search, against
            )
            for t in self._data.get("templates", [])
        ]
        self._save()
        return self.ids()

    def _save(self) -> None:
        self.path.write_text(
            json.dumps(self._data, indent=2) + "\n", encoding="utf-8", newline="\n"
        )


# Values used to render a template when it is checked / proven. Synthetic only.
SAMPLE_VALUES: dict[str, Any] = {
    "index": "main",
    "sourcetype_filter": 'sourcetype="sample:sourcetype"',
    "step_filter": '("00000000-0000-0000-0000-000000000000")',
    "location_filter": 'index=main sourcetype="sample:sourcetype" '
    '("00000000-0000-0000-0000-000000000000")',
    "host_filter": 'dest_host IN ("sample-host*")',
    "earliest": 1700000000,
    "latest": 1700000600,
    "fields": table_fields(),
    "limit": 1000,
}


class QueryWriter:
    """Writes the wide and the narrow search for a batch of steps."""

    def __init__(
        self,
        store: TemplateStore,
        index: str,
        sourcetypes: list[str] | None = None,
        limit: int = 1000,
    ) -> None:
        """Validate the configured index / sourcetypes once."""
        if not is_safe_index(index):
            raise SplunkESQueryRefusedError(
                f"Search refused: index name '{index}' is not a plain index name"
            )
        self.sourcetypes = [s for s in (sourcetypes or ["*"]) if s] or ["*"]
        for sourcetype in self.sourcetypes:
            if not is_safe_sourcetype(sourcetype):
                raise SplunkESQueryRefusedError(
                    f"Search refused: sourcetype '{sourcetype}' is not a plain name"
                )
        self.store = store
        self.index = index
        self.limit = int(limit)

    def _sourcetype_filter(self) -> str:
        if len(self.sourcetypes) == 1:
            value = self.sourcetypes[0]
            return "sourcetype=*" if value == "*" else f'sourcetype="{value}"'
        return "sourcetype IN (" + ",".join(f'"{s}"' for s in self.sourcetypes) + ")"

    def wide(
        self, steps: list[StepContext], earliest: datetime, latest: datetime
    ) -> str:
        """One search for all steps over the configured index and sourcetypes."""
        clauses = step_clauses(steps)
        if not clauses:
            raise SplunkESQueryRefusedError(
                "Search refused: no step has a marker or an IP to search for"
            )
        return self.store.render(
            "wide_step_search",
            index=self.index,
            sourcetype_filter=self._sourcetype_filter(),
            step_filter=" OR ".join(clauses),
            earliest=_epoch(earliest),
            latest=_epoch(latest),
            fields=table_fields(),
            limit=self.limit,
        )

    def host_window(
        self, hosts: list[str], earliest: datetime, latest: datetime
    ) -> str:
        """Every alert naming one of these hosts in a time range.

        Used by the learned-rule matcher: it needs the alerts around a step
        that carry no marker, and the same hosts' alerts in a quiet window.
        """
        names = []
        for host in hosts:
            short = host.strip().lower().split(".", 1)[0]
            if not _HOST_RE.match(short):
                raise SplunkESQueryRefusedError(
                    f"Search refused: '{host}' is not a plain host name"
                )
            if f'"{short}*"' not in names:
                names.append(f'"{short}*"')
        if not names:
            raise SplunkESQueryRefusedError("Search refused: no host to search for")
        joined = ",".join(names)
        return self.store.render(
            "host_window_search",
            index=self.index,
            sourcetype_filter=self._sourcetype_filter(),
            host_filter=" OR ".join(f"{f} IN ({joined})" for f in HOST_FIELDS),
            earliest=_epoch(earliest),
            latest=_epoch(latest),
            fields=table_fields(),
            limit=self.limit,
        )

    def narrow(
        self,
        steps_by_location: dict[tuple[str, str], list[StepContext]],
        earliest: datetime,
        latest: datetime,
    ) -> str:
        """One search over the remembered (index, sourcetype) locations only."""
        groups = []
        for (index, sourcetype), steps in steps_by_location.items():
            if not is_safe_index(index) or not is_safe_sourcetype(sourcetype):
                continue
            clauses = step_clauses(steps)
            if not clauses:
                continue
            groups.append(
                f'(index={index} sourcetype="{sourcetype}" ({" OR ".join(clauses)}))'
            )
        if not groups:
            # Not a refusal: the caller falls back to the wide search.
            raise SplunkESValidationError("No usable remembered location")
        return self.store.render(
            "narrow_location_search",
            location_filter=" OR ".join(groups),
            earliest=_epoch(earliest),
            latest=_epoch(latest),
            fields=table_fields(),
            limit=self.limit,
        )
