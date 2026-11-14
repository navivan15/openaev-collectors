"""Intel ant: reads a threat scenario from OpenCTI and lists its techniques.

It only reads. The input is a STIX 2.1 bundle, which is what OpenCTI exports
for a report or an intrusion set: the threat itself, ``attack-pattern``
objects carrying MITRE ATT&CK ids, and ``uses`` relationships between them.

Two ways in:

* ``IntelAnt.from_bundle(bundle)`` - a bundle you already have (a file
  exported from OpenCTI, or the same bundle OpenAEV's own STIX import takes).
* ``OpenCTIClient(...).report_bundle(report_id)`` - fetch it from OpenCTI's
  GraphQL API. Written against the mock in the sandbox; the query has not
  been checked against a real OpenCTI.

The intel ant never decides what to run. It hands the technique list to the
scenario builder.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import requests  # type: ignore[import-untyped]

_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
THREAT_TYPES = ("intrusion-set", "threat-actor", "campaign", "malware", "report")
# ATT&CK tactic order, used to put a scenario's steps in a believable sequence.
TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]


class IntelError(Exception):
    """The scenario could not be read from OpenCTI."""


@dataclass
class Technique:
    id: str  # ATT&CK id, e.g. T1059.001
    name: str
    tactic: str  # first kill-chain phase, "" when the bundle has none

    @property
    def order(self) -> int:
        return TACTIC_ORDER.index(self.tactic) if self.tactic in TACTIC_ORDER else 99


@dataclass
class Threat:
    """One threat scenario as OpenCTI describes it."""

    id: str
    name: str
    kind: str
    description: str
    techniques: list[Technique] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)  # attack patterns without an ATT&CK id

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "kind": self.kind,
                "description": self.description, "skipped": self.skipped,
                "techniques": [{"id": t.id, "name": t.name, "tactic": t.tactic}
                               for t in self.techniques]}


class IntelAnt:
    @staticmethod
    def from_bundle(bundle: dict[str, Any]) -> Threat:
        """Read the threat and the techniques it uses from a STIX bundle."""
        if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
            raise IntelError("This is not a STIX bundle")
        objects = [o for o in bundle.get("objects") or [] if isinstance(o, dict)]
        threat = next((o for kind in THREAT_TYPES for o in objects if o.get("type") == kind), None)
        if threat is None:
            raise IntelError("The bundle names no threat (intrusion set, campaign or report)")

        # Techniques the threat "uses"; for a report, the ones it refers to.
        wanted = {r.get("target_ref") for r in objects
                  if r.get("type") == "relationship" and r.get("relationship_type") == "uses"
                  and r.get("source_ref") == threat.get("id")}
        wanted |= set(threat.get("object_refs") or [])
        patterns = [o for o in objects if o.get("type") == "attack-pattern"
                    and (o.get("id") in wanted or not wanted)]

        techniques: dict[str, Technique] = {}
        skipped: list[str] = []
        for pattern in patterns:
            attack_id = next(
                (str(ref.get("external_id")) for ref in pattern.get("external_references") or []
                 if ref.get("source_name") == "mitre-attack"
                 and _TECHNIQUE_RE.match(str(ref.get("external_id") or ""))), None)
            if not attack_id:
                skipped.append(str(pattern.get("name") or pattern.get("id")))
                continue
            phases = pattern.get("kill_chain_phases") or []
            tactic = str(phases[0].get("phase_name")) if phases else ""
            techniques.setdefault(attack_id, Technique(
                id=attack_id, name=str(pattern.get("name") or attack_id), tactic=tactic))
        if not techniques:
            raise IntelError("The bundle has no ATT&CK technique to build tests from")
        ordered = sorted(techniques.values(), key=lambda t: (t.order, t.id))
        return Threat(id=str(threat.get("id")), name=str(threat.get("name") or "Unnamed threat"),
                      kind=str(threat.get("type")),
                      description=str(threat.get("description") or ""),
                      techniques=ordered, skipped=skipped)


class OpenCTIClient:
    """Read-only OpenCTI client: fetches one report as a STIX bundle."""

    QUERY = "query Bundle($id: String!) { report(id: $id) { toStixReportBundle } }"

    def __init__(self, base_url: str, token: str, timeout: int = 20) -> None:
        self.base_url = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {token}"}
        self.timeout = timeout

    def report_bundle(self, report_id: str) -> dict[str, Any]:
        import json

        try:
            response = requests.post(
                self.base_url + "/graphql", headers=self._headers, timeout=self.timeout,
                json={"query": self.QUERY, "variables": {"id": report_id}})
        except (requests.ConnectionError, requests.Timeout) as e:
            raise IntelError(f"OpenCTI could not be reached: {e}") from e
        if response.status_code in (401, 403):
            raise IntelError("OpenCTI rejected the sign-in")
        if response.status_code != 200:
            raise IntelError(f"OpenCTI answered {response.status_code}")
        body = response.json()
        if body.get("errors"):
            raise IntelError(f"OpenCTI reported errors: {body['errors']}")
        raw = ((body.get("data") or {}).get("report") or {}).get("toStixReportBundle")
        if not raw:
            raise IntelError(f"OpenCTI has no report '{report_id}'")
        return json.loads(raw) if isinstance(raw, str) else raw
