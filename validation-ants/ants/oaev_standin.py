"""A small stand-in for the OpenAEV Python client (``pyoaev``).

Why it exists
    The Splunk observer reuses the ``splunk-es`` collector's search and
    matching code, and that code imports a few names from ``pyoaev``. On a
    machine where ``pyoaev`` cannot be installed the ants would not start.

What it is
    Our own code for the five pieces the ants' path through the collector
    touches: the signature type names, the expectation objects, the helper
    that compares a signature with an alert, and three names that only have to
    exist (the configuration holder, the collector daemon, the API client).
    It is written for this repository; it is not a copy of ``pyoaev``.

Rules
    * The real client always wins. The stand-in is used only when ``pyoaev``
      cannot be imported, or when ``OAEV_FORCE_STANDIN=1`` asks for it (that
      is how it is tested on a machine that has the real client).
    * It cannot talk to an OpenAEV platform. The API client and the collector
      daemon refuse to start. The ``splunk-es`` collector itself, its harness
      and its unit tests still need the real client.
    * A run says which one it used (see ``notice``).

``check_standin.py`` compares the stand-in with the real client, piece by
piece, on a machine that has both.
"""

from __future__ import annotations

import enum
import importlib.util
import os
import sys
import types
from typing import Any

FORCE_ENV = "OAEV_FORCE_STANDIN"
CLIENT, STANDIN = "client", "standin"


class StandinOnly(RuntimeError):
    """Raised when something needs the real OpenAEV client."""


def similarity(a: str, b: str) -> int:
    """How alike two strings are, as a whole number from 0 to 100.

    Twice the length of their longest common subsequence, over their combined
    length, as a percentage rounded half to even. Two equal strings give 100.
    """
    if a == b:
        return 100
    total = len(a) + len(b)
    previous = [0] * (len(b) + 1)
    for ch in a:
        current = [0]
        for j, other in enumerate(b, 1):
            current.append(previous[j - 1] + 1 if ch == other
                           else max(previous[j], current[j - 1]))
        previous = current
    whole, rest = divmod(200 * previous[-1], total)
    if 2 * rest > total or (2 * rest == total and whole % 2):
        whole += 1
    return whole


class DetectionHelper:
    """Says whether an alert carries every signature it is asked about.

    ``alert_data`` maps a signature type to how it is compared:
    ``{"type": "simple", "data": [...]}`` - the value appears in the data;
    ``{"type": "fuzzy", "data": [...], "score": n}`` - one of the data values
    is more than ``n`` alike. A signature whose type is not in
    ``relevant_signatures_types`` is left out. A relevant type missing from
    ``alert_data`` is a ``KeyError``, which the collector reports as no match.

    Not covered: the client's extra rule for ``command_line`` signatures. The
    collector never asks for that type.
    """

    def __init__(self, logger: Any, relevant_signatures_types: Any) -> None:
        self.logger = logger
        self.relevant_signatures_types = relevant_signatures_types

    def match_alert_elements(self, signatures: list[dict[str, Any]],
                             alert_data: dict[str, Any]) -> bool:
        # Every relevant signature is looked at, even after one has failed, so that alert data
        # missing a relevant type is always an error and never a quiet "no match".
        results = [self._matches(signature["value"], alert_data[signature["type"]])
                   for signature in signatures
                   if signature["type"] in self.relevant_signatures_types]
        return all(results)

    @staticmethod
    def _matches(value: str, entry: dict[str, Any]) -> bool:
        if entry["type"] == "simple":
            return value in str(entry["data"])
        if entry["type"] == "fuzzy":
            for seen in entry["data"]:
                if not isinstance(seen, str):
                    raise TypeError("a fuzzy comparison needs text")
                if similarity(seen, value) > entry["score"]:
                    return True
            return False
        return False


def build() -> dict[str, dict[str, Any]]:
    """The stand-in's contents, by the module name the collector imports from."""
    from uuid import UUID

    from pydantic import BaseModel

    class SignatureTypes(str, enum.Enum):
        """The signature types the splunk-es collector and the ants use."""

        SIG_TYPE_PARENT_PROCESS_NAME = "parent_process_name"
        SIG_TYPE_SOURCE_IPV4_ADDRESS = "source_ipv4_address"
        SIG_TYPE_SOURCE_IPV6_ADDRESS = "source_ipv6_address"
        SIG_TYPE_TARGET_IPV4_ADDRESS = "target_ipv4_address"
        SIG_TYPE_TARGET_IPV6_ADDRESS = "target_ipv6_address"
        SIG_TYPE_TARGET_HOSTNAME_ADDRESS = "target_hostname_address"
        SIG_TYPE_START_DATE = "start_date"
        SIG_TYPE_END_DATE = "end_date"

    class ExpectationSignature(BaseModel):
        type: SignatureTypes
        value: str

    class Expectation(BaseModel):
        """What one step is expected to leave behind: an id and its signatures."""

        inject_expectation_id: UUID
        inject_expectation_signatures: list[ExpectationSignature]
        success_label: str = "Success"
        failure_label: str = "Failure"

        def __init__(self, **data: Any) -> None:
            data.pop("api_client", None)      # there is no platform to report to
            super().__init__(**data)

        def update(self, *args: Any, **kwargs: Any) -> None:
            raise StandinOnly("reporting a result to OpenAEV needs the real client (pyoaev)")

    class DetectionExpectation(Expectation):
        success_label: str = "Detected"
        failure_label: str = "Not Detected"

    class PreventionExpectation(Expectation):
        success_label: str = "Prevented"
        failure_label: str = "Not Prevented"

    class Configuration:
        """Holds the settings the collector would hand to its daemon."""

        def __init__(self, config_hints: dict[str, Any] | None = None,
                     config_base_model: Any = None, **_: Any) -> None:
            self.config_hints = config_hints or {}
            self.config_base_model = config_base_model

    class CollectorDaemon:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise StandinOnly("running the collector needs the real client (pyoaev)")

    class OpenAEV:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise StandinOnly("talking to OpenAEV needs the real client (pyoaev)")

    return {
        "pyoaev": {},
        "pyoaev.apis": {},
        "pyoaev.apis.inject_expectation": {},
        "pyoaev.apis.inject_expectation.model": {
            "DetectionExpectation": DetectionExpectation,
            "PreventionExpectation": PreventionExpectation,
            "ExpectationSignature": ExpectationSignature,
        },
        "pyoaev.signatures": {},
        "pyoaev.signatures.types": {"SignatureTypes": SignatureTypes},
        "pyoaev.helpers": {"OpenAEVDetectionHelper": DetectionHelper},
        "pyoaev.configuration": {"Configuration": Configuration},
        "pyoaev.daemons": {"CollectorDaemon": CollectorDaemon},
        "pyoaev.client": {"OpenAEV": OpenAEV},
    }


def _real_client_installed() -> bool:
    try:
        return importlib.util.find_spec("pyoaev") is not None
    except (ImportError, ValueError):
        return False


def _install() -> None:
    for name, contents in build().items():
        module = types.ModuleType(name, "Stand-in for the OpenAEV client; see ants/oaev_standin.py")
        module.__standin__ = True  # type: ignore[attr-defined]
        module.__path__ = []       # type: ignore[attr-defined]
        module.__dict__.update(contents)
        sys.modules[name] = module
        parent, _, child = name.rpartition(".")
        if parent:
            setattr(sys.modules[parent], child, module)


_why = ""       # why the stand-in was chosen, for the notice


def ensure() -> str:
    """Make ``import pyoaev`` work. Says which one is in use: client or stand-in."""
    global _why
    loaded = sys.modules.get("pyoaev")
    if loaded is not None:
        return STANDIN if getattr(loaded, "__standin__", False) else CLIENT
    forced = os.environ.get(FORCE_ENV, "").strip().lower() in ("1", "true", "yes")
    installed = _real_client_installed()
    if installed and not forced:
        return CLIENT
    _why = f"{FORCE_ENV} is set" if installed else "pyoaev is not installed"
    _install()
    return STANDIN


def notice() -> str | None:
    """One line for a run's output when the stand-in is in use; nothing otherwise."""
    if ensure() != STANDIN:
        return None
    return f"OpenAEV client: built-in stand-in ({_why or 'loaded earlier'})"
