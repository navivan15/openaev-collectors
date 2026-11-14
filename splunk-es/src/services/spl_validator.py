"""Refuse any SPL the collector should never send.

Every search goes through :func:`validate_spl` right before it is sent. A
search is accepted only when:

* it starts with a plain base search (no generating command such as
  ``| rest`` or ``| inputlookup``),
* the base search names its ``index`` (not a bare ``*``) and a ``sourcetype``,
  and has a bounded time window (``earliest=`` and ``latest=``),
* every piped command is on the allow-list below (searching, filtering,
  counting, field selection, ordering and limiting),
* it contains no subsearch (``[...]``) and no macro (backticks), because
  either can hide a command the allow-list would refuse.

Anything that writes, deletes, sends, calls out or runs scripts is therefore
refused before it reaches Splunk.
"""

from __future__ import annotations

import re

from .exception import SplunkESValidationError

# The only commands a collector search may use.
ALLOWED_COMMANDS: tuple[str, ...] = (
    "search",  # searching
    "where",  # filtering
    "regex",  # filtering
    "dedup",  # filtering
    "stats",  # counting
    "fields",  # field selection
    "table",  # field selection
    "sort",  # ordering
    "head",  # limiting
    "tail",  # limiting
)

# Not needed for the decision (anything off the allow-list is refused), only
# to say *why* in the refusal message.
_REFUSAL_KIND = {
    "collect": "writes",
    "mcollect": "writes",
    "meventcollect": "writes",
    "tscollect": "writes",
    "outputlookup": "writes",
    "outputcsv": "writes",
    "outputtext": "writes",
    "summaryindex": "writes",
    "sichart": "writes",
    "sitop": "writes",
    "delete": "deletes",
    "sendemail": "sends",
    "sendalert": "sends",
    "rest": "calls out",
    "dbxquery": "calls out",
    "curl": "calls out",
    "script": "runs scripts",
    "run": "runs scripts",
    "runshellscript": "runs scripts",
    "map": "runs other searches",
    "savedsearch": "runs other searches",
    "loadjob": "runs other searches",
}


class SplunkESQueryRefusedError(SplunkESValidationError):
    """Raised when a search is refused by the validator. Nothing is sent."""

    pass


def _mask_quoted(spl: str) -> str:
    """Replace the content of double-quoted strings with spaces (same length)."""
    out = []
    in_quote = False
    escaped = False
    for ch in spl:
        if in_quote:
            if escaped:
                escaped = False
                out.append(" ")
            elif ch == "\\":
                escaped = True
                out.append(" ")
            elif ch == '"':
                in_quote = False
                out.append('"')
            else:
                out.append(" ")
        else:
            if ch == '"':
                in_quote = True
            out.append(ch)
    if in_quote:
        raise SplunkESQueryRefusedError("Search refused: unbalanced double quote")
    return "".join(out)


def split_pipeline(spl: str) -> list[str]:
    """Split a search on pipes that are outside quoted strings."""
    masked = _mask_quoted(spl)
    segments, start = [], 0
    for i, ch in enumerate(masked):
        if ch == "|":
            segments.append(spl[start:i])
            start = i + 1
    segments.append(spl[start:])
    return segments


def validate_spl(spl: str) -> None:
    """Raise SplunkESQueryRefusedError unless the search is safe to send."""
    if not spl or not spl.strip():
        raise SplunkESQueryRefusedError("Search refused: empty search")

    masked = _mask_quoted(spl)
    if "`" in masked:
        raise SplunkESQueryRefusedError("Search refused: macros are not allowed")
    if "[" in masked or "]" in masked:
        raise SplunkESQueryRefusedError("Search refused: subsearches are not allowed")

    segments = split_pipeline(spl)
    masked_segments = split_pipeline(masked)

    base = masked_segments[0].strip()
    if base.lower().startswith("search "):
        base = base[7:].strip()
    if not base:
        raise SplunkESQueryRefusedError(
            "Search refused: it must start with a base search, not a generating command"
        )

    # Find "index=" outside quoted strings (masked text), then read the value
    # from the real text at the same offset (the name itself may be quoted).
    indexes = []
    for found in re.finditer(r"\bindex\s*=\s*", masked_segments[0], re.IGNORECASE):
        value = re.match(r'"?([^\s"()]*)', segments[0][found.end() :])
        indexes.append(value.group(1) if value else "")
    if not indexes:
        raise SplunkESQueryRefusedError("Search refused: it does not name an index")
    for name in indexes:
        if not name or name.startswith("*"):
            raise SplunkESQueryRefusedError(
                "Search refused: the index must be named, not a wildcard"
            )
    if not re.search(r"\bsourcetype\s*(=|\bIN\s*\()", base, re.IGNORECASE):
        raise SplunkESQueryRefusedError("Search refused: it does not name a sourcetype")
    if not re.search(r"\bearliest\s*=", base, re.IGNORECASE) or not re.search(
        r"\blatest\s*=", base, re.IGNORECASE
    ):
        raise SplunkESQueryRefusedError(
            "Search refused: it has no bounded time window (earliest= and latest=)"
        )

    for segment in masked_segments[1:]:
        words = segment.strip().split()
        command = words[0].lower() if words else ""
        if command not in ALLOWED_COMMANDS:
            kind = _REFUSAL_KIND.get(command)
            detail = f" ({kind})" if kind else ""
            raise SplunkESQueryRefusedError(
                f"Search refused: command '{command or '(empty)'}' is not on the "
                f"allow-list{detail}. Allowed: {', '.join(ALLOWED_COMMANDS)}"
            )
