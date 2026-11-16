"""Change-and-undo actions: the rules every one of them must pass.

A read-only action cannot imitate an attack that changes the system (a
scheduled task, a logon autostart, a hidden file). A change-and-undo action
can, and stays benign, because of what it is allowed to be:

1. One small change, then an undo, then a check that the undo worked. All
   three are part of the action; none can be left out.
2. Everything it creates is named with the step marker, so it cannot be
   mistaken for anything real, and its undo can only remove that.
3. Anything it sets up to launch is exactly the harmless payload: a command
   that prints the marker.
4. Current user only: no administrator rights, nothing machine-wide.
5. No network, no passwords, nothing in anyone's own folders.
6. Only a short list of built-in tools, each only in the form it is used here.

These rules are checked when the file is loaded; an entry that breaks one
stops the load. Two more controls sit outside this file: change-and-undo
actions are off unless a run switches them on, and the gatekeeper lets them
run only on machines a person listed as dedicated test machines, and blocks
a machine whose undo could not be confirmed until a person clears it.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

REVERSIBLE_PATH = Path(__file__).with_name("reversible.json")
ARTIFACT = "oaev-step-{marker}"
PREFIX = "cmd.exe /c "
_TOOLS = {"schtasks", "reg", "attrib", "bitsadmin", "copy", "certutil", "cscript", "echo", "type", "del", "dir"}
_FORBIDDEN: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"https?://|ftp://", re.I), "reaches the internet"),
    (re.compile(r"\\\\\\\\"), "reaches another machine"),
    (re.compile(r"lsass|mimikatz|procdump|ntds|\\sam\b|\\security\b|passw|credential", re.I),
     "touches passwords or credentials"),
    (re.compile(r"%userprofile%|%appdata%|%localappdata%|c:\\users|\\documents\b|\\desktop\b|\\downloads\b", re.I),
     "touches people's own folders"),
    (re.compile(r"\bhklm\b|\bhkcr\b|\bhku\b|hkey_local_machine|hkey_classes_root|hkey_users", re.I),
     "changes the registry outside the current user"),
    (re.compile(r"(?<!\w)/(ru|rl|rp|s|u|p)\b|\brunas\b", re.I), "asks for other rights or another machine"),
    (re.compile(r"[`^()]|\$\(|\|"), "uses shell features the checker cannot read"),
]


class ReversibleError(ValueError):
    """A change-and-undo action breaks the rules."""


def _parts(text: str) -> list[str]:
    return [p.strip() for p in re.split(r"\s*&\s*", text[len(PREFIX):]) if p.strip()]


def _tool(part: str) -> str:
    word = part.split()[0].strip('"').lower()
    return word[:-4] if word.endswith(".exe") and "\\" not in word else word


def check_reversible(action: dict[str, Any], payload: str) -> list[str]:
    """Every rule a change-and-undo action breaks. An empty list means it passes."""
    problems: list[str] = []
    if not action.get("reversible"):
        problems.append("is not marked as a change-and-undo action")
    if action.get("elevation") or action.get("agentless"):
        problems.append("asks for administrator rights or has no agent to undo it")
    if not str(action.get("changes") or "").strip():
        problems.append("does not say what it changes")
    for key in ("command", "cleanup", "verify"):
        text = str(action.get(key) or "")
        if not text:
            problems.append(f"has no {key}")
            continue
        if not text.startswith(PREFIX) or ARTIFACT not in text:
            problems.append(f"its {key} does not name the marked artifact")
            continue
        for pattern, why in _FORBIDDEN:
            if pattern.search(text[len(PREFIX):]):
                problems.append(f"its {key} {why}")
        for part in _parts(text):
            tool = _tool(part)
            own = part.split()[0].lower().startswith("%temp%\\" + ARTIFACT.lower())
            if not own and tool not in _TOOLS:
                problems.append(f"its {key} uses '{tool}', which is not on the list")
            problems += [f"its {key}: {p}" for p in _form_problems(tool, part, payload)]
        # Whatever is written, hidden or deleted must be the marked artifact, in the temp folder.
        for target in re.findall(r"(?:>\s*|\bdel\s+|\battrib\s+[+-]h\s+|-decode\s+\S+\s+)(\S+)", text):
            if not target.lower().startswith("%temp%\\" + ARTIFACT.lower()):
                problems.append(f"its {key} writes or deletes '{target}', which is not the marked artifact")
    verify_tools = {_tool(p) for p in _parts(str(action.get("verify") or PREFIX))}
    if verify_tools - {"schtasks", "reg", "bitsadmin", "dir"}:
        problems.append("its check does more than look")
    return list(dict.fromkeys(problems))


def _form_problems(tool: str, part: str, payload: str) -> list[str]:
    """Each change tool only in the form these actions use."""
    low, out = part.lower(), []
    words = low.split()
    if tool == "schtasks":
        if len(words) < 2 or words[1] not in ("/create", "/delete", "/query"):
            out.append("schtasks only as /create, /delete or /query")
        if f"/tn {ARTIFACT}" not in part:
            out.append("the task is not named with the marker")
        if "/create" in words and f'/tr "{payload}"' not in part:
            out.append("the task would launch something other than the harmless payload")
    elif tool == "reg":
        if len(words) < 3 or words[1] not in ("add", "delete", "query") or not words[2].startswith("hkcu\\"):
            out.append("reg only as add, delete or query under the current user")
        if f"/v {ARTIFACT}" not in part:
            out.append("the registry value is not named with the marker")
        data = re.search(r'/d\s+("[^"]*"|\S+)', part)
        if data and data.group(1).strip('"') not in (payload, "1"):
            out.append("the registry value would launch something other than the harmless payload")
    elif tool == "bitsadmin":
        if len(words) != 3 or words[1] not in ("/create", "/cancel", "/info") or words[2] != ARTIFACT.lower():
            out.append("bitsadmin only to create, cancel or look at the marked job")
    elif tool == "copy":
        if len(words) != 3 or words[1] != "%systemroot%\\system32\\whoami.exe":
            out.append("copy only of the built-in whoami tool")
        elif not words[2].startswith("%temp%\\" + ARTIFACT.lower()):
            out.append("the copy is not named with the marker")
    elif tool == "certutil":
        if len(words) != 4 or words[1] != "-decode":
            out.append("certutil only to decode the marked file")
    elif tool == "cscript":
        if len(words) != 3 or words[1] != "//nologo" or not words[2].startswith("%temp%\\" + ARTIFACT.lower()):
            out.append("cscript only on the marked script")
    elif tool == "type":
        if words[:3] != ["type", "nul", ">"]:
            out.append("type only to create an empty file")
    elif tool == "attrib":
        if len(words) != 3 or words[1] not in ("+h", "-h"):
            out.append("attrib only to hide or unhide the marked file")
    return out


def load_reversible(path: Path | str = REVERSIBLE_PATH) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """The change-and-undo actions and their technique names. Raises on any broken rule."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    payload = str(data.get("payload") or "")
    if payload != PREFIX + "echo " + ARTIFACT:
        raise ReversibleError("the payload is not the harmless one")
    for action_id, action in data["actions"].items():
        problems = check_reversible(action, payload)
        if problems:
            raise ReversibleError(f"Change-and-undo action '{action_id}' {'; '.join(problems)}")
    return data["actions"], data.get("techniques", {})
