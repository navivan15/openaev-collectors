"""Librarian ant: finds a public test for a technique the library has no action for.

When a scenario names a technique that has no action on the allow-list, the
librarian looks the technique up in a public library of attack tests (the
Atomic Red Team index, read from a local file), throws out every test that is
not harmless by fixed rules, adds the step marker to the first one left, and
writes a *draft* action for a person.

What it is not:

* It does not invent anything. It finds, filters and adapts. A technique with
  no harmless public test stays a gap.
* It does not use a model. Every decision is a rule below.
* It never downloads, and it never runs a command. The index is a file someone
  put there; the sandbox trial is the simulated agent.
* It cannot put an action on the allow-list. A draft becomes usable only when
  it has passed its sandbox trial and a person has approved it; the approval is
  bound to the exact action, and the rules are checked again every time the
  approved actions are loaded.

The rules are an allow-list, not a block-list: a command passes only when every
part of it is a known read-only tool used in a known read-only way. Anything
the checker does not recognise is refused.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml  # type: ignore[import-untyped]

SOURCE = {"library": "Atomic Red Team", "licence": "MIT",
          "url": "https://github.com/redcanaryco/atomic-red-team"}
MAX_COMMAND = 400
MAX_PARTS = 6
_ID_RE = re.compile(r"^(art|ai)_[a-z0-9_]{3,60}$")   # art_: public test, ai_: model draft
_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_ARGUMENT_RE = re.compile(r"^[A-Za-z0-9 _.:\\/\-*%]{0,120}$")
_WORD_RE = re.compile(r'"[^"]*"|\S+')


class LibrarianError(ValueError):
    """A draft or an approval was refused."""


# ---------------------------------------------------------------------------
# Rules: what a harmless command may consist of
# ---------------------------------------------------------------------------
# Refused wherever they appear, whatever the tool.
_FORBIDDEN: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r">"), "writes to a file"),
    (re.compile(r"[`^{}()]|\$"), "uses shell features the checker cannot read"),
    (re.compile(r"https?://|ftp://", re.I), "reaches the internet"),
    (re.compile(r"\\\\"), "reaches another machine"),
    (re.compile(r"lsass|mimikatz|procdump|ntds|\\sam\b|\\security\b|passw|credential|"
                r"key=clear|cpassword|vaultcmd", re.I), "touches passwords or credentials"),
    (re.compile(r"(?<!\w)/(add|delete|del|create|change|active|purge|flush\w*|renew|release|"
                r"register\w*|run|end|f|maxpwage|minpwage|minpwlen|uniquepw|lockout\w*)\b", re.I),
     "changes something"),
]


def _words(args: str) -> list[str]:
    return [w.strip('"') for w in _WORD_RE.findall(args)]


def _any(_: str) -> str | None:
    return None


def _bare(args: str) -> str | None:
    return None if not args.strip() else "is only harmless without arguments"


def _first_in(*allowed: str) -> Callable[[str], str | None]:
    def rule(args: str) -> str | None:
        words = _words(args.lower())
        return None if words and words[0] in allowed else \
            f"only its read-only forms are allowed ({', '.join(allowed)})"
    return rule


def _only_flags(*allowed: str) -> Callable[[str], str | None]:
    def rule(args: str) -> str | None:
        extra = [w for w in _words(args.lower()) if w not in allowed]
        return f"'{extra[0]}' is not one of its read-only options" if extra else None
    return rule


def _not_remote(args: str) -> str | None:
    return "asks another machine" if re.search(r"(?<!\w)/s\b|/server:", args, re.I) else None


def _net(args: str) -> str | None:
    words = _words(args.lower())
    if not words:
        return "needs a sub-command"
    sub, rest = words[0], words[1:]
    flags = [w for w in rest if w.startswith("/")]
    names = [w for w in rest if not w.startswith("/")]
    if any(f != "/domain" for f in flags):
        return f"'{flags[0]}' is not a read-only option"
    if sub in ("user", "group", "localgroup"):
        # 'net user NAME NEWPASSWORD' sets a password: one name at most.
        return "more than one name: that form changes an account" if len(names) > 1 else None
    if sub in ("accounts", "share", "use", "view", "start"):
        return f"'net {sub}' is only harmless with nothing after it" if names else None
    if sub == "config":
        return None if names in (["workstation"], ["server"]) else "only 'workstation' or 'server'"
    return f"'net {sub}' is not on the read-only list"


def _wmic(args: str) -> str | None:
    if re.search(r"\b(call|create|delete|set|terminate|uninstall)\b", args, re.I):
        return "changes something"
    if _not_remote(args) or re.search(r"/node:", args, re.I):
        return "asks another machine"
    return None if re.search(r"\b(get|list)\b", args, re.I) else "only 'get' and 'list' are read-only"


def _netsh(args: str) -> str | None:
    if re.search(r"\b(add|set|delete|import|export|reset|dump|exec)\b", args, re.I):
        return "changes something"
    return None if re.search(r"\bshow\b", args, re.I) else "only 'show' is read-only"


def _schtasks(args: str) -> str | None:
    return None if re.search(r"(?<!\w)/query\b", args, re.I) and not _not_remote(args) \
        else "only '/query' on this machine is read-only"


def _nltest(args: str) -> str | None:
    allowed = ("/dclist:", "/domain_trusts", "/dsgetdc:", "/trusted_domains", "/all_trusts")
    bad = [w for w in _words(args.lower()) if not w.startswith(allowed)]
    return f"'{bad[0]}' is not one of its read-only options" if bad else None


# Tool -> rule for its arguments. A tool that is not here is refused.
CMD_TOOLS: dict[str, Callable[[str], str | None]] = {
    "whoami": _any, "hostname": _bare, "ver": _bare, "set": _bare, "chcp": _bare,
    "systeminfo": _not_remote, "tasklist": _not_remote, "getmac": _not_remote,
    "driverquery": _not_remote, "qwinsta": _not_remote, "quser": _not_remote,
    "netstat": _any, "dir": _any, "tree": _any, "where": _any, "echo": _any, "dsquery": _any,
    "ipconfig": _only_flags("/all", "/displaydns"),
    "arp": _only_flags("-a", "-g"),
    "route": _only_flags("print"),
    "gpresult": _only_flags("/r", "/z", "/v"),
    "time": _only_flags("/t"), "date": _only_flags("/t"),
    "w32tm": _first_in("/tz", "/query"),
    "fsutil": _first_in("fsinfo"),
    "query": _first_in("user", "session", "process"),
    "reg": _first_in("query"),
    "sc": _first_in("query", "queryex", "qc"),
    "wevtutil": _first_in("el", "enum-logs", "gl", "get-log", "gli", "get-loginfo"),
    "net": _net, "wmic": _wmic, "netsh": _netsh, "schtasks": _schtasks, "nltest": _nltest,
    # Filters after a pipe.
    "findstr": _any, "find": _any, "more": _bare, "sort": _any,
}

# PowerShell: single read-only cmdlets with plain parameters, nothing else.
POWERSHELL_CMDLETS = frozenset(c.lower() for c in (
    "Get-Process", "Get-Service", "Get-LocalUser", "Get-LocalGroup", "Get-LocalGroupMember",
    "Get-NetIPAddress", "Get-NetIPConfiguration", "Get-NetAdapter", "Get-NetTCPConnection",
    "Get-NetNeighbor", "Get-NetRoute", "Get-ComputerInfo", "Get-CimInstance", "Get-WmiObject",
    "Get-HotFix", "Get-Date", "Get-TimeZone", "Get-Culture", "Get-ChildItem", "Get-ItemProperty",
    "Get-ScheduledTask", "Get-SmbShare", "Get-PSDrive", "Get-Volume", "Get-Disk",
    "Get-ADUser", "Get-ADGroup", "Get-ADComputer", "Get-ADDomain", "Get-ADGroupMember",
))


def _check_part(part: str) -> str | None:
    words = _WORD_RE.findall(part)
    if not words:
        return "has an empty part"
    tool = words[0].strip('"').lower()
    if "\\" in tool or "/" in tool or ":" in tool:
        return f"names a program by its path ('{words[0]}')"
    tool = tool[:-4] if tool.endswith(".exe") else tool
    rule = CMD_TOOLS.get(tool)
    if rule is None:
        return f"'{tool}' is not on the list of read-only tools"
    problem = rule(part[len(words[0]):].strip())
    return f"'{tool}': {problem}" if problem else None


def check_command(command: str, executor: str) -> tuple[str | None, list[str]]:
    """Return (the command as one line, []) when it is harmless by the rules,
    or (None, reasons) when it is not."""
    lines = [ln.strip() for ln in str(command or "").splitlines() if ln.strip()]
    lines = [ln for ln in lines if not re.match(r"(?i)^(rem\b|::|#)", ln)]
    if not lines:
        return None, ["has no command"]
    reasons: list[str] = []
    text = " & ".join(lines)
    for pattern, why in _FORBIDDEN:
        if pattern.search(text) and why not in reasons:
            reasons.append(why)
    if len(text) > MAX_COMMAND:
        reasons.append("is too long to review")
    if executor == "powershell":
        if len(lines) != 1 or re.search(r'[|;&"\']', text):
            reasons.append("PowerShell is only accepted as one plain command")
        else:
            words = text.split()
            if words[0].lower() not in POWERSHELL_CMDLETS:
                reasons.append(f"'{words[0]}' is not on the list of read-only commands")
            if re.search(r"(?i)-(computername|cimsession|credential|session)\b", text):
                reasons.append("asks another machine")
            if not re.match(r"^[A-Za-z0-9 _.:\\\-*,/]*$", text):
                reasons.append("has characters the checker cannot read")
    else:
        parts = [p.strip() for p in re.split(r"&&|\|\||&|\||;", text)]
        if len(parts) > MAX_PARTS:
            reasons.append("has too many parts to review")
        for part in parts:
            problem = _check_part(part)
            if problem and problem not in reasons:
                reasons.append(problem)
    return (None, reasons) if reasons else (text, [])


def check_test(test: dict[str, Any]) -> tuple[str | None, str, list[str]]:
    """Check one public test. Returns (command or None, executor, reasons)."""
    executor = test.get("executor") or {}
    name = str(executor.get("name") or "")
    reasons: list[str] = []
    platforms = [str(p).lower() for p in test.get("supported_platforms") or []]
    if "windows" not in platforms:
        reasons.append("is not a Windows test")
    if name not in ("command_prompt", "powershell"):
        reasons.append("is a manual step or uses another shell")
    if executor.get("elevation_required"):
        reasons.append("needs administrator rights")
    if test.get("dependencies"):
        reasons.append("needs something installed or downloaded first")
    if str(executor.get("cleanup_command") or "").strip():
        reasons.append("needs cleaning up afterwards, so it changes something")
    command = str(executor.get("command") or "")
    for key, spec in (test.get("input_arguments") or {}).items():
        default = str((spec or {}).get("default", ""))
        if not _ARGUMENT_RE.match(default) or ".." in default:
            reasons.append(f"its setting '{key}' is not a plain value")
            default = ""
        command = command.replace("#{" + str(key) + "}", default)
    if "#{" in command:
        reasons.append("has a setting with no value")
    checked, problems = check_command(command, name)
    reasons += [p for p in problems if p not in reasons]
    return (None if reasons else checked), name, reasons


def wrap(command: str, executor: str) -> str:
    """The action's command template: the public command plus the step marker."""
    if executor == "powershell":
        return f"powershell.exe -NoProfile -Command {command} # oaev-step-{{marker}}"
    return f"cmd.exe /c {command} & rem oaev-step-{{marker}}"


def digest(action: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(action, sort_keys=True).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# The ant
# ---------------------------------------------------------------------------
class Librarian:
    def __init__(self, index_path: Path | str, actions: dict[str, dict[str, Any]],
                 not_simulated: dict[str, str], store_dir: Path | str) -> None:
        self.actions = actions
        self.not_simulated = not_simulated
        self.store_dir = Path(store_dir)
        self.index_path = Path(index_path)
        # yaml.safe_load only builds plain data; nothing in the file is executed.
        raw = yaml.safe_load(self.index_path.read_text(encoding="utf-8")) or {}
        self.by_technique: dict[str, dict[str, Any]] = {}
        for tactic, techniques in raw.items():
            for technique, entry in (techniques or {}).items():
                if not _TECHNIQUE_RE.match(str(technique)) or not isinstance(entry, dict):
                    continue
                known = self.by_technique.setdefault(str(technique), {
                    "name": str((entry.get("technique") or {}).get("name") or technique),
                    "tactic": str(tactic), "tests": []})
                seen = {t.get("auto_generated_guid") for t in known["tests"]}
                known["tests"] += [t for t in entry.get("atomic_tests") or []
                                   if isinstance(t, dict) and t.get("auto_generated_guid") not in seen]

    # -- store ----------------------------------------------------------------

    def _path(self, draft_id: str) -> Path:
        if not _ID_RE.match(draft_id):
            raise LibrarianError(f"'{draft_id}' is not a draft id")
        return self.store_dir / f"{draft_id}.json"

    def load(self, draft_id: str) -> dict[str, Any]:
        path = self._path(draft_id)
        if not path.exists():
            raise LibrarianError(f"There is no draft '{draft_id}'")
        return json.loads(path.read_text(encoding="utf-8"))

    def _save(self, draft: dict[str, Any]) -> None:
        self.store_dir.mkdir(parents=True, exist_ok=True)
        self._path(draft["id"]).write_text(json.dumps(draft, indent=2), encoding="utf-8")

    def drafts(self) -> list[dict[str, Any]]:
        if not self.store_dir.exists():
            return []
        return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(self.store_dir.glob("*.json"))
                if _ID_RE.match(p.stem)]

    # -- checks ---------------------------------------------------------------

    def _refused_family(self, technique: str) -> str | None:
        return self.not_simulated.get(technique) or self.not_simulated.get(technique.split(".", 1)[0])

    def _problems(self, draft: dict[str, Any]) -> list[str]:
        """Everything that must still hold for a stored draft. Empty means fine."""
        action = draft.get("action") or {}
        problems = []
        if self._refused_family(str(draft.get("technique"))):
            problems.append("its technique is in a family the ants refuse")
        checked, reasons = check_command(str(draft.get("source_command") or ""),
                                         str(draft.get("executor") or ""))
        problems += reasons
        if checked is not None and action.get("command") != wrap(checked, str(draft.get("executor"))):
            problems.append("its command is not the checked public command plus the marker")
        if action.get("techniques") != [draft.get("technique")]:
            problems.append("its technique was changed")
        return problems

    # -- finding --------------------------------------------------------------

    def find(self, technique: str) -> dict[str, Any]:
        """Look one technique up. Writes a draft when a harmless public test exists."""
        out: dict[str, Any] = {"technique": technique, "name": technique, "tactic": "",
                               "status": "", "why": "", "draft_id": None, "command": None,
                               "candidates": []}
        if not _TECHNIQUE_RE.match(technique):
            return {**out, "status": "not a technique id", "why": "The id is not an ATT&CK technique id."}
        entry = self.by_technique.get(technique)
        if entry:
            out.update(name=entry["name"], tactic=entry["tactic"])
        have = next((n for n, a in self.actions.items() if technique in a.get("techniques", [])), None)
        if have:
            return {**out, "status": "already in the library", "why": f"Action '{have}' covers it."}
        family = self._refused_family(technique)
        if family:
            # Not even looked up: a harmless-looking test must not open a refused family.
            return {**out, "status": "refused family", "why": family}
        existing = next((d for d in self.drafts() if d["technique"] == technique), None)
        if existing:
            return {**out, "status": existing["status"], "draft_id": existing["id"],
                    "command": existing["action"]["command"], "candidates": existing["candidates"],
                    "why": "A draft for this technique already exists."}
        if not entry or not entry["tests"]:
            return {**out, "status": "not in the public library",
                    "why": f"{SOURCE['library']} has no test for this technique."}

        passed = []
        for test in entry["tests"]:
            command, executor, reasons = check_test(test)
            out["candidates"].append({
                "name": str(test.get("name")), "guid": str(test.get("auto_generated_guid")),
                "verdict": "rejected" if reasons else "harmless by the rules", "why": reasons})
            if command:
                passed.append((executor != "command_prompt", len(command), command, executor, test))
        if not passed:
            return {**out, "status": "nothing harmless found",
                    "why": f"{len(entry['tests'])} public test(s), each refused by the rules."}
        _, _, command, executor, test = sorted(passed, key=lambda p: p[:2])[0]
        guid = str(test["auto_generated_guid"])
        draft = self.new_draft(
            draft_id=f"art_{technique.lower().replace('.', '_')}_{re.sub(r'[^0-9a-f]', '', guid.lower())[:8]}",
            technique=technique, name=entry["name"], tactic=entry["tactic"], command=command,
            executor=executor, fidelity="full", candidates=out["candidates"],
            description=f"{test.get('name')}. A public test, checked as read-only and marked.",
            source={**SOURCE, "test": str(test.get("name")), "guid": guid})
        draft_id = draft["id"]
        return {**out, "status": "draft", "draft_id": draft_id, "command": draft["action"]["command"],
                "why": f"{len(passed)} of {len(entry['tests'])} public test(s) passed the rules. "
                       f"Waiting for a sandbox trial and a person's approval."}

    def new_draft(self, *, draft_id: str, technique: str, name: str, tactic: str, command: str,
                  executor: str, fidelity: str, description: str, source: dict[str, Any],
                  candidates: list[dict[str, Any]]) -> dict[str, Any]:
        """Write a draft action. The only way a draft comes to exist, whoever proposes it.

        The command is checked here again, so nothing reaches the store unchecked.
        """
        if not _TECHNIQUE_RE.match(technique) or self._refused_family(technique):
            raise LibrarianError(f"No draft can be written for {technique}")
        checked, reasons = check_command(command, executor)
        if checked is None:
            raise LibrarianError(f"The command is not harmless by the rules: {'; '.join(reasons)}")
        draft = {
            "id": draft_id, "status": "draft", "technique": technique, "name": name, "tactic": tactic,
            "executor": executor, "source_command": checked,
            "created": datetime.now(timezone.utc).isoformat(), "candidates": candidates, "trial": None,
            "action": {
                "description": description, "command": wrap(checked, executor),
                "techniques": [technique], "category": "endpoint", "fidelity": fidelity,
                "expect": {"splunk": "detection"}, "source": source,
            },
        }
        self._path(draft_id)                      # refuses an id that is not a draft id
        self._save(draft)
        return draft

    def fill_gaps(self, techniques: list[str]) -> list[dict[str, Any]]:
        return [self.find(t) for t in techniques]

    # -- trial and approval ---------------------------------------------------

    def record_trial(self, draft_id: str, passed: bool, notes: str) -> dict[str, Any]:
        """Record what the sandbox trial of a draft showed."""
        draft = self.load(draft_id)
        if draft["status"] != "draft":
            raise LibrarianError(f"Draft '{draft_id}' is '{draft['status']}', not a draft")
        draft["trial"] = {"passed": bool(passed), "notes": notes,
                          "at": datetime.now(timezone.utc).isoformat(),
                          "digest": digest(draft["action"])}
        self._save(draft)
        return draft

    def approve(self, draft_id: str, by: str) -> dict[str, Any]:
        """A person approves the draft exactly as it is now."""
        if not by or not by.strip():
            raise LibrarianError("An approval needs a person")
        draft = self.load(draft_id)
        if draft["status"] != "draft":
            raise LibrarianError(f"Draft '{draft_id}' is '{draft['status']}', not a draft")
        problems = self._problems(draft)
        if problems:
            raise LibrarianError(f"Draft '{draft_id}' is not harmless by the rules: {'; '.join(problems)}")
        trial = draft.get("trial") or {}
        if not trial.get("passed") or trial.get("digest") != digest(draft["action"]):
            raise LibrarianError(f"Draft '{draft_id}' has not passed a sandbox trial as it is now")
        draft.update(status="approved", approved_by=by.strip(),
                     approved_at=datetime.now(timezone.utc).isoformat(),
                     approved_digest=digest(draft["action"]))
        self._save(draft)
        return draft

    def approved_actions(self) -> dict[str, dict[str, Any]]:
        """Actions a person approved, still unchanged and still harmless by the rules."""
        out = {}
        for draft in self.drafts():
            if draft.get("status") != "approved" or not draft.get("approved_by"):
                continue
            if draft.get("approved_digest") != digest(draft["action"]) or self._problems(draft):
                continue
            out[draft["id"]] = draft["action"]
        return out

    # -- survey ---------------------------------------------------------------

    def survey(self) -> dict[str, Any]:
        """How far the public library would close the gaps. Writes nothing."""
        tally = {"already in the library": 0, "refused family": 0, "harmless test found": 0,
                 "nothing harmless found": 0}
        reasons: dict[str, int] = {}
        for technique, entry in sorted(self.by_technique.items()):
            if any(technique in a.get("techniques", []) for a in self.actions.values()):
                tally["already in the library"] += 1
            elif self._refused_family(technique):
                tally["refused family"] += 1
            else:
                found = False
                for test in entry["tests"]:
                    command, _, why = check_test(test)
                    found = found or bool(command)
                    for r in why:
                        key = re.sub(r"'[^']*'", "'...'", r)
                        reasons[key] = reasons.get(key, 0) + 1
                tally["harmless test found" if found else "nothing harmless found"] += 1
        return {"techniques": len(self.by_technique),
                "tests": sum(len(e["tests"]) for e in self.by_technique.values()),
                "tally": tally,
                "top_reasons": sorted(reasons.items(), key=lambda kv: -kv[1])[:10]}
