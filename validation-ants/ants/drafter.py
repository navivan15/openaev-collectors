"""Drafter ant: asks a model for a harmless test when no public test fits.

This is the only ant that uses a model, and it is called only when the
librarian found nothing: the technique has no public test, or every public
test changes something.

What the model is asked for is deliberately small: ONE Windows command that
uses the same built-in tool the technique uses, in a form that only reads.
That is the "partial" kind of action the library already has (for example the
port-proxy tool run in show mode). The model is not asked for, and cannot get
through, anything else:

* Its answer is data. It is parsed as a small JSON object; anything else is
  thrown away.
* The command goes through exactly the same rules as a public test
  (librarian.check_command): an allow-list of read-only tools in read-only
  forms. A refused answer is sent back to the model with the reasons, a
  limited number of times.
* The model is never asked about a technique in a refused family, or one the
  library already covers.
* What passes becomes a draft like any other: sandbox trial, then a person's
  approval, with the rules checked again every time approved actions load.
  The model cannot approve anything.
* The request holds the technique's id and public name and nothing else: no
  scenario name, no host, no log.

The model is whatever callable is handed in. In the sandbox it is a scripted
stand-in. With a chat-only model, ``request()`` gives the text to paste and
``read_answer()`` checks what comes back.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable

from .librarian import Librarian, LibrarianError, check_command

MAX_TRIES = 3
_PLAIN = re.compile(r"[^A-Za-z0-9 ,.'/\-]")

REQUEST = """You are helping a defensive security team test that their own tools notice attacker behaviour.
The test must be harmless.

ATT&CK technique: {technique} ({name})

Give ONE Windows command that uses the same built-in tool this technique uses, in a form that ONLY READS:
it must not create, change, delete, start, stop or download anything, must not need administrator rights,
and must not touch passwords or another machine. One plain command, no pipes into scripts, no PowerShell
scripts, no redirection.

Answer with JSON only, in exactly this shape:
{{"command": "<the command>", "why": "<one sentence: how this imitates the technique>"}}
If no such command exists, answer:
{{"command": null, "why": "<one sentence>"}}"""

RETRY = """Your command was refused by fixed safety rules: {reasons}.
Answer again in the same JSON shape with a command that only reads, or with "command": null."""


class Drafter:
    def __init__(self, librarian: Librarian, model: Callable[[str], str], model_name: str) -> None:
        self.librarian = librarian
        self.model = model
        self.model_name = model_name
        self.calls = 0

    # -- the two halves, usable on their own for a chat-only model ----------------

    def request(self, technique: str, name: str) -> str:
        """The text sent to the model. Only the technique's public id and name."""
        return REQUEST.format(technique=technique, name=_PLAIN.sub("", name)[:80])

    @staticmethod
    def read_answer(answer: str) -> tuple[str | None, str, list[str]]:
        """Check one answer. Returns (command or None, the model's reason, problems)."""
        try:
            data = json.loads(str(answer).strip())
        except ValueError:
            return None, "", ["the answer is not the JSON that was asked for"]
        if not isinstance(data, dict) or set(data) - {"command", "why"}:
            return None, "", ["the answer is not the JSON that was asked for"]
        why = _PLAIN.sub("", str(data.get("why") or ""))[:160]
        command = data.get("command")
        if command is None:
            return None, why, []                       # the model declined: not a problem
        if not isinstance(command, str) or len(command) > 200:
            return None, why, ["the command is not a short piece of text"]
        checked, reasons = check_command(command, "command_prompt")
        return checked, why, reasons

    # -- the ant ---------------------------------------------------------------------

    def draft(self, technique: str, name: str, tactic: str) -> dict[str, Any]:
        """Ask the model for a harmless test for one technique. Writes a draft when one passes."""
        out: dict[str, Any] = {"technique": technique, "name": name, "tactic": tactic, "status": "",
                               "why": "", "draft_id": None, "command": None, "model": self.model_name,
                               "tries": []}
        known = self.librarian.find(technique)
        if known["status"] in ("already in the library", "refused family", "not a technique id",
                               "draft", "approved"):
            # Nothing to ask a model: covered, refused for good, or already drafted.
            return {**out, "status": known["status"], "why": known["why"], "draft_id": known["draft_id"],
                    "command": known["command"]}
        text = self.request(technique, name)
        for attempt in range(1, MAX_TRIES + 1):
            self.calls += 1
            try:
                answer = self.model(text)
            except Exception as e:                     # a model that fails is a gap, not a crash
                return {**out, "status": "model not reachable", "why": f"{type(e).__name__}: {e}"}
            command, why, problems = self.read_answer(answer)
            out["tries"].append({"attempt": attempt, "answer": str(answer)[:240],
                                 "verdict": "refused" if problems else "declined" if command is None else "passed",
                                 "why": problems})
            if command is None and not problems:
                return {**out, "status": "model declined", "why": why or "The model gave no command."}
            if command:
                digest = hashlib.sha256(command.encode("utf-8")).hexdigest()[:8]
                try:
                    draft = self.librarian.new_draft(
                        draft_id=f"ai_{technique.lower().replace('.', '_')}_{digest}",
                        technique=technique, name=name, tactic=tactic, command=command,
                        executor="command_prompt", fidelity="partial", candidates=known["candidates"],
                        description=f"Read-only imitation of {technique}. {why}".strip(),
                        source={"library": "model draft", "model": self.model_name})
                except LibrarianError as e:
                    return {**out, "status": "refused by the rules", "why": str(e)}
                return {**out, "status": "draft", "draft_id": draft["id"],
                        "command": draft["action"]["command"],
                        "why": f"Drafted by the model on attempt {attempt} and passed the rules. "
                               f"Waiting for a sandbox trial and a person's approval."}
            text = RETRY.format(reasons="; ".join(problems))
        return {**out, "status": "refused by the rules",
                "why": f"{MAX_TRIES} answers, none of them harmless by the rules."}
