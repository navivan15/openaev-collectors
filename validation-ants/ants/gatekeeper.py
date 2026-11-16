"""Gatekeeper ant: nothing runs unless it is in scope, signed and inside the window.

Controls, each checked again at the moment a step is about to run:

1. **Kill switch.** While the kill-switch file exists, every step is refused.
2. **Scope list.** The host must be on the allowed-hosts list (full name,
   exact match) and the target address on the allowed-targets list. The step
   id must be a UUID and the addresses must be real IP addresses, so nothing
   else can be smuggled into a command. The action must be on the allowed
   list, and the command must be exactly what the catalogue's allow-listed
   action produces for that step: the gatekeeper derives it itself.
3. **Signed steps.** A step runs only with a valid signature (HMAC-SHA256 over
   its id, run, test, action, command, host and addresses, who approved it,
   and the approved time window). Changing any of those voids the signature,
   and a signature made for one window is void under another.
4. **Time window.** Now must be inside the approved run window.
5. **No replay, bounded runs.** A signed step is authorised once, and a run
   cannot exceed its step limit, also across restarts and across several
   gatekeeper processes sharing the same files.

Every decision is appended to an audit log. Each entry is sealed with a keyed
hash that covers the entry before it, and the log's head (last sequence
number and seal, the used step ids, the per-run counts) is kept in a sealed
state file. An edited, removed, re-sealed or cut-off entry is therefore
detected, and while the log does not verify, every step is refused.

Limit: the state file sits next to the log. Someone who can delete both files
resets the replay memory. In real use keep the state on storage the run
cannot rewrite.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from .models import Plan, Step

_MAILBOX_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,190}$")
_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9\-.]{0,251}[a-z0-9])?$")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def norm_host(host: str) -> str:
    """Full host name, lower case, no trailing dot. Never shortened."""
    return str(host).strip().lower().rstrip(".")


def _canonical(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode()


class Refused(Exception):
    """A step was refused. ``reason`` is a short machine-readable code."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


class Gatekeeper:
    def __init__(
        self,
        scope: dict[str, Any],
        actions: dict[str, dict[str, Any]],
        key: bytes,
        audit_path: Path | str,
        kill_switch_path: Path | str,
        now: Callable[[], datetime] = _now,
    ) -> None:
        if len(key) < 32:
            raise ValueError("The signing key must be at least 32 bytes")
        self.allowed_hosts = {norm_host(h) for h in scope.get("allowed_hosts", [])}
        self.allowed_targets = {str(ipaddress.ip_address(t))
                                for t in scope.get("allowed_targets", [])}
        self.allowed_actions = set(scope.get("allowed_actions", []))
        # Dedicated test machines: the only hosts where a change-and-undo step may run.
        self.reversible_hosts = {norm_host(h) for h in scope.get("reversible_hosts", [])}
        # Test mailboxes an email step may be sent to. Nothing else gets mail.
        self.allowed_mailboxes = [str(m) for m in scope.get("allowed_mailboxes", [])]
        for mailbox in self.allowed_mailboxes:
            if not _MAILBOX_RE.match(mailbox):
                raise ValueError(f"'{mailbox}' on the scope list is not a mailbox address")
        self.not_before = datetime.fromisoformat(scope["not_before"])
        self.not_after = datetime.fromisoformat(scope["not_after"])
        if self.not_before.tzinfo is None or self.not_after.tzinfo is None:
            raise ValueError("The scope's time window must carry a time zone")
        self.max_steps = int(scope.get("max_steps", 50))
        self.actions = actions
        self._key = key
        self.audit_path = Path(audit_path)
        self.state_path = self.audit_path.with_suffix(".state")
        self.lock_path = self.audit_path.with_suffix(".lock")
        self.kill_switch_path = Path(kill_switch_path)
        self._now = now

    # -- sealed state and audit log -----------------------------------------------

    def _seal(self, data: dict[str, Any]) -> str:
        return hmac.new(self._key, _canonical(data), hashlib.sha256).hexdigest()

    @contextmanager
    def _locked(self) -> Iterator[None]:
        """One gatekeeper at a time may read-check-append (also across processes)."""
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + 10
        while True:
            try:
                fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.close(fd)
                break
            except FileExistsError:
                try:
                    if time.time() - self.lock_path.stat().st_mtime > 30:
                        self.lock_path.unlink()      # left behind by a dead process
                        continue
                except OSError:
                    pass
                if time.monotonic() > deadline:
                    raise Refused("busy", "another gatekeeper holds the audit log")
                time.sleep(0.02)
        try:
            yield
        finally:
            try:
                self.lock_path.unlink()
            except OSError:
                pass

    def read_audit(self) -> list[dict[str, Any]]:
        if not self.audit_path.exists():
            return []
        lines = self.audit_path.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines if line.strip()]

    def _read_state(self) -> dict[str, Any]:
        """The sealed head of the log. Raises ValueError when it cannot be trusted."""
        if not self.state_path.exists():
            if self.audit_path.exists() and self.audit_path.stat().st_size:
                raise ValueError("the audit log exists but its state file is missing")
            return {"seq": 0, "head": "0" * 64, "used": [], "runs": {}}
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        seal = state.pop("seal", "")
        if not hmac.compare_digest(seal, self._seal(state)):
            raise ValueError("the audit state file was changed")
        return state

    def _write_state(self, state: dict[str, Any]) -> None:
        sealed = dict(state, seal=self._seal(state))
        tmp = self.state_path.with_suffix(".state.tmp")
        tmp.write_text(json.dumps(sealed), encoding="utf-8")
        os.replace(tmp, self.state_path)

    def _check_log(self, state: dict[str, Any]) -> tuple[bool, int | None]:
        prev, expected = "0" * 64, 0
        for entry in self.read_audit():
            expected += 1
            body = {k: v for k, v in entry.items() if k != "hash"}
            if (entry.get("prev") != prev or entry.get("seq") != expected
                    or not hmac.compare_digest(str(entry.get("hash")), self._seal(body))):
                return False, entry.get("seq", expected)
            prev = entry["hash"]
        if expected != state["seq"] or prev != state["head"]:
            return False, expected + 1          # entries were cut off the end (or added)
        return True, None

    def verify_audit(self) -> tuple[bool, int | None]:
        """(intact, first bad sequence number). Detects edits, removals and truncation."""
        try:
            return self._check_log(self._read_state())
        except (ValueError, OSError):
            return False, None

    def _append(self, state: dict[str, Any], event: str, step: Step | None,
                **extra: Any) -> dict[str, Any]:
        entry: dict[str, Any] = {"seq": state["seq"] + 1, "at": self._now().isoformat(),
                                 "event": event, "prev": state["head"]}
        if step is not None:
            entry.update(step_id=step.id, run_id=step.run_id, test_id=step.test_id,
                         host=step.host, target_ip=step.target_ip, action=step.action,
                         command=step.command)
        entry.update(extra)
        entry["hash"] = self._seal(entry)
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self.audit_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
        state["seq"], state["head"] = entry["seq"], entry["hash"]
        self._write_state(state)
        return entry

    def _audit(self, event: str, step: Step | None = None, **extra: Any) -> dict[str, Any]:
        """Append one entry outside of authorise (signing, kill switch)."""
        with self._locked():
            try:
                state = self._read_state()
                intact, _ = self._check_log(state)
            except (ValueError, OSError):
                intact = False
            if not intact:
                # Never write on top of a log that cannot be trusted.
                raise Refused("audit_broken", "the audit log does not verify")
            return self._append(state, event, step, **extra)

    # -- change-and-undo steps ----------------------------------------------------

    def record_cleanup(self, step: Step, confirmed: bool, detail: str = "") -> dict[str, Any]:
        """Record whether a change-and-undo step's undo was confirmed.

        An unconfirmed undo blocks the machine for further change-and-undo steps
        until a person clears it.
        """
        with self._locked():
            try:
                state = self._read_state()
                intact, _ = self._check_log(state)
            except (ValueError, OSError):
                intact = False
            if not intact:
                raise Refused("audit_broken", "the audit log does not verify")
            if not confirmed:
                state.setdefault("unclean", {})[norm_host(step.host)] = step.id
            return self._append(state, "cleanup_confirmed" if confirmed else "cleanup_failed", step,
                                detail=detail or (step.cleanup or ""))

    def unclean_hosts(self) -> dict[str, str]:
        """Machines with an undo that was not confirmed: host -> the step that left it."""
        try:
            return dict(self._read_state().get("unclean", {}))
        except (ValueError, OSError):
            return {}

    def clear_host(self, host: str, by: str) -> None:
        """A person has checked the machine by hand and says it is clean."""
        if not by or not by.strip():
            raise ValueError("Clearing a machine needs a person")
        with self._locked():
            state = self._read_state()
            intact, _ = self._check_log(state)
            if not intact:
                raise Refused("audit_broken", "the audit log does not verify")
            state.get("unclean", {}).pop(norm_host(host), None)
            self._append(state, "host_cleared", None, host=host, actor=by.strip())

    # -- kill switch -----------------------------------------------------------

    def kill_switch_engaged(self) -> bool:
        return self.kill_switch_path.exists()

    def engage_kill_switch(self, by: str, why: str) -> None:
        self.kill_switch_path.parent.mkdir(parents=True, exist_ok=True)
        self.kill_switch_path.write_text(f"{by}: {why}\n", encoding="utf-8")
        try:
            self._audit("kill_switch_engaged", actor=by, reason=why)
        except Refused:
            pass    # the switch is engaged either way; a broken log already blocks every step

    def release_kill_switch(self, by: str) -> None:
        if self.kill_switch_path.exists():
            self.kill_switch_path.unlink()
        self._audit("kill_switch_released", actor=by)

    # -- checks ----------------------------------------------------------------

    def _signature(self, step: Step, approver: str) -> str:
        return self._seal({**step.signed_fields(), "signed_by": approver,
                           "not_before": self.not_before.isoformat(),
                           "not_after": self.not_after.isoformat()})

    def _check_scope(self, step: Step) -> None:
        try:
            if str(uuid.UUID(str(step.id))) != str(step.id).lower():
                raise ValueError
        except (ValueError, AttributeError, TypeError):
            raise Refused("bad_step_id", "the step id is not a UUID")
        host = norm_host(step.host)
        if not _HOST_RE.match(host) or host not in self.allowed_hosts:
            raise Refused("out_of_scope", f"host '{step.host}' is not on the scope list")
        try:
            source = str(ipaddress.ip_address(str(step.source_ip)))
            target = str(ipaddress.ip_address(str(step.target_ip)))
        except ValueError:
            raise Refused("bad_address", "a step address is not an IP address")
        if source != step.source_ip or target != step.target_ip:
            raise Refused("bad_address", "a step address is not in plain IP form")
        if target not in self.allowed_targets:
            raise Refused("out_of_scope",
                          f"target address '{step.target_ip}' is not on the scope list")
        if step.action not in self.allowed_actions or step.action not in self.actions:
            raise Refused("action_not_allowed", f"action '{step.action}' is not allowed")
        action = self.actions[step.action]
        if action.get("reversible"):
            # A step that changes something: only on a dedicated test machine, and only
            # with exactly the allow-listed undo and check.
            if host not in self.reversible_hosts:
                raise Refused("reversible_not_allowed",
                              f"'{step.host}' is not listed as a dedicated test machine, and this "
                              f"step changes something before undoing it")
            if (not step.reversible or step.cleanup != action["cleanup"].format(marker=step.id)
                    or step.verify != action["verify"].format(marker=step.id)):
                raise Refused("command_not_allowed",
                              "the undo or its check is not what the allow-listed action produces")
        elif step.reversible or step.cleanup or step.verify:
            raise Refused("command_not_allowed", "a read-only action cannot carry an undo step")
        template = action["command"]
        if "{mailbox}" in template:
            # An email step: the command must be exactly the allow-listed test
            # email, addressed to a mailbox on the scope list.
            if step.command not in [
                    template.format(marker=step.id, target_ip=target, mailbox=m)
                    for m in self.allowed_mailboxes]:
                raise Refused("out_of_scope",
                              "the email is not the allow-listed test email to a test "
                              "mailbox on the scope list")
            return
        expected = template.format(marker=step.id, target_ip=target)
        if step.command != expected:
            raise Refused("command_not_allowed",
                          "the command is not what the allow-listed action produces")

    def _check_window(self) -> None:
        now = self._now()
        if now < self.not_before or now > self.not_after:
            raise Refused(
                "outside_window",
                f"now is outside the approved window "
                f"{self.not_before.isoformat()} .. {self.not_after.isoformat()}")

    # -- signing and authorising ---------------------------------------------

    def sign_plan(self, plan: Plan, approver: str) -> list[tuple[Step, Refused]]:
        """Sign every step that is in scope. Returns the steps left unsigned."""
        refused: list[tuple[Step, Refused]] = []
        signed = 0
        for step in plan.steps:
            try:
                if signed >= self.max_steps:
                    raise Refused("too_many_steps",
                                  f"the run is limited to {self.max_steps} steps")
                self._check_scope(step)
                self._audit("signed", step, actor=approver)   # no signature without a record
                step.signature = self._signature(step, approver)
                step.signed_by = approver
                signed += 1
            except Refused as e:
                refused.append((step, e))
                if e.reason != "audit_broken":
                    self._audit("sign_refused", step, actor=approver, reason=e.reason,
                                detail=e.detail)
        return refused

    def authorise(self, step: Step) -> dict[str, Any]:
        """Final check right before a step runs. Raises Refused, or returns the audit entry."""
        with self._locked():
            try:
                state = self._read_state()
                intact, _ = self._check_log(state)
            except (ValueError, OSError):
                raise Refused("audit_broken", "the audit log does not verify")
            if not intact:
                raise Refused("audit_broken", "the audit log does not verify")
            try:
                if self.kill_switch_engaged():
                    raise Refused("kill_switch", "the kill switch is engaged")
                self._check_scope(step)
                if not isinstance(step.signature, str) or not step.signed_by:
                    raise Refused("not_signed", "the step has no signature")
                expected = self._signature(step, str(step.signed_by))
                if not hmac.compare_digest(step.signature.encode("utf-8", "replace"),
                                           expected.encode()):
                    raise Refused("bad_signature",
                                  "the step, or its approved window, changed after signing")
                self._check_window()
                if step.reversible and norm_host(step.host) in state.get("unclean", {}):
                    raise Refused("host_not_clean",
                                  "an earlier change on this machine was not confirmed undone; "
                                  "a person has to check the machine and clear it")
                if step.id in state["used"]:
                    raise Refused("replay", "this step was already authorised once")
                if state["runs"].get(step.run_id, 0) >= self.max_steps:
                    raise Refused("too_many_steps",
                                  f"the run is limited to {self.max_steps} steps")
            except Refused as e:
                self._append(state, "refused", step, reason=e.reason, detail=e.detail)
                raise
            except Exception as e:  # anything unexpected is a logged refusal, never a run
                self._append(state, "refused", step, reason="internal_error", detail=str(e))
                raise Refused("internal_error", f"the check itself failed: {e}")
            state["used"].append(step.id)
            state["runs"][step.run_id] = state["runs"].get(step.run_id, 0) + 1
            return self._append(state, "authorised", step, actor=step.signed_by)
