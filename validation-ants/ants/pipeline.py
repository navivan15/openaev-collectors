"""One validation run, ant by ant: plan, gate, run, observe, analyse, match, report."""

from __future__ import annotations

from typing import Any, Callable

from .gatekeeper import Gatekeeper, Refused
from .matcher import Matcher
from .models import Observation, Step
from .planner import Planner
from .reporter import Reporter

Emit = Callable[..., None]


def run_validation(
    *,
    planner: Planner,
    gatekeeper: Gatekeeper,
    agent: Any,
    observers: list[Any],
    matcher: Matcher,
    reporter: Reporter,
    test_ids: list[str],
    hosts: list[dict[str, str]],
    approver: str,
    analyst: Any = None,
    engineer: Any = None,
    plan: Any = None,
    emit: Emit = lambda *a, **k: None,
    before_step: Callable[[int, Step], None] | None = None,
) -> dict[str, Any]:
    """Run the whole pipeline once and return the reporter's report."""
    # 1. Planner
    if plan is None:
        plan = planner.plan(test_ids, hosts)
    emit("Planner", f"Planned {len(plan.steps)} step(s) from "
                    f"{len({s.test_id for s in plan.steps})} test(s) "
                    f"on {len({s.host for s in plan.steps})} host(s)",
         data=[{"test": s.test_id, "title": s.title, "technique": s.technique, "host": s.host,
                "marker": s.id, "command": s.command} for s in plan.steps])

    # 2. Gatekeeper: sign what is in scope
    unsigned = gatekeeper.sign_plan(plan, approver)
    emit("Gatekeeper", f"Signed {len(plan.steps) - len(unsigned)} of {len(plan.steps)} "
                       f"step(s) for {approver}",
         status="ok" if not unsigned else "stop",
         data=[{"host": s.host, "test": s.test_id, "refused": e.reason, "why": e.detail}
               for s, e in unsigned])

    # 3. Agent: every step asks the gatekeeper again right before it runs
    ran: list[Step] = []
    not_run: list[tuple[Step, str, str]] = []
    cleanups: list[dict[str, Any]] = []
    for index, step in enumerate(plan.steps):
        if before_step:
            before_step(index, step)
        try:
            entry = agent.run(step)
            ran.append(step)
            emit("Agent", f"Ran '{step.title}' on {step.host}", detail=step.command)
            if step.reversible:
                confirmed = bool((entry or {}).get("cleanup_ok"))
                cleanups.append({"step_id": step.id, "test_id": step.test_id, "host": step.host,
                                 "technique": step.technique, "confirmed": confirmed,
                                 "cleanup": step.cleanup, "verify": step.verify})
                emit("Agent",
                     f"Undid the change on {step.host} and checked that nothing is left" if confirmed
                     else f"Could NOT confirm the undo on {step.host}: the machine is blocked for "
                          f"further change-and-undo steps until a person clears it",
                     detail=f"{step.cleanup}\n{step.verify}", status="ok" if confirmed else "none")
        except Refused as e:
            not_run.append((step, e.reason, e.detail))
            emit("Gatekeeper", f"Refused '{step.title}' on {step.host}: {e.detail}",
                 status="stop", data={"reason": e.reason})

    # 4. Observers
    agentless = {name for name, a in planner.actions.items() if a.get("agentless")}
    observations: list[Observation] = []
    with_memory = next((o for o in observers if hasattr(o, "memory_snapshot")), None)
    memory_before = with_memory.memory_snapshot() if with_memory else {}
    for observer in observers:
        seen = observer.observe(ran, agentless) if ran else []
        observations.extend(seen)
        counts: dict[str, int] = {}
        for o in seen:
            counts[o.outcome] = counts.get(o.outcome, 0) + 1
        emit(f"{observer.name.capitalize()} observer",
             ", ".join(f"{n} {k}" for k, n in counts.items()) or "nothing to look for",
             status="stop" if "Could not check" in counts else "ok",
             data=[o.to_dict() for o in seen])

    # 5. Analyst: what changed in how each test will be searched, and why
    changes: list[dict[str, Any]] = []
    if analyst is not None and with_memory is not None and ran:
        changes = analyst.record(plan.run_id, ran, observations, memory_before,
                                 with_memory.memory_snapshot())
        moved = [c for c in changes if c["change"] in ("learned", "added", "dropped")]
        emit("Analyst", f"{len(moved)} search change(s) written to the change log, "
                        f"{len(changes) - len(moved)} unchanged", data=changes)

    # 6. Matcher
    verdicts = matcher.fuse(ran, observations,
                            {o.name: o.candidates for o in observers})
    learned = sum(1 for v in verdicts for o in v.observations if o.method == "learned_rule")
    emit("Matcher", f"{len(verdicts)} verdict(s); {learned} from a learned rule; "
                    f"{sum(len(v.findings) for v in verdicts)} finding(s)",
         data=[v.to_dict() for v in verdicts])

    # 7. Detection engineer: a tested proposal for each missed step
    proposals: dict[str, Any] = {}
    if engineer is not None and verdicts:
        proposals = engineer.propose(verdicts)
        ready = [p for p in proposals["proposals"] if p["status"] == "ready for review"]
        if proposals["proposals"] or proposals["no_proposal"] or proposals["advice"] \
                or proposals["error"]:
            emit("Detection engineer",
                 proposals["error"] or (
                     f"{len(ready)} detection(s) ready for a person to review, "
                     f"{len(proposals['proposals']) - len(ready)} tested and set aside, "
                     f"{len(proposals['no_proposal'])} missed step(s) with nothing to propose, "
                     f"{len(proposals['advice'])} prevention note(s)"),
                 status="stop" if proposals["error"] else "ok", data=proposals)

    # 8. Reporter
    report = reporter.report(plan.run_id, verdicts, not_run)
    report["detection_proposals"] = proposals
    report["cleanups"] = cleanups
    left = {c["step_id"] for c in cleanups if not c["confirmed"]}
    for scored in report["steps"]:
        if scored["step_id"] in left:
            scored["findings"].append("undo not confirmed: the artifact may still be on the machine; "
                                      "a person has to check and clear it")
    report["search_changes"] = changes
    rate = report["detection_rate"]
    emit("Reporter", f"Detection rate {'n/a' if rate is None else format(rate, '.0%')} over "
                     f"{report['scored_steps']} scored step(s); "
                     f"{len(report['regressions'])} regression(s)",
         status="none" if report["regressions"] else "ok", data=report)
    report["audit_intact"] = gatekeeper.verify_audit()[0]
    return report
