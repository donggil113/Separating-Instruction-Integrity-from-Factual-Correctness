"""Task specification (trusted planner output) and grant instantiation.

Every defense receives the same ``TaskSpec``. It stands for the output of a
*correct* trusted planner that saw only the user's request and the deployment
configuration (assumption P1 in docs/02_threat_model.md). Defenses differ only
in how they (i) let untrusted content influence actions, (ii) resolve fact
values, and (iii) enforce checks before committing.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from epad.schema import (ActionRequest, ArgSlot, AuthorityGrant, BoundArg, Condition, FactKey,
                         SlotKind)


# ------------------------------------------------------------------ transforms
def _hhmm_minus(t: str, minutes: int) -> str:
    h, m = map(int, t.split(":"))
    tot = (h * 60 + m - minutes) % (24 * 60)
    return f"{tot // 60:02d}:{tot % 60:02d}"


TRANSFORMS: dict[str, Callable[[Any], Any]] = {
    "pickup_150_before": lambda t: _hhmm_minus(t, 150),
    "arrival_message": lambda t: f"My flight lands at {t}.",
    "meeting_title": lambda t: t,
}


INVERSE_TRANSFORMS: dict[str, Callable[[Any], Any]] = {
    "pickup_150_before": lambda t: _hhmm_minus(t, -150),
    "arrival_message": lambda s: s.rsplit(" ", 1)[-1].rstrip("."),
    "meeting_title": lambda t: t,
}


def invert_transform(name: Optional[str], value: Any) -> Any:
    if name is None:
        return value
    return INVERSE_TRANSFORMS[name](value)


def apply_transform(name: Optional[str], value: Any) -> Any:
    if name is None:
        return value
    return TRANSFORMS[name](value)


# ------------------------------------------------------------------ task spec
@dataclass(frozen=True)
class ReadStep:
    keyword: str   # search_documents(keyword)


@dataclass(frozen=True)
class TaskSpec:
    task_id: str
    domain: str
    user_prompt: str
    grant: AuthorityGrant
    reads: tuple[ReadStep, ...]
    store_keys: tuple[tuple[str, FactKey], ...]   # trusted stores the planner consults: (store, key)
    fact_refs: tuple[tuple[FactKey, str], ...]    # deployment config: which reference covers which fact
    free_values: tuple[tuple[str, str], ...] = ()  # (slot name, value) for FREE slots decided by the planner

    def reference_for(self, key: FactKey) -> Optional[str]:
        for k, r in self.fact_refs:
            if k == key:
                return r
        return None

    def store_for(self, key: FactKey) -> Optional[str]:
        for s, k in self.store_keys:
            if k == key:
                return s
        return None

    def free_value(self, slot: str) -> Optional[str]:
        for s, v in self.free_values:
            if s == slot:
                return v
        return None


@dataclass(frozen=True)
class Resolved:
    """A fact value chosen by some defense, with the basis for choosing it."""
    value: Any
    basis: str                               # "evidence" | "trusted_store" | "untrusted" | "reference_lookup"
    evidence_ids: tuple[str, ...] = ()
    claim_ids: tuple[str, ...] = ()


def _cmp(op: str, a: Any, b: Any) -> bool:
    return {"<=": a <= b, ">=": a >= b, "==": a == b, "!=": a != b}[op]


def eval_condition(cond: Optional[Condition], facts: dict[FactKey, Resolved]) -> Optional[bool]:
    if cond is None:
        return True
    r = facts.get(cond.fact)
    if r is None:
        return None
    return _cmp(cond.op, r.value, cond.operand)


def instantiate(spec: TaskSpec, facts: dict[FactKey, Resolved], origin: str = "plan"
                ) -> tuple[list[ActionRequest], list[tuple[str, str]]]:
    """Instantiate every template of the grant with the given fact resolutions.

    Returns (actions, abstentions). A template whose condition evaluates to
    False yields no action and no abstention (a legitimate decision not to act).
    A template with an unresolved fact yields an abstention.
    """
    actions: list[ActionRequest] = []
    abstain: list[tuple[str, str]] = []
    for tpl in spec.grant.templates:
        c = eval_condition(tpl.condition, facts)
        if c is None:
            abstain.append((tpl.tool, f"condition fact {tpl.condition.fact} unresolved"))
            continue
        if c is False:
            continue
        args: dict[str, Any] = {}
        just: list[BoundArg] = []
        missing = None
        for s in tpl.slots:
            if s.kind == SlotKind.USER_FIXED:
                args[s.name] = s.value
                just.append(BoundArg(s.name, s.value, "user"))
            elif s.kind == SlotKind.FREE:
                v = spec.free_value(s.name) or ""
                args[s.name] = v
                just.append(BoundArg(s.name, v, "free"))
            else:
                r = facts.get(s.fact)
                if r is None:
                    missing = s.fact
                    break
                v = apply_transform(s.transform, r.value)
                args[s.name] = v
                just.append(BoundArg(s.name, v, r.basis, r.evidence_ids, r.claim_ids))
        if missing is not None:
            abstain.append((tpl.tool, f"fact {missing} unresolved"))
            continue
        actions.append(ActionRequest(tpl.tool, args, origin, tuple(just)))
    return actions, abstain


def slot_for_fact(spec: TaskSpec, key: FactKey) -> list[ArgSlot]:
    return [s for t in spec.grant.templates for s in t.slots if s.kind == SlotKind.FACT and s.fact == key]
