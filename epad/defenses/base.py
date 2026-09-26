"""Shared machinery for all defenses.

Fairness contract (enforced by construction, checked in tests):
  * every defense receives the same ``TaskSpec`` (the correct trusted planner's
    output for the user request) and the same ``Runtime`` (same read tools,
    trusted stores, references and verification budget ``k``);
  * no defense receives the case variant, ground truth, or world object;
  * defenses that verify use the same candidate ordering helper
    (``verification_order``) so that no defense wins by a cleverer search.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from epad.plan import Resolved, TaskSpec, slot_for_fact
from epad.sandbox.runtime import BudgetExhausted, Runtime
from epad.sandbox.world import Document, values_equal
from epad.schema import Claim, Evidence, FactKey, SlotKind, SlotRole, Verdict, VerifyRule
from epad.sim import ReaderOutput, ScriptedReader

PLANNER_SYSTEM_TOKENS = 900   # system prompt incl. tool signatures (same for all planners)
ACTOR_SYSTEM_TOKENS = 700


@dataclass(frozen=True)
class RunContext:
    pair_key: str               # "<base>-s<seed>": identical across the paired variants
    follow_prob: float = 1.0    # phi: actor compliance with instructions in untrusted content
    compromise_prob: float = 1.0  # rho: reader hijack when a reader payload is present
    omit_prob: float = 0.0      # omega: a fact is resolved WITHOUT the verification step (planner/resolver slip)
    reader_factory: Optional[Callable[[], Any]] = None   # e.g. an LLM-backed reader (epad/llm_reader.py)

    def omits(self, key) -> bool:
        from epad.sim import draw
        return self.omit_prob > 0 and draw(self.pair_key, str(key), "omit_verification") < self.omit_prob


class Defense:
    name = "abstract"
    family = ""
    description = ""

    def run(self, spec: TaskSpec, rt: Runtime, ctx: RunContext) -> None:
        raise NotImplementedError


# ------------------------------------------------------------------ helpers
def retrieve(spec: TaskSpec, rt: Runtime) -> list[Document]:
    seen: dict[str, Document] = {}
    for step in spec.reads:
        for d in rt.search_documents(step.keyword):
            seen[d.doc_id] = d
    return sorted(seen.values(), key=lambda d: d.timestamp)


def store_values(spec: TaskSpec, rt: Runtime) -> dict[FactKey, Any]:
    out: dict[FactKey, Any] = {}
    for store, key in spec.store_keys:
        v = rt.read_store(store, key)
        if v is not None:
            out[key] = v
    return out


def read_all(rt: Runtime, docs: list[Document], keys: list[FactKey], ctx: RunContext,
             imperative_as_fact: bool = True) -> tuple[list[Claim], list, bool]:
    reader = (ctx.reader_factory() if ctx.reader_factory is not None
              else ScriptedReader(ctx.pair_key, ctx.compromise_prob, imperative_as_fact))
    claims, directives, compromised = [], [], False
    for d in docs:
        out: ReaderOutput = reader.read(rt, d, keys)
        claims += out.claims
        directives += out.directives
        compromised |= out.compromised
    return claims, directives, compromised


def distinct_newest_first(claims: list[Claim], key: FactKey) -> list[tuple[Any, list[Claim]]]:
    groups: list[tuple[Any, list[Claim]]] = []
    for c in sorted([c for c in claims if c.key == key], key=lambda c: -c.timestamp):
        for v, cs in groups:
            if values_equal(v, c.value):
                cs.append(c)
                break
        else:
            groups.append((c.value, [c]))
    return groups


def latest_claim(claims: list[Claim], key: FactKey) -> Optional[Claim]:
    cs = sorted([c for c in claims if c.key == key], key=lambda c: c.timestamp)
    return cs[-1] if cs else None


def verification_order(claims: list[Claim], key: FactKey, store_val: Any) -> list[tuple[Any, list[Claim]]]:
    """Common candidate order for every verifying defense: document values that
    challenge the trusted store (newest first), then the trusted-store value."""
    groups = [(v, cs) for v, cs in distinct_newest_first(claims, key)
              if store_val is None or not values_equal(v, store_val)]
    if store_val is not None:
        groups.append((store_val, []))
    return groups


def slot_rule(spec: TaskSpec, key: FactKey) -> VerifyRule:
    rules = [s.verify for s in slot_for_fact(spec, key)]
    return VerifyRule.ALWAYS if (not rules or VerifyRule.ALWAYS in rules) else VerifyRule.IF_UNTRUSTED_OR_CONFLICT


def slot_roles(spec: TaskSpec, key: FactKey) -> set[SlotRole]:
    roles = {s.role for s in slot_for_fact(spec, key)}
    for t in spec.grant.templates:
        if t.condition and t.condition.fact == key:
            roles.add(SlotRole.QUANTITY)   # a condition fact decides whether a consequential call happens
    return roles


def ref_info(spec: TaskSpec, rt: Runtime, key: FactKey) -> tuple[Optional[str], bool]:
    name = spec.reference_for(key)
    if name is None:
        return None, False
    info = next(r for r in rt.references() if r["name"] == name)
    return name, info["supports_lookup"]


def try_lookup(rt: Runtime, ref: str, key: FactKey) -> Optional[Resolved]:
    try:
        ev = rt.lookup(ref, key)
    except BudgetExhausted:
        return None
    if ev.verdict == Verdict.CONFIRMED:
        return Resolved(ev.value, "reference_lookup", (ev.evidence_id,))
    return None


def try_verify(rt: Runtime, ref: str, key: FactKey, value: Any, claim_ids=()) -> Optional[Evidence]:
    try:
        return rt.verify(ref, key, value, claim_ids[0] if claim_ids else None)
    except BudgetExhausted:
        return None


def contested(claims: list[Claim], key: FactKey, store_val: Any) -> bool:
    return any(not values_equal(c.value, store_val) for c in claims if c.key == key)


def planner_call(rt: Runtime, spec: TaskSpec, out_tokens: int = 250) -> None:
    rt.llm("planner", PLANNER_SYSTEM_TOKENS + len(spec.user_prompt) // 4, out_tokens)


def commit_all(rt: Runtime, actions, check=None, by: str = "") -> None:
    """Propose each action; commit unless ``check`` returns a denial reason."""
    for act in actions:
        att = rt.propose(act)
        reason = check(act) if check else None
        if reason:
            rt.block(att, by, reason)
        else:
            rt.commit(att)
