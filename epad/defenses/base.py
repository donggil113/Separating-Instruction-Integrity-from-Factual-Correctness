"""Shared machinery for all defenses.

Fairness contract (enforced by construction, checked in tests):
  * every defense receives the same ``TaskSpec`` (the correct trusted planner's
    output for the user request) and the same ``Runtime`` (same read tools,
    trusted stores, references and verification budget ``k``);
  * no defense receives the case variant, ground truth, or world object;
  * every defense whose plan verifies claims uses the same resolver
    (``resolve``) under an explicit ``ResolvePolicy``, so that differences between
    designs are differences in *rules* (what may be bound), not in search skill.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional

from epad.plan import Resolved, TaskSpec, slot_for_fact
from epad.sandbox.runtime import BudgetExhausted, Runtime
from epad.sandbox.world import Document, values_equal
from epad.schema import Claim, Evidence, FactKey, SlotKind, SlotRole, Verdict, VerifyRule
from epad.sim import ReaderOutput, ScriptedReader, draw

PLANNER_SYSTEM_TOKENS = 900   # system prompt incl. tool signatures (same for all planners)
ACTOR_SYSTEM_TOKENS = 700


@dataclass(frozen=True)
class RunContext:
    pair_key: str               # "<base>-s<seed>": identical across the paired variants
    follow_prob: float = 1.0    # phi: actor compliance with instructions in untrusted content
    compromise_prob: float = 1.0  # rho: reader/purifier hijack when a reader payload is present
    omit_prob: float = 0.0      # omega: a fact is resolved WITHOUT the verification step (slip)
    keep_imperative_facts: float = 1.0   # prob. a reader/purifier keeps a fact phrased as a request
    directive_as_claim: float = 0.0      # prob. a reader/purifier turns a valued directive into a claim
    reader_factory: Optional[Callable[[], Any]] = None   # e.g. an LLM-backed reader (epad/llm_reader.py)

    def omits(self, key) -> bool:
        return self.omit_prob > 0 and draw(self.pair_key, str(key), "omit_verification") < self.omit_prob


class Defense:
    name = "abstract"
    family = ""
    description = ""

    def run(self, spec: TaskSpec, rt: Runtime, ctx: RunContext) -> None:
        raise NotImplementedError


# ------------------------------------------------------------------ retrieval / extraction
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


def make_reader(ctx: RunContext):
    if ctx.reader_factory is not None:
        return ctx.reader_factory()
    return ScriptedReader(ctx.pair_key, ctx.compromise_prob, ctx.keep_imperative_facts, ctx.directive_as_claim)


def read_all(rt: Runtime, docs: list[Document], keys: list[FactKey], ctx: RunContext
             ) -> tuple[list[Claim], list, bool]:
    reader = make_reader(ctx)
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


def contested(claims: list[Claim], key: FactKey, store_val: Any) -> bool:
    return any(not values_equal(c.value, store_val) for c in claims if c.key == key)


# ------------------------------------------------------------------ task metadata
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


# ------------------------------------------------------------------ the shared resolver
@dataclass(frozen=True)
class ResolvePolicy:
    """How a verifying design turns candidate values into a bound fact.

    endorse        -- may a document value be bound when the reference CONFIRMS it?
                      (False = provenance-only: only trusted-store values or lookups)
    verify_store   -- "always": a trusted-store value is bound only when the reference confirms it
                      (the store is the user's record: integrity trusted, freshness not);
                      "if_contested": an uncontested store value binds unverified (pre-audit EP).
    order          -- "store_first": verify the user's record first, then document challengers
                      (newest first); "challengers_first": the reverse.
    fallback_after_refute -- pre-audit bug kept for comparison: once every challenger is refuted,
                      bind the (contested!) store value without verifying it.
    lookup_first   -- use a lookup-capable reference before any shortcut.
    require_unique -- verify every candidate and bind only if exactly one is CONFIRMED (for
                      references whose CONFIRMED is not unique, e.g. name-match payee checks).
    """
    endorse: bool = True
    verify_store: str = "always"
    order: str = "store_first"
    fallback_after_refute: bool = False
    lookup_first: bool = True
    require_unique: bool = False


EP_POLICY = ResolvePolicy()
EP_PRE_AUDIT = ResolvePolicy(verify_store="if_contested", order="challengers_first", fallback_after_refute=True,
                             lookup_first=False)


def resolve(spec: TaskSpec, rt: Runtime, key: FactKey, claims: list[Claim], store_val: Any,
            pol: ResolvePolicy = EP_POLICY, omit: bool = False) -> Optional[Resolved]:
    if omit:   # the verification step is skipped: newest claimed value (or the store) is used as-is
        c = latest_claim(claims, key)
        if c is not None:
            return Resolved(c.value, "untrusted", claim_ids=(c.claim_id,))
        return Resolved(store_val, "trusted_store") if store_val is not None else None
    ref, lookup = ref_info(spec, rt, key)
    rule = slot_rule(spec, key)
    is_contested = store_val is not None and contested(claims, key, store_val)
    store_needs_evidence = (pol.verify_store == "always" or is_contested or rule == VerifyRule.ALWAYS)
    if store_val is not None and not store_needs_evidence and not (lookup and pol.lookup_first):
        return Resolved(store_val, "trusted_store")
    if ref is None:
        return None
    if lookup and (pol.lookup_first or store_val is None or store_needs_evidence):
        return try_lookup(rt, ref, key)
    challengers = [(v, cs) for v, cs in distinct_newest_first(claims, key)
                   if store_val is None or not values_equal(v, store_val)]
    if not pol.endorse:
        challengers = []                    # an unbindable candidate is never worth a verification
    store_cand = [(store_val, [])] if store_val is not None else []
    cands = store_cand + challengers if pol.order == "store_first" else challengers + store_cand
    confirmed: list[Resolved] = []
    complete = True
    for value, cs in cands:
        is_store = store_val is not None and not cs and values_equal(value, store_val)
        if is_store and pol.fallback_after_refute and pol.verify_store != "always" and rule != VerifyRule.ALWAYS:
            # pre-audit behaviour: reaching the store in challengers-first order means every challenger was
            # refuted; the contested store value was then bound WITHOUT evidence (RT-EP-1)
            return Resolved(store_val, "trusted_store")
        ev = try_verify(rt, ref, key, value, tuple(c.claim_id for c in cs))
        if ev is None:                       # budget exhausted
            complete = False
            break
        if ev.verdict == Verdict.UNKNOWN:
            return None
        if ev.verdict == Verdict.CONFIRMED:
            r = Resolved(value, "trusted_store" if is_store else "evidence", (ev.evidence_id,),
                         tuple(c.claim_id for c in cs))
            if not pol.require_unique:
                return r
            confirmed.append(r)
    if pol.require_unique and complete and len(confirmed) == 1:
        return confirmed[0]
    return None


# ------------------------------------------------------------------ misc
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
