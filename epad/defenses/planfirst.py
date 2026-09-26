"""Plan-first baselines: CaMeL-style and Fides-style emulations, plus controls.

Emulation notes (details and sources: docs/05_baselines.md):

CaMeL (Debenedetti et al., arXiv 2503.18813v2; code google-research/camel-prompt-injection)
  * P-LLM writes the program from the user query only; Q-LLM extracts typed values
    from untrusted text; the interpreter tracks provenance (capabilities).
  * Policy (banking.py analogue): an *authority* argument (recipient / target
    account / item acted upon) must be trusted, i.e. have only User /
    TrustedToolSource provenance. Data arguments may carry untrusted values
    subject to readers checks. We run readers checks CHARITABLY (non-sensitive
    data treated as public), which only ever raises CaMeL's utility.
  * No endorsement: a verifier/lookup output depends on its arguments, so a
    confirmation keyed by an extracted value stays untrusted.
  * Denied call -> halt + escalate to the user (we count a blocked attempt and do
    not model the user's approval, which would be an extra oracle).

Fides (Costa et al., arXiv 2505.23643v2)
  * Planner sees only trusted data; untrusted tool results are hidden in
    variables; query_llm writes a U-labelled variable; P-T requires a trusted
    context label for consequential calls.
  * "as evaluated": P-T checks only the context label, not argument labels.
  * "arg": argument-level P-T on security-critical arguments (target, item,
    quantity), which the paper describes as the stricter variant (§4.3, §6.1).
  * "typed": the capacity-based endorsement escape hatch (§5.2; not used in the
    paper's evaluation): a U-labelled *bool* may enter the context without
    tainting it; here the bool is the shared verifier's verdict.
  * A verifier result keyed by a U value is U (Alg. 5 l.9); a lookup keyed by a
    trusted entity id is T.
"""
from __future__ import annotations

from typing import Any, Optional

from epad.defenses.base import (Defense, RunContext, commit_all, contested, latest_claim, planner_call,
                                read_all, ref_info, retrieve, slot_roles, store_values, try_lookup,
                                try_verify)
from epad.defenses.ep import EvidencePreserving, resolve_with_evidence
from epad.plan import Resolved, TaskSpec, instantiate
from epad.sandbox.runtime import Runtime
from epad.sandbox.world import values_equal
from epad.schema import ActionRequest, FactKey, SlotKind, SlotRole, Verdict

AUTHORITY_ROLES = {SlotRole.TARGET, SlotRole.ITEM}
FIDES_CRITICAL = {SlotRole.TARGET, SlotRole.ITEM, SlotRole.QUANTITY}
TRUSTED_BASES = {"user", "trusted_store", "reference_lookup", "free"}


def _template(spec: TaskSpec, act: ActionRequest):
    return next(t for t in spec.grant.templates if t.tool == act.tool)


def _condition_bases(spec: TaskSpec, facts: dict[FactKey, Resolved]) -> list[str]:
    return [facts[t.condition.fact].basis for t in spec.grant.templates
            if t.condition and t.condition.fact in facts]


# ================================================================== CaMeL
class CaMeL(Defense):
    """``planner="as_evaluated"``: Q-LLM extracts each fact from the documents the
    request points to (latest value), falling back to the trusted store; no
    verification. ``planner="strong"``: lookups when the reference supports them,
    and the same claim-verification plan as EP for everything else.
    ``endorse=True`` adds our rule R2 to the policy (ablation: EP inside CaMeL)."""

    family = "existing (emulated)"

    def __init__(self, planner: str = "strong", endorse: bool = False, name: Optional[str] = None):
        self.planner = planner
        self.endorse = endorse
        self.name = name or {("as_evaluated", False): "CaMeL (as evaluated)", ("strong", False): "CaMeL (strong plan)",
                             ("strong", True): "CaMeL + endorsement"}[(planner, endorse)]
        self.description = f"plan-first + provenance policy; planner={planner}; endorse={endorse}"

    def run(self, spec: TaskSpec, rt: Runtime, ctx: RunContext) -> None:
        planner_call(rt, spec)                       # P-LLM writes the program from the query only
        keys = spec.grant.fact_keys()
        docs = retrieve(spec, rt)
        claims, _, _ = read_all(rt, docs, keys, ctx)  # Q-LLM (directives have no channel to the P-LLM)
        stores = store_values(spec, rt)
        facts: dict[FactKey, Resolved] = {}
        for key in keys:
            if self.planner == "as_evaluated":
                c = latest_claim(claims, key)
                if c is not None:
                    facts[key] = Resolved(c.value, "untrusted", claim_ids=(c.claim_id,))
                elif key in stores:
                    facts[key] = Resolved(stores[key], "trusted_store")
            else:
                r = resolve_with_evidence(spec, rt, key, claims, stores.get(key), endorse=True,
                                          omit=ctx.omits(key))
                if r is not None:
                    facts[key] = r
        actions, abst = instantiate(spec, facts, origin="p-llm")
        for tool, why in abst:
            rt.abstain(tool, why)
        halted = False
        for act in actions:
            att = rt.propose(act)
            if halted:
                rt.block(att, "camel_policy", "execution halted after an earlier denial")
                continue
            reason = self.policy(spec, rt, act)
            if reason:
                rt.block(att, "camel_policy", reason)
                halted = True                        # SecurityPolicyDeniedError halts the program
            else:
                rt.commit(att)

    def policy(self, spec: TaskSpec, rt: Runtime, act: ActionRequest) -> Optional[str]:
        tpl = _template(spec, act)
        evid = {e.evidence_id: e for e in rt.log.verifications}
        for b in act.justification:
            s = tpl.slot(b.slot)
            if s.role not in AUTHORITY_ROLES or b.basis in TRUSTED_BASES:
                continue
            if self.endorse and b.basis == "evidence" and any(
                    evid.get(i) and evid[i].verdict == Verdict.CONFIRMED and evid[i].key == s.fact
                    and evid[i].reference == spec.reference_for(s.fact) for i in b.evidence_ids):
                continue
            return f"authority argument '{b.slot}' does not come from a trusted source"
        return None


# ================================================================== Fides
class Fides(Defense):
    family = "existing (emulated)"

    def __init__(self, mode: str = "as_evaluated", planner: str = "strong", name: Optional[str] = None):
        assert mode in ("as_evaluated", "arg", "typed") and planner in ("as_evaluated", "strong")
        self.mode = mode
        self.planner = planner
        self.name = name or {("as_evaluated", "as_evaluated"): "Fides (as evaluated)",
                             ("as_evaluated", "strong"): "Fides (strong plan)",
                             ("arg", "strong"): "Fides (arg-level P-T)",
                             ("typed", "strong"): "Fides (typed endorsement)"}[(mode, planner)]
        self.description = f"IFC planner with hiding + query_llm; policy mode={mode}; planner={planner}"

    def run(self, spec: TaskSpec, rt: Runtime, ctx: RunContext) -> None:
        keys = spec.grant.fact_keys()
        planner_call(rt, spec, 120)                      # choose retrieval (context stays T: results hidden)
        docs = retrieve(spec, rt)
        stores = store_values(spec, rt)
        claims, _, _ = read_all(rt, docs, keys, ctx)     # query_llm, one query per fact argument
        context_tainted = False
        facts: dict[FactKey, Resolved] = {}
        for key in keys:
            planner_call(rt, spec, 80)                   # one planner turn per argument decision
            ref, lookup = ref_info(spec, rt, key)
            critical = bool(slot_roles(spec, key) & FIDES_CRITICAL)
            if ref and lookup and self.planner == "strong":   # lookup keyed by the trusted entity id -> T
                r = try_lookup(rt, ref, key)
                if r is not None:
                    facts[key] = r
                    continue
            if self.mode == "typed":
                # verifier verdicts are bools: admitted to the context by the capacity escape hatch
                r = resolve_with_evidence(spec, rt, key, claims, stores.get(key), endorse=True,
                                          omit=ctx.omits(key))
                if r is not None:
                    facts[key] = r
                continue
            if self.mode == "arg" and critical:
                sv = stores.get(key)
                if sv is not None and ref:
                    ev = try_verify(rt, ref, key, sv)    # T args -> T verdict: no taint
                    if ev is not None and ev.verdict == Verdict.CONFIRMED:
                        facts[key] = Resolved(sv, "trusted_store", (ev.evidence_id,))
                        continue
                    if ev is None:                       # budget exhausted: T value, unverified
                        facts[key] = Resolved(sv, "trusted_store")
                        continue
                c = latest_claim(claims, key)            # only a U value remains -> policy will block it
                if c is not None and (sv is None or not values_equal(c.value, sv)):
                    facts[key] = Resolved(c.value, "untrusted", claim_ids=(c.claim_id,))
                continue
            # as evaluated (and non-critical args under "arg"): pass the query_llm variable by reference
            c = latest_claim(claims, key)
            if c is not None:
                facts[key] = Resolved(c.value, "untrusted", claim_ids=(c.claim_id,))
            elif key in stores:
                facts[key] = Resolved(stores[key], "trusted_store")
        # a condition on a U value is data-dependent control flow: the planner must expand it -> context U
        for t in spec.grant.templates:
            if t.condition and t.condition.fact in facts and facts[t.condition.fact].basis == "untrusted":
                context_tainted = True
        actions, abst = instantiate(spec, facts, origin="fides-planner")
        for tool, why in abst:
            rt.abstain(tool, why)
        for act in actions:
            planner_call(rt, spec, 60)
            att = rt.propose(act)
            reason = self.policy(spec, act, context_tainted)
            if reason:
                rt.block(att, "fides_policy", reason)
            else:
                rt.commit(att)

    def policy(self, spec: TaskSpec, act: ActionRequest, context_tainted: bool) -> Optional[str]:
        if context_tainted:
            return "P-T: consequential call made in a U-labelled context"
        if self.mode == "arg":
            tpl = _template(spec, act)
            for b in act.justification:
                if tpl.slot(b.slot).role in FIDES_CRITICAL and b.basis not in TRUSTED_BASES:
                    return f"P-T(arg): argument '{b.slot}' is U-labelled"
        return None


# ================================================================== controls
class ProvenanceTrust(EvidencePreserving):
    """EP's authority rule R1, but truth taken from provenance: a claim from an
    authenticated sender is accepted (newest wins); unauthenticated claims are
    ignored; no verification. Tests 'hash/provenance is not truth'."""
    name = "Provenance-as-truth"
    family = "ablation"
    description = "grant-only actions; authenticated-sender claims accepted as true"

    def run(self, spec, rt, ctx):
        planner_call(rt, spec)
        keys = spec.grant.fact_keys()
        docs = retrieve(spec, rt)
        claims, _, _ = read_all(rt, docs, keys, ctx)
        stores = store_values(spec, rt)
        facts = {}
        for key in keys:
            auth = [c for c in claims if c.key == key and c.authenticated]
            if auth:
                c = max(auth, key=lambda c: c.timestamp)
                facts[key] = Resolved(c.value, "provenance", claim_ids=(c.claim_id,))
            elif key in stores:
                facts[key] = Resolved(stores[key], "trusted_store")
        actions, abst = instantiate(spec, facts, origin="grant")
        for tool, why in abst:
            rt.abstain(tool, why)
        commit_all(rt, actions)


class ReferenceOnly(Defense):
    """Grant-only actions; facts only from references (lookup) or verified trusted
    stores; documents are never read. Tests whether reading documents is needed."""
    name = "Reference-only"
    family = "ablation"
    description = "ignores documents; lookup or verified trusted-store values only"

    def run(self, spec, rt, ctx):
        planner_call(rt, spec)
        stores = store_values(spec, rt)
        facts = {}
        for key in spec.grant.fact_keys():
            ref, lookup = ref_info(spec, rt, key)
            if ref and lookup:
                r = try_lookup(rt, ref, key)
                if r is not None:
                    facts[key] = r
                continue
            sv = stores.get(key)
            if sv is not None and ref:
                ev = try_verify(rt, ref, key, sv)
                if ev is not None and ev.verdict == Verdict.CONFIRMED:
                    facts[key] = Resolved(sv, "trusted_store", (ev.evidence_id,))
        actions, abst = instantiate(spec, facts, origin="grant")
        for tool, why in abst:
            rt.abstain(tool, why)
        commit_all(rt, actions)
