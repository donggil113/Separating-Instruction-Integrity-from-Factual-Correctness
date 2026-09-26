"""Plan-first baselines: CaMeL-style and Fides-style emulations, plus controls.

Emulation notes (details and sources: docs/05_baselines.md):

CaMeL (Debenedetti et al., arXiv 2503.18813v2; code google-research/camel-prompt-injection)
  * P-LLM writes the program from the user query only; Q-LLM extracts typed values from untrusted
    text; the interpreter tracks provenance (capabilities). NORMAL interpreter mode (code default).
  * Policy (banking.py analogue): an *authority* argument (recipient / target account; by default
    also the item acted upon -- see ``authority_roles``) must be trusted: User / TrustedToolSource
    provenance, a trusted-store value, or a lookup keyed by the trusted id. Data arguments may carry
    untrusted values subject to readers checks.
  * ``readers="charitable"``: readers checks off (non-sensitive data public). This raises CaMeL's
    utility AND its false-fact commits (both directions, audit CAMEL-2). ``readers="faithful"``:
    a branch on document-derived data is a non-public control context (engine rule, denies), and
    data derived from private web/file content cannot flow to a recipient.
  * No endorsement: a verifier output depends on its arguments, so a confirmation keyed by an
    extracted value stays untrusted. The strong plan is *policy-aware*: for authority facts it only
    verifies candidates the policy could ever accept (the trusted store, or a lookup).
  * Denial -> halt; later calls are not reached (recorded as escalations, not as attempts). The
    user-approval oracle is not modelled.

Fides (Costa et al., arXiv 2505.23643v2)
  * Untrusted tool results are hidden in variables; query_llm writes U-labelled variables (one call
    per retrieved document in this emulation); P-T requires a T context for consequential calls.
  * A verify call whose arguments are all T (grant entity + trusted-store value) returns T; a lookup
    keyed by a trusted id is T; a verify call on a U value returns U (Alg. 5 l.9).
  * "as evaluated" policy: P-T on the context label only. Strong plan (audit FID-1): lookup; else
    verify the T store value; CONFIRMED -> store; REFUTED -> pass the newest query_llm variable by
    reference (unverified); budget exhausted/UNKNOWN -> store.
  * "arg": argument-level P-T on critical arguments (target, item, quantity) (§4.3, §6.1).
  * "typed": capacity-based endorsement escape hatch (§5.2; unused in the paper's evaluation) with
    the bool taken from the shared verifier -- i.e. EP's resolver in a Fides shell (a transplant).
"""
from __future__ import annotations

from typing import Optional

from epad.defenses.base import (EP_POLICY, Defense, ResolvePolicy, RunContext, commit_all, latest_claim,
                                planner_call, read_all, ref_info, resolve, retrieve, slot_roles, store_values,
                                try_lookup, try_verify)
from epad.defenses.ep import EvidencePreserving
from epad.plan import Resolved, TaskSpec, apply_transform, instantiate
from epad.sandbox.runtime import Runtime
from epad.sandbox.world import values_equal
from epad.schema import ActionRequest, FactKey, SlotKind, SlotRole, Verdict

AUTHORITY_ROLES = frozenset({SlotRole.TARGET, SlotRole.ITEM})
FIDES_CRITICAL = {SlotRole.TARGET, SlotRole.ITEM, SlotRole.QUANTITY}
TRUSTED_BASES = {"user", "trusted_store", "reference_lookup", "free"}


def _evidence_binds(spec: TaskSpec, rt: Runtime, key: FactKey, b, transform) -> bool:
    evid = {e.evidence_id: e for e in rt.log.verifications}
    return any(evid.get(i) and evid[i].verdict == Verdict.CONFIRMED and evid[i].key == key
               and evid[i].reference == spec.reference_for(key)
               and values_equal(apply_transform(transform, evid[i].value), b.value) for i in b.evidence_ids)


# ================================================================== CaMeL
class CaMeL(Defense):
    """``planner="as_evaluated"``: the Q-LLM extracts each fact from the documents the request
    points to (newest value), falling back to the trusted store; no verification.
    ``planner="strong"``: the policy-aware plan described in the module docstring.
    ``endorse`` (transplant): "authority" adds EP's rule R2 for authority arguments only;
    "all" makes every FACT argument trusted-or-endorsed (full-scope transplant)."""

    family = "existing (emulated)"

    def __init__(self, planner: str = "strong", endorse: Optional[str] = None, readers: str = "charitable",
                 authority_roles: frozenset = AUTHORITY_ROLES, name: Optional[str] = None):
        self.planner = planner
        self.endorse = endorse
        self.readers = readers
        self.authority_roles = authority_roles
        base = {("as_evaluated", None): "CaMeL (as evaluated)", ("strong", None): "CaMeL (strong plan)",
                ("strong", "authority"): "CaMeL + endorsement (authority args)",
                ("strong", "all"): "CaMeL + endorsement (all fact args)"}[(planner, endorse)]
        suffix = [] if readers == "charitable" else ["faithful readers"]
        if authority_roles != AUTHORITY_ROLES:
            suffix.append("TARGET-only authority")
        self.name = name or (base + (", " + ", ".join(suffix) if suffix else ""))
        self.description = f"plan-first + provenance policy; planner={planner}; endorse={endorse}; readers={readers}"

    def _is_authority_fact(self, spec: TaskSpec, key: FactKey) -> bool:
        return bool(slot_roles(spec, key) & self.authority_roles) and not any(
            t.condition and t.condition.fact == key for t in spec.grant.templates)

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
                continue
            # strong plan: never spend budget on a candidate the policy can never accept
            bindable = self.endorse is not None or not self._is_authority_fact(spec, key)
            pol = EP_POLICY if bindable else ResolvePolicy(endorse=False)
            r = resolve(spec, rt, key, claims, stores.get(key), pol, omit=ctx.omits(key))
            if r is not None:
                facts[key] = r
        actions, abst = instantiate(spec, facts, origin="p-llm")
        for tool, why in abst:
            rt.abstain(tool, why)
        channel = {d.doc_id: d.channel for d in docs}
        doc_channels = lambda r: [channel.get(c.split(":")[0]) for c in r.claim_ids if c.split(":")[0] in channel]
        cond_private = self.readers == "faithful" and any(
            t.condition and t.condition.fact in facts and doc_channels(facts[t.condition.fact])
            for t in spec.grant.templates)
        for i, act in enumerate(actions):
            reason = self.policy(spec, rt, act)
            if not reason and self.readers == "faithful":
                if cond_private:
                    reason = "engine: consequential call under a non-public control context"
                elif any("web" in doc_channels(facts.get(tpl_s.fact)) for tpl_s in
                         spec.grant.templates[act.template].slots if tpl_s.kind == SlotKind.FACT and facts.get(tpl_s.fact)):
                    reason = "readers: argument derived from private (web/file) data the recipient cannot read"
            att = rt.propose(act)
            if reason:
                rt.block(att, "camel_policy", reason)
                for later in actions[i + 1:]:      # SecurityPolicyDeniedError halts the program
                    rt.abstain(later.tool, "not executed: program halted after a policy denial")
                return
            rt.commit(att)

    def policy(self, spec: TaskSpec, rt: Runtime, act: ActionRequest) -> Optional[str]:
        tpl = spec.grant.templates[act.template]
        for b in act.justification:
            s = tpl.slot(b.slot)
            if s.kind != SlotKind.FACT:
                continue
            needs_trust = s.role in self.authority_roles or self.endorse == "all"
            if not needs_trust or b.basis in TRUSTED_BASES:
                continue
            if self.endorse and b.basis == "evidence" and _evidence_binds(spec, rt, s.fact, b, s.transform):
                continue
            return f"argument '{b.slot}' does not come from a trusted source"
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
                             ("typed", "strong"): "Fides shell + EP resolver (typed hatch)"}[(mode, planner)]
        self.description = f"IFC planner with hiding + query_llm; policy mode={mode}; planner={planner}"

    def _store_first(self, spec, rt, key, claims, sv, ref, critical_T: bool) -> Optional[Resolved]:
        """Verify the T store value (T args -> T verdict). REFUTED -> the U claim (as_evaluated) or
        nothing that a T-requiring argument could take (arg mode). Budget/UNKNOWN -> T store value."""
        ev = try_verify(rt, ref, key, sv)
        if ev is None or ev.verdict == Verdict.UNKNOWN:
            return Resolved(sv, "trusted_store")
        if ev.verdict == Verdict.CONFIRMED:
            return Resolved(sv, "trusted_store", (ev.evidence_id,))
        c = latest_claim(claims, key)                # store refuted
        if c is not None and not values_equal(c.value, sv):
            return Resolved(c.value, "untrusted", claim_ids=(c.claim_id,))
        return None

    def run(self, spec: TaskSpec, rt: Runtime, ctx: RunContext) -> None:
        keys = spec.grant.fact_keys()
        planner_call(rt, spec, 120)                      # choose retrieval (context stays T: results hidden)
        docs = retrieve(spec, rt)
        stores = store_values(spec, rt)
        claims, _, _ = read_all(rt, docs, keys, ctx)     # query_llm into U variables
        facts: dict[FactKey, Resolved] = {}
        for key in keys:
            planner_call(rt, spec, 80)                   # one planner turn per argument decision
            if self.mode == "typed":                     # verifier bool admitted by the capacity hatch
                r = resolve(spec, rt, key, claims, stores.get(key), EP_POLICY, omit=ctx.omits(key))
                if r is not None:
                    facts[key] = r
                continue
            ref, lookup = ref_info(spec, rt, key)
            critical = bool(slot_roles(spec, key) & FIDES_CRITICAL)
            sv = stores.get(key)
            if ref and lookup and self.planner == "strong":   # lookup keyed by the trusted entity id -> T
                r = try_lookup(rt, ref, key)
                if r is not None:
                    facts[key] = r
                    continue
            if self.planner == "strong" and sv is not None and ref and (self.mode == "as_evaluated" or critical):
                r = self._store_first(spec, rt, key, claims, sv, ref, critical)
                if r is not None:
                    facts[key] = r
                continue
            c = latest_claim(claims, key)                # pass the query_llm variable by reference
            if c is not None:
                facts[key] = Resolved(c.value, "untrusted", claim_ids=(c.claim_id,))
            elif sv is not None:
                facts[key] = Resolved(sv, "trusted_store")
        # a condition on a U value is data-dependent control flow: the planner must expand it -> context U
        context_tainted = any(t.condition and t.condition.fact in facts and facts[t.condition.fact].basis == "untrusted"
                              for t in spec.grant.templates)
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
            tpl = spec.grant.templates[act.template]
            for b in act.justification:
                if tpl.slot(b.slot).role in FIDES_CRITICAL and b.basis not in TRUSTED_BASES:
                    return f"P-T(arg): argument '{b.slot}' is U-labelled"
        return None


# ================================================================== controls
class ProvenanceTrust(EvidencePreserving):
    """EP's authority rule R1, but truth taken from provenance: a claim from an authenticated sender
    is accepted (newest wins); unauthenticated claims are ignored; no verification."""
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
    """Grant-only actions; facts only from references (lookup) or reference-confirmed trusted
    stores; documents are never read. Tests whether reading documents is needed."""
    name = "Reference-only"
    family = "ablation"
    description = "ignores documents; lookup or verified trusted-store values only"

    def run(self, spec, rt, ctx):
        planner_call(rt, spec)
        stores = store_values(spec, rt)
        facts = {}
        for key in spec.grant.fact_keys():
            r = resolve(spec, rt, key, [], stores.get(key), ResolvePolicy(endorse=False))
            if r is not None:
                facts[key] = r
        actions, abst = instantiate(spec, facts, origin="grant")
        for tool, why in abst:
            rt.abstain(tool, why)
        commit_all(rt, actions)
