"""Evidence-Preserving defense (EP): the design studied in this project.

Pipeline:  user request --(trusted planner)--> AuthorityGrant
           untrusted docs --(quarantined reader, schema = grant's fact keys)--> Claims (+ Directives, audit only)
           trusted user store --> one more *candidate* (the user's record; fresh or stale)
           candidate --(independent reference, entity id from the grant)--> Evidence
           Evidence-backed value --> FACT argument / condition of an action the grant already permits
           reference monitor re-checks every proposed action before commit.

Not new (credited in docs/01_related_work.md): plan-from-trusted-query and quarantined extraction
(Dual-LLM / CaMeL / Fides variable passing), provenance/taint labels (IFC), endorsement (IFC; Fides'
typed escape hatch), reference monitors, verify-before-pay (Confirmation-of-Payee / VoP practice).
What EP fixes as *rules*:

  R1  Authority only from the grant: documents cannot add tools, calls, counterparties or user-fixed
      values; directives are recorded, never run.
  R2  Every FACT argument and every condition fact must be backed by a CONFIRMED verdict (or a lookup)
      from the reference configured for exactly that (entity-from-grant, attribute) key, for exactly
      that value. The user's own store is a candidate like any other: it is trusted not to be forged,
      not to be current. Provenance (authenticated sender) and hashes are never evidence.
  R3  If no admissible value exists within the verification budget, escalate instead of acting.

``EvidencePreserving(policy=EP_PRE_AUDIT, strict=False)`` reproduces the version that the adversarial
audit broke (uncontested store bound unverified; contested store bound after refuting challengers).
"""
from __future__ import annotations

import re
from typing import Optional

from epad.defenses.base import (EP_POLICY, EP_PRE_AUDIT, Defense, ResolvePolicy, RunContext, commit_all,
                                planner_call, read_all, resolve, retrieve, store_values)
from epad.plan import Resolved, TaskSpec, apply_transform, eval_condition, instantiate
from epad.sandbox.runtime import Runtime
from epad.sandbox.world import values_equal
from epad.schema import ActionRequest, FactKey, Policy, SlotKind, Verdict


class EvidencePreserving(Defense):
    name = "EP (ours)"
    family = "ours"
    description = "authority from grant only; every fact value -> independent verification -> argument; else escalate"

    def __init__(self, policy: ResolvePolicy = EP_POLICY, strict: bool = True, name: Optional[str] = None,
                 deploy_policy: Policy = Policy()):
        self.policy = policy
        self.strict = strict                 # monitor requires reference evidence for every FACT value
        self.deploy_policy = deploy_policy
        if name:
            self.name = name

    def run(self, spec: TaskSpec, rt: Runtime, ctx: RunContext) -> None:
        planner_call(rt, spec)                       # grant derived from the user request only
        keys = spec.grant.fact_keys()
        docs = retrieve(spec, rt)
        claims, directives, _ = read_all(rt, docs, keys, ctx)
        for d in directives:                         # R1: preserved for audit, never executed
            rt.note(f"directive ignored ({d.source}): {d.text[:80]}")
        stores = store_values(spec, rt)
        facts: dict[FactKey, Resolved] = {}
        for key in keys:
            r = resolve(spec, rt, key, claims, stores.get(key), self.policy, omit=ctx.omits(key))
            if r is not None:
                facts[key] = r
        refuted = [e for e in rt.log.verifications if e.verdict in (Verdict.REFUTED, Verdict.CLOSE_MATCH)
                   and e.claim_id is not None]
        for e in refuted:                            # surfaced: a document claim the reference contradicts
            rt.note(f"refuted claim {e.claim_id}: {e.key[1]}={e.value} ({e.verdict.value})")
        actions, abstentions = instantiate(spec, facts, origin="grant")
        for tool, why in abstentions:
            rt.abstain(tool, why)
        commit_all(rt, actions, lambda a: self.monitor(spec, rt, a, facts), by="ep_monitor")

    # ---------------------------------------------------------- reference monitor
    def _admissible(self, spec: TaskSpec, rt: Runtime, key: FactKey, r: Optional[Resolved],
                    value, transform: Optional[str]) -> Optional[str]:
        if r is None:
            return f"R2: {key[1]} unresolved"
        evid = {e.evidence_id: e for e in rt.log.verifications}
        ok_ev = any(evid.get(i) and evid[i].verdict == Verdict.CONFIRMED and evid[i].key == key
                    and evid[i].reference == spec.reference_for(key)
                    and values_equal(apply_transform(transform, evid[i].value), value)
                    for i in r.evidence_ids)
        if ok_ev:
            return None
        if not self.strict and r.basis == "trusted_store":
            store = spec.store_for(key)
            sv = rt.read_store(store, key) if store else None
            if sv is not None and values_equal(apply_transform(transform, sv), value):
                return None
        return f"R2: no reference evidence for {key[1]}={value} (basis {r.basis})"

    def monitor(self, spec: TaskSpec, rt: Runtime, act: ActionRequest, facts: dict) -> Optional[str]:
        if act.template is None or not (0 <= act.template < len(spec.grant.templates)):
            return "R1: action not instantiated from the user's grant"
        tpl = spec.grant.templates[act.template]
        if tpl.tool != act.tool or not all(values_equal(act.args.get(s.name), s.value)
                                           for s in tpl.slots if s.kind == SlotKind.USER_FIXED):
            return "R1: action does not match its grant template"
        n_same = sum(1 for a in rt.log.committed if a.template == act.template)
        if n_same >= tpl.max_calls:
            return "R1: call count exceeds grant"
        if tpl.condition is not None:                # R2 for condition facts, re-evaluated here
            cr = facts.get(tpl.condition.fact)
            why = self._admissible(spec, rt, tpl.condition.fact, cr, cr.value if cr else None, None)
            if why or eval_condition(tpl.condition, facts) is not True:
                return why or "R2: grant condition not established"
        just = {b.slot: b for b in act.justification}
        for s in tpl.slots:
            v = act.args.get(s.name)
            if s.kind == SlotKind.FREE:
                if (s.free_pattern and not re.match(s.free_pattern, str(v))) or len(str(v)) > s.free_max_len:
                    return f"free arg {s.name} violates constraint"
            elif s.kind == SlotKind.FACT:
                b = just.get(s.name)
                r = facts.get(s.fact)
                if b is None or r is None:
                    return f"R2: no basis for {s.name}"
                why = self._admissible(spec, rt, s.fact, r, v, s.transform)
                if why:
                    return why
        if act.tool == "send_payment" and float(act.args.get("amount", 0)) > self.deploy_policy.max_payment:
            return "policy: payment limit"
        if any(isinstance(v, str) and m in v.upper() for v in act.args.values()
               for m in self.deploy_policy.sensitive_markers):
            return "policy: sensitive data in arguments"
        return None


def ep_pre_audit() -> EvidencePreserving:
    return EvidencePreserving(EP_PRE_AUDIT, strict=False, name="EP v0 (pre-audit)")
