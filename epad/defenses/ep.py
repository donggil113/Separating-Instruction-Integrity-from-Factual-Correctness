"""Evidence-Preserving defense (EP): the design studied in this project.

Pipeline:  user request --(trusted planner)--> AuthorityGrant
           untrusted docs --(quarantined reader, schema = grant's fact keys)--> Claims (+ Directives, audit only)
           Claim --(independent reference, entity id taken from the grant)--> Evidence
           Evidence-backed value --> FACT argument of an action the grant already permits
           reference monitor re-checks every proposed action before commit.

What is *not* new here (credited in docs/01_related_work.md): plan-from-trusted-
query and quarantined extraction (Dual-LLM / CaMeL / Fides variable passing),
provenance/taint labels (IFC), endorsement (IFC; Fides' capacity-based escape
hatch), reference monitors. What EP fixes as a *rule*:

  R1  Authority only from the grant: documents cannot add tools, calls,
      counterparties or user-fixed values; directives are recorded, never run.
  R2  A FACT argument may be bound only to a value with an admissible basis:
      (a) a CONFIRMED verdict from the reference configured for exactly that
          (entity, attribute) key, where the entity comes from the grant, or a
          lookup from that reference; or
      (b) an uncontested trusted-store value, when the slot's rule allows it.
      Provenance (authenticated sender) and content hashes are never a basis.
  R3  If no admissible value exists within the verification budget, abstain
      (escalate) for the affected action instead of guessing.
"""
from __future__ import annotations

import re
from typing import Any, Optional

from epad.defenses.base import (Defense, RunContext, commit_all, contested, planner_call, read_all,
                                ref_info, retrieve, slot_rule, store_values, try_lookup, try_verify,
                                verification_order)
from epad.plan import Resolved, TaskSpec, instantiate
from epad.sandbox.runtime import Runtime
from epad.sandbox.world import values_equal
from epad.schema import (ActionRequest, Claim, FactKey, Policy, SlotKind, Verdict, VerifyRule)


def resolve_with_evidence(spec: TaskSpec, rt: Runtime, key: FactKey, claims: list[Claim],
                          store_val: Any, endorse: bool = True, omit: bool = False) -> Optional[Resolved]:
    """Rule R2. ``endorse=False`` gives the provenance-only variant (no untrusted
    value may be bound even when the reference confirms it). ``omit=True``
    simulates a slip in which the verification step is skipped and the newest
    claimed value is used as-is (sensitivity analysis, omega)."""
    if omit:
        cs = sorted([c for c in claims if c.key == key], key=lambda c: c.timestamp)
        if cs:
            return Resolved(cs[-1].value, "untrusted", claim_ids=(cs[-1].claim_id,))
        return Resolved(store_val, "trusted_store") if store_val is not None else None
    ref, lookup = ref_info(spec, rt, key)
    rule = slot_rule(spec, key)
    is_contested = contested(claims, key, store_val) if store_val is not None else True
    if store_val is not None and not is_contested and rule == VerifyRule.IF_UNTRUSTED_OR_CONFLICT:
        return Resolved(store_val, "trusted_store")
    if ref is None:
        return None
    if lookup:
        return try_lookup(rt, ref, key)
    all_challengers_refuted = True
    for value, cs in verification_order(claims, key, store_val):
        is_store = store_val is not None and not cs and values_equal(value, store_val)
        if not is_store and not endorse:
            all_challengers_refuted = False       # provenance-only: an untrusted value can never be bound
            continue
        if is_store and all_challengers_refuted and rule == VerifyRule.IF_UNTRUSTED_OR_CONFLICT:
            return Resolved(store_val, "trusted_store")   # every challenger was refuted by the reference
        ev = try_verify(rt, ref, key, value, tuple(c.claim_id for c in cs))
        if ev is None or ev.verdict == Verdict.UNKNOWN:   # budget exhausted / not covered
            return None
        if ev.verdict == Verdict.CONFIRMED:
            basis = "evidence"
            return Resolved(value, basis, (ev.evidence_id,), tuple(c.claim_id for c in cs))
    return None


class EvidencePreserving(Defense):
    name = "EP (ours)"
    family = "ours"
    description = "authority from grant only; claim -> independent verification -> FACT argument; abstain otherwise"

    def __init__(self, endorse: bool = True, policy: Policy = Policy(), name: Optional[str] = None):
        self.endorse = endorse
        self.policy = policy
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
        # resolve condition facts and slots in grant order; unchallenged trusted values cost nothing
        for key in keys:
            r = resolve_with_evidence(spec, rt, key, claims, stores.get(key), endorse=self.endorse,
                                      omit=ctx.omits(key))
            if r is not None:
                facts[key] = r
        actions, abstentions = instantiate(spec, facts, origin="grant")
        for tool, why in abstentions:
            rt.abstain(tool, why)
        commit_all(rt, actions, lambda a: self.monitor(spec, rt, a, facts), by="ep_monitor")

    # ---------------------------------------------------------- reference monitor
    def monitor(self, spec: TaskSpec, rt: Runtime, act: ActionRequest, facts: dict) -> Optional[str]:
        tpl = next((t for t in spec.grant.templates if t.tool == act.tool and all(
            values_equal(act.args.get(s.name), s.value) for s in t.slots if s.kind == SlotKind.USER_FIXED)), None)
        if tpl is None:
            return "R1: action not permitted by the user's grant"
        n_same = sum(1 for a in rt.log.committed if a.tool == act.tool)
        if n_same >= tpl.max_calls:
            return "R1: call count exceeds grant"
        evid = {e.evidence_id: e for e in rt.log.verifications}
        just = {b.slot: b for b in act.justification}
        for s in tpl.slots:
            v = act.args.get(s.name)
            if s.kind == SlotKind.FREE:
                if s.free_pattern and not re.match(s.free_pattern, str(v)) or len(str(v)) > s.free_max_len:
                    return f"free arg {s.name} violates constraint"
            elif s.kind == SlotKind.FACT:
                b = just.get(s.name)
                if b is None:
                    return f"R2: no basis for {s.name}"
                if b.basis in ("evidence", "reference_lookup"):
                    ok = any(evid.get(i) and evid[i].verdict == Verdict.CONFIRMED and evid[i].key == s.fact
                             and evid[i].reference == spec.reference_for(s.fact) for i in b.evidence_ids)
                    if not ok:
                        return f"R2: evidence for {s.name} missing or not from the configured reference"
                elif b.basis != "trusted_store":
                    return f"R2: inadmissible basis {b.basis} for {s.name}"
        if act.tool == "send_payment" and float(act.args.get("amount", 0)) > self.policy.max_payment:
            return "policy: payment limit"
        if any(isinstance(v, str) and m in v.upper() for v in act.args.values() for m in self.policy.sensitive_markers):
            return "policy: sensitive data in arguments"
        return None
