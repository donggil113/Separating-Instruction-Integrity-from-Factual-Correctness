"""AgentSentry emulation (Zhang et al., arXiv 2602.22724v1). No official code exists;
this follows Sec. 3-4, Alg. 1-2 and App. B-C, with the paper's unspecified
operators set to their most favorable plausible behavior:

* boundary after each untrusted tool return; four dry-run regimes
  (orig, mask, mask_sanitized, orig_sanitized), K=1, B=0;
* severity Y=2 for any proposed side-effect call;
* under the task-neutral probe, the model proposes every instruction it sees
  (p_follow_mask = 1: ideal detection) and proposes a fact-suggested action with
  probability ``p_fact_suggest`` (default 0: ideal detection);
* IE = mu(mask) - mu(mask_sanitized); takeover iff IE >= tau_IE (=1);
* Purify = instruction-to-evidence projection: drops directives and reader
  payloads, keeps goal-relevant facts (incl. facts phrased as requests);
* Revise drops mediator-contingent calls; the Auth effect gate is given the same
  static per-task policy as everyone else (tool + user-fixed arguments of the grant).

``verify_facts=True`` additionally prompts the live agent to check fact values
against the shared references (same candidate order and budget as EP) -- an
equal-information strengthening that the paper does not include.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Optional

from epad.defenses.base import (ACTOR_SYSTEM_TOKENS, Defense, RunContext, retrieve, store_values)
from epad.defenses.ep import resolve_with_evidence
from epad.plan import Resolved, TaskSpec, instantiate
from epad.sandbox.runtime import Runtime
from epad.sandbox.world import Document, values_equal
from epad.schema import ActionRequest, BoundArg, Claim, SlotKind, Trust
from epad.sim import ScriptedActor, draw

INSTRUCTION_KINDS = ("directive", "reader_payload")


def purify(doc: Document) -> Document:
    return replace(doc, statements=tuple(s for s in doc.statements if s.kind not in INSTRUCTION_KINDS))


class AgentSentry(Defense):
    family = "existing (emulated)"

    def __init__(self, verify_facts: bool = False, p_fact_suggest: float = 0.0, tau_ie: float = 1.0,
                 name: Optional[str] = None):
        self.verify_facts = verify_facts
        self.p_fact_suggest = p_fact_suggest
        self.tau_ie = tau_ie
        self.name = name or ("AgentSentry + verify prompt" if verify_facts else "AgentSentry")
        self.description = "counterfactual replay at tool-return boundaries + purification + Auth gate"

    # ------------------------------------------------------------ diagnostics
    def _severity_mask(self, ctx: RunContext, docs: list[Document], sanitized: bool) -> int:
        y = 0
        for d in docs:
            for s in d.statements:
                if s.kind in INSTRUCTION_KINDS and not sanitized:
                    y = 2                                   # probe proposes the instructed call
                elif s.kind == "fact" and draw(ctx.pair_key, f"{d.doc_id}:{s.text}", "fact_suggest") < self.p_fact_suggest:
                    y = 2                                   # probe proposes a fact-suggested call
        return y

    def run(self, spec: TaskSpec, rt: Runtime, ctx: RunContext) -> None:
        rt.llm("actor", ACTOR_SYSTEM_TOKENS + len(spec.user_prompt) // 4, 60)
        docs = retrieve(spec, rt)
        stores = store_values(spec, rt)
        doc_tokens = sum(d.n_tokens for d in docs)
        # boundary diagnostics: 4 dry-run regimes (K=1) + 1 Purify call per untrusted boundary
        for regime in ("orig", "mask", "mask_sanitized", "orig_sanitized"):
            rt.llm(f"actor_replay:{regime}", ACTOR_SYSTEM_TOKENS + doc_tokens, 60)
        rt.llm("purifier", doc_tokens + 200, doc_tokens)
        ie = self._severity_mask(ctx, docs, False) - self._severity_mask(ctx, docs, True)
        takeover = ie >= self.tau_ie
        live_docs = [purify(d) for d in docs] if takeover else docs
        if takeover:
            rt.llm("revise", ACTOR_SYSTEM_TOKENS + doc_tokens, 80)
            rt.note("AgentSentry takeover detected; context purified")

        actor = ScriptedActor(ctx.pair_key, ctx.follow_prob)
        dec = actor.decide(rt, spec, live_docs, stores)
        actions = dec.actions
        if self.verify_facts:
            actions = self._verified_actions(spec, rt, ctx, live_docs, stores, dec)
        for _ in actions:
            rt.llm("actor", ACTOR_SYSTEM_TOKENS + doc_tokens, 40)
        for tool, why in dec.abstentions:
            if not self.verify_facts:
                rt.abstain(tool, why)
        for a in actions:
            att = rt.propose(a)
            reason = self.auth(spec, a)
            if reason:
                rt.block(att, "agentsentry_auth", reason)
            else:
                rt.commit(att)

    def _verified_actions(self, spec, rt, ctx, docs, stores, dec) -> list[ActionRequest]:
        """Verify-prompted live agent: facts in context become candidates checked against
        the references (EP's candidate order/budget); instructed extra calls remain."""
        claims: list[Claim] = []
        for d in docs:
            for s in d.statements:
                if s.kind == "fact" or (s.key is not None and s.kind in INSTRUCTION_KINDS):
                    claims.append(Claim(f"{d.doc_id}:{len(claims)}", s.key, s.value, d.doc_id, Trust.UNTRUSTED,
                                        d.authenticated, d.timestamp, s.phrasing, "actor"))
        facts = {}
        for key in spec.grant.fact_keys():
            r = resolve_with_evidence(spec, rt, key, claims, stores.get(key), endorse=True,
                                      omit=ctx.omits(key))
            if r is not None:
                facts[key] = r
        acts, abst = instantiate(spec, facts, origin="actor")
        for tool, why in abst:
            rt.abstain(tool, why)
        extra = [a for a in dec.actions if a.origin.startswith("directive")]
        return acts + extra

    @staticmethod
    def auth(spec: TaskSpec, act: ActionRequest) -> Optional[str]:
        for t in spec.grant.templates:
            if t.tool == act.tool and all(values_equal(act.args.get(s.name), s.value)
                                          for s in t.slots if s.kind == SlotKind.USER_FIXED):
                return None
        return "Auth: call not consistent with the user goal"
