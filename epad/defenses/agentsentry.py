"""AgentSentry emulation (Zhang et al., arXiv 2602.22724v1). No official code exists;
this follows Sec. 3-4, Alg. 1-2 and App. B-C. Where the paper is unspecified the choice is
stated, and every choice that can be wrong is a knob:

* boundary = each tool return (documents, trusted-store reads, verifier returns); four dry-run
  regimes (orig, mask, mask_sanitized, orig_sanitized) at K=1, B=0 plus one Purify per boundary;
* severity Y=2 for any proposed side-effect call. Tool-less instructions (argument redirects,
  extractor payloads) are scored as if the probe proposed the redirected call (ideal detection);
* the probe proposes each instruction it sees (p_follow_mask = 1) and a fact-suggested action
  with probability ``p_fact_suggest`` (default 0 = ideal detection; swept);
* takeover iff IE = mu(mask) - mu(mask_sanitized) >= 1;
* Purify = instruction-to-evidence projection: drops directives and payloads, keeps goal-relevant
  facts. It is an LLM reading attacker text, so it gets the same knobs as every reader: rho
  (a payload can make it report the payload value), keep_imperative_facts, directive_as_claim;
* Revise drops mediator-contingent calls (the live decision on the purified context replaces the
  raw one); the Auth effect gate checks tool + user-fixed arguments of the grant
  (``auth="lenient"``: utility-favouring, fails open on false facts) or additionally that fact
  arguments equal the user's trusted state where it exists (``auth="strict"``: fails closed on
  legitimate changes). The paper leaves Auth unspecified; both readings are reported.

``verify_facts=True`` prompts the live agent to check fact values against the shared references.
It is modelled with EP's resolver (perfect adherence, immune to phi) -- i.e. a transplant of EP's
rule into AgentSentry, reported as such.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Optional

from epad.defenses.base import (ACTOR_SYSTEM_TOKENS, EP_POLICY, Defense, RunContext, resolve, retrieve,
                                store_values)
from epad.plan import Resolved, TaskSpec, apply_transform, instantiate
from epad.sandbox.runtime import Runtime
from epad.sandbox.world import Document, Statement, values_equal
from epad.schema import ActionRequest, Claim, SlotKind, Trust
from epad.sim import ScriptedActor, draw

INSTRUCTION_KINDS = ("directive", "reader_payload")


def purify(doc: Document, ctx: Optional[RunContext] = None) -> Document:
    """Instruction-to-evidence projection, with the same failure knobs as a quarantined reader."""
    rho = ctx.compromise_prob if ctx else 0.0
    keep_imp = ctx.keep_imperative_facts if ctx else 1.0
    dir_claim = ctx.directive_as_claim if ctx else 0.0
    key = ctx.pair_key if ctx else ""
    hijacked = {}
    for s in doc.statements:
        if s.kind == "reader_payload" and s.key is not None and draw(key, f"{doc.doc_id}:{s.text}", "reader_compromise") < rho:
            hijacked[s.key] = s.value
    out = []
    for s in doc.statements:
        if s.kind == "fact":
            if s.key in hijacked:
                continue
            if s.phrasing == "imperative" and draw(key, f"{doc.doc_id}:{s.text}", "imp_fact") >= keep_imp:
                continue
            out.append(s)
        elif s.kind == "directive" and s.key is not None and draw(key, f"{doc.doc_id}:{s.text}", "dir_claim") < dir_claim:
            out.append(Statement("fact", s.text, s.key, s.value, "imperative"))
        elif s.kind == "note":
            out.append(s)
    for k, v in hijacked.items():
        out.append(Statement("fact", f"(extracted) {k[1]}: {v}", k, v))
    return replace(doc, statements=tuple(out))


def auth_check(spec: TaskSpec, act: ActionRequest, stores: dict, strict: bool) -> Optional[str]:
    for t in spec.grant.templates:
        if t.tool == act.tool and all(values_equal(act.args.get(s.name), s.value)
                                      for s in t.slots if s.kind == SlotKind.USER_FIXED):
            if strict:
                for s in t.slots:
                    if s.kind == SlotKind.FACT and s.fact in stores and not values_equal(
                            act.args.get(s.name), apply_transform(s.transform, stores[s.fact])):
                        return f"Auth(strict): {s.name} disagrees with trusted state"
            return None
    return "Auth: call not consistent with the user goal"


class AgentSentry(Defense):
    family = "existing (emulated)"

    def __init__(self, verify_facts: bool = False, p_fact_suggest: float = 0.0, auth: str = "lenient",
                 name: Optional[str] = None):
        self.verify_facts = verify_facts
        self.p_fact_suggest = p_fact_suggest
        self.auth = auth
        base = "AgentSentry + verify prompt" if verify_facts else "AgentSentry"
        self.name = name or (base if auth == "lenient" else f"{base} (strict Auth)")
        self.description = "counterfactual replay at tool-return boundaries + purification + Auth gate"

    def _severity_mask(self, ctx: RunContext, docs: list[Document], sanitized: bool) -> int:
        y = 0
        for d in docs:
            for s in d.statements:
                if s.kind in INSTRUCTION_KINDS and not sanitized:
                    y = 2
                elif s.kind == "fact" and draw(ctx.pair_key, f"{d.doc_id}:{s.text}", "fact_suggest") < self.p_fact_suggest:
                    y = 2
        return y

    def _boundary(self, rt: Runtime, tokens: int) -> None:
        for regime in ("orig", "mask", "mask_sanitized", "orig_sanitized"):
            rt.llm(f"actor_replay:{regime}", ACTOR_SYSTEM_TOKENS + tokens, 60)
        rt.llm("purifier", tokens + 200, max(20, tokens))

    def run(self, spec: TaskSpec, rt: Runtime, ctx: RunContext) -> None:
        rt.llm("actor", ACTOR_SYSTEM_TOKENS + len(spec.user_prompt) // 4, 60)
        docs = retrieve(spec, rt)
        doc_tokens = sum(d.n_tokens for d in docs)
        self._boundary(rt, doc_tokens)                           # boundary: document return
        stores = store_values(spec, rt)
        if stores:
            self._boundary(rt, 40)                               # boundary: trusted-store return
        ie = self._severity_mask(ctx, docs, False) - self._severity_mask(ctx, docs, True)
        takeover = ie >= 1
        live_docs = [purify(d, ctx) for d in docs] if takeover else docs
        if takeover:
            rt.llm("revise", ACTOR_SYSTEM_TOKENS + doc_tokens, 80)
            rt.note("AgentSentry takeover detected; context purified")
        actor = ScriptedActor(ctx.pair_key, ctx.follow_prob)
        dec = actor.decide(rt, spec, live_docs, stores)
        actions, abst = dec.actions, dec.abstentions
        if self.verify_facts:
            actions, abst = self._verified_actions(spec, rt, ctx, live_docs, stores, dec)
        for _ in actions:
            rt.llm("actor", ACTOR_SYSTEM_TOKENS + doc_tokens, 40)
        for tool, why in abst:
            rt.abstain(tool, why)
        for a in actions:
            att = rt.propose(a)
            reason = auth_check(spec, a, stores, self.auth == "strict")
            if reason:
                rt.block(att, "agentsentry_auth", reason)
            else:
                rt.commit(att)

    def _verified_actions(self, spec, rt, ctx, docs, stores, dec):
        claims: list[Claim] = []
        for d in docs:
            for s in d.statements:
                if s.kind == "fact" or (s.key is not None and s.kind in INSTRUCTION_KINDS):
                    claims.append(Claim(f"{d.doc_id}:{len(claims)}", s.key, s.value, d.doc_id, Trust.UNTRUSTED,
                                        d.authenticated, d.timestamp, s.phrasing, "actor"))
        facts = {}
        n0 = len(rt.log.verifications)
        for key in spec.grant.fact_keys():
            r = resolve(spec, rt, key, claims, stores.get(key), EP_POLICY, omit=ctx.omits(key))
            if r is not None:
                facts[key] = r
        for _ in rt.log.verifications[n0:]:                      # each verifier return: a turn + a boundary
            rt.llm("actor", ACTOR_SYSTEM_TOKENS + 200, 40)
            self._boundary(rt, 30)
        acts, abst = instantiate(spec, facts, origin="actor")
        extra = [a for a in dec.actions if a.origin.startswith("directive")]
        return acts + extra, abst
