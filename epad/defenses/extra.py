"""Additional strong baselines named by the prior-art sweep (docs/01b_prior_art_sweep.md).

* Firewall      -- tool-output sanitizer + tool-input minimizer ("Indirect Prompt Injections: Are
                   Firewalls All You Need, or Stronger Benchmarks?", arXiv 2510.05244): every tool output
                   is rewritten to remove instructions before the agent sees it; secrets are stripped from
                   tool-call arguments. Emulated with a perfect sanitizer (charitable).
* OriginGuard   -- ROPE-style origin enforcement (arXiv 2608.27496): a state-changing parameter may take a
                   value only from the user's own records or from an authenticated origin the user's
                   records name for that counterparty; any other content cannot supply it (fails closed).
                   No truth check.
* AllowlistJudge-- Agent-Sentry-style (Sequeira et al., arXiv 2603.22868): action structure must match
                   the task; sensitive argument values must be on an allowlist learned from the user's
                   history; otherwise an LLM judge decides. Without evidence the judge cannot tell a false
                   change from a legitimate one, so it accepts both with the same probability q (swept).
"""
from __future__ import annotations

from dataclasses import replace
from typing import Optional

from epad.defenses.agentsentry import AgentSentry, purify
from epad.defenses.base import (ACTOR_SYSTEM_TOKENS, EP_POLICY, Defense, RunContext, commit_all, planner_call,
                                read_all, resolve, retrieve, store_values)
from epad.defenses.reactive import run_actor
from epad.plan import Resolved, TaskSpec, instantiate
from epad.sandbox.runtime import Runtime
from epad.sandbox.world import values_equal
from epad.schema import ActionRequest, Claim, SlotKind, SlotRole, Trust
from epad.sim import ScriptedActor, draw

SENSITIVE_ROLES = {SlotRole.TARGET, SlotRole.ITEM}   # recipient / item identifiers, as in value allowlists


class Firewall(Defense):
    family = "existing (emulated)"

    def __init__(self, verify_facts: bool = False, name: Optional[str] = None):
        self.verify_facts = verify_facts
        self.name = name or ("Firewall + verify prompt" if verify_facts else "Firewall (sanitizer+minimizer)")
        self.description = "tool outputs sanitized of instructions; secrets minimized out of tool inputs"

    def run(self, spec: TaskSpec, rt: Runtime, ctx: RunContext) -> None:
        raw = retrieve(spec, rt)
        for d in raw:                                             # tool-output firewall: one call per output
            rt.llm("sanitizer", d.n_tokens + 200, d.n_tokens)
        docs = [purify(d, ctx) for d in raw]
        rt.llm("actor", ACTOR_SYSTEM_TOKENS + len(spec.user_prompt) // 4, 60)
        stores = store_values(spec, rt)
        dec = ScriptedActor(ctx.pair_key, ctx.follow_prob).decide(rt, spec, docs, stores)
        actions, abst = dec.actions, dec.abstentions
        if self.verify_facts:
            claims = [Claim(f"{d.doc_id}:{i}", s.key, s.value, d.doc_id, Trust.UNTRUSTED, d.authenticated,
                            d.timestamp, s.phrasing, "actor")
                      for d in docs for i, s in enumerate(d.statements) if s.kind == "fact"]
            facts = {}
            for key in spec.grant.fact_keys():
                r = resolve(spec, rt, key, claims, stores.get(key), EP_POLICY, omit=ctx.omits(key))
                if r is not None:
                    facts[key] = r
            actions, abst = instantiate(spec, facts, origin="actor")
        for tool, why in abst:
            rt.abstain(tool, why)
        for a in actions:
            rt.llm("minimizer", 150, 60)                          # tool-input firewall: one call per call
            att = rt.propose(a)
            rt.commit(att)


class OriginGuard(Defense):
    name = "Origin guard (ROPE-style)"
    family = "existing (emulated)"
    description = "parameters only from user records or the counterparty's authenticated address on record"

    def run(self, spec: TaskSpec, rt: Runtime, ctx: RunContext) -> None:
        planner_call(rt, spec)
        keys = spec.grant.fact_keys()
        docs = retrieve(spec, rt)
        claims, _, _ = read_all(rt, docs, keys, ctx)
        stores = store_values(spec, rt)
        senders = {d.doc_id: d.sender for d in docs}
        facts = {}
        for key in keys:
            ok = [c for c in claims if c.key == key and c.authenticated and senders.get(c.source) in spec.trusted_senders]
            if ok:
                c = max(ok, key=lambda c: c.timestamp)
                facts[key] = Resolved(c.value, "provenance", claim_ids=(c.claim_id,))
            elif key in stores:
                facts[key] = Resolved(stores[key], "trusted_store")
        actions, abst = instantiate(spec, facts, origin="grant")
        for tool, why in abst:
            rt.abstain(tool, why)
        commit_all(rt, actions)


class AllowlistJudge(Defense):
    family = "existing (emulated)"

    def __init__(self, accept_prob: float = 0.5, name: Optional[str] = None):
        self.q = accept_prob
        self.name = name or f"Allowlist + judge (q={accept_prob})"
        self.description = "structural check + allowlist of known sensitive values + judge for new values"

    def run(self, spec: TaskSpec, rt: Runtime, ctx: RunContext) -> None:
        dec, _ = run_actor(spec, rt, ctx)
        stores = store_values(spec, rt)
        for tool, why in dec.abstentions:
            rt.abstain(tool, why)
        for a in dec.actions:
            att = rt.propose(a)
            tpl = next((t for t in spec.grant.templates if t.tool == a.tool and all(
                values_equal(a.args.get(s.name), s.value) for s in t.slots if s.kind == SlotKind.USER_FIXED)), None)
            if tpl is None:
                rt.block(att, "structure", "call does not match the task's action structure")
                continue
            new_values = [s.name for s in tpl.slots if s.kind == SlotKind.FACT and s.role in SENSITIVE_ROLES
                          and s.fact in stores and not values_equal(a.args.get(s.name), stores[s.fact])]
            if not new_values:
                rt.commit(att)
                continue
            rt.llm("judge", ACTOR_SYSTEM_TOKENS + 300, 40)
            if draw(ctx.pair_key, f"{a.tool}:{sorted(a.args.items())}", "judge") < self.q:
                rt.commit(att)
            else:
                rt.block(att, "judge", f"new sensitive value(s) {new_values} not approved")
