"""Reactive (ReAct-style) agents: the LLM sees untrusted content and picks tool calls.

* NoDefense   -- the undefended agent (AgentDojo "no defense" analogue).
* ToolFilter  -- AgentDojo's tool-filter baseline: before seeing any data, the
                 model restricts the tool set to what the user's request needs.
* VerifyGuard -- ablation: a fact-checking monitor that verifies every
                 checkable argument against the shared references and blocks
                 refuted calls, but has no notion of authority. It isolates
                 "verification without authority separation".
* DenyAll     -- never acts (safety floor; utility floor).

All get the same references and budget; only VerifyGuard spends it.
"""
from __future__ import annotations

from typing import Any, Optional

from epad.cases.tasks import payee_id, slug
from epad.defenses.base import (ACTOR_SYSTEM_TOKENS, Defense, RunContext, planner_call, retrieve,
                                store_values, try_verify)
from epad.plan import TaskSpec, invert_transform
from epad.sandbox.runtime import Runtime
from epad.schema import ActionRequest, FactKey, SlotKind, Verdict
from epad.sim import ScriptedActor


def run_actor(spec: TaskSpec, rt: Runtime, ctx: RunContext, docs=None, role: str = "actor"):
    rt.llm(role, ACTOR_SYSTEM_TOKENS + len(spec.user_prompt) // 4, 60)   # turn 1: decide what to read
    docs = retrieve(spec, rt) if docs is None else docs
    stores = store_values(spec, rt)
    actor = ScriptedActor(ctx.pair_key, ctx.follow_prob)
    dec = actor.decide(rt, spec, docs, stores, role=role)
    for _ in dec.actions:                                                  # one turn per emitted call
        rt.llm(role, ACTOR_SYSTEM_TOKENS + sum(d.n_tokens for d in docs), 40)
    return dec, docs


class NoDefense(Defense):
    name = "No defense"
    family = "reference point"
    description = "ReAct agent; untrusted content in context; credulous about facts"

    def run(self, spec, rt, ctx):
        dec, _ = run_actor(spec, rt, ctx)
        for tool, why in dec.abstentions:
            rt.abstain(tool, why)
        for a in dec.actions:
            rt.commit(rt.propose(a))


class ToolFilter(Defense):
    name = "Tool filter"
    family = "AgentDojo baseline"
    description = "tools restricted to those the user request needs, chosen before reading data"

    def run(self, spec, rt, ctx):
        allowed = spec.grant.tools()
        dec, _ = run_actor(spec, rt, ctx)
        for tool, why in dec.abstentions:
            rt.abstain(tool, why)
        for a in dec.actions:
            att = rt.propose(a)
            if a.tool in allowed:
                rt.commit(att)
            else:
                rt.block(att, "tool_filter", f"{a.tool} not in filtered tool set")


def checkable_keys(spec: TaskSpec, act: ActionRequest) -> list[tuple[FactKey, Any, Optional[str]]]:
    """(key, value-to-check, transform) for the arguments of ``act`` that a
    reference can check, derived from the action alone (the guard does not know
    which call the user authorized)."""
    out = []
    for t in spec.grant.templates:
        if t.tool != act.tool:
            continue
        for s in t.slots:
            if s.kind == SlotKind.FACT:   # derived arguments are inverted to the underlying fact value
                out.append((s.fact, invert_transform(s.transform, act.args.get(s.name)), s.transform))
    if act.tool == "send_payment":
        out.append(((payee_id(act.args["payee"]), "account"), act.args["account"], None))
    if act.tool == "place_order":
        out.append(((f"product:{act.args['sku']}@{slug(act.args['supplier'])}", "unit_price"),
                    act.args["unit_price"], None))
    seen, uniq = set(), []
    for k, v, tr in out:
        if (k, str(v)) not in seen:
            seen.add((k, str(v)))
            uniq.append((k, v, tr))
    return uniq


class VerifyGuard(Defense):
    name = "Verify-only guard"
    family = "ablation"
    description = "fact-checks every checkable argument against the references; blocks refuted calls; no authority"

    def run(self, spec, rt, ctx):
        dec, _ = run_actor(spec, rt, ctx)
        for tool, why in dec.abstentions:
            rt.abstain(tool, why)
        refs = {r["name"]: r for r in rt.references()}
        for a in dec.actions:
            att = rt.propose(a)
            reason = None
            for key, value, _ in checkable_keys(spec, a):
                ref = spec.reference_for(key) or next((n for n, r in refs.items() if key[1] in r["attributes"]), None)
                if ref is None:
                    continue
                ev = try_verify(rt, ref, key, value)
                if ev is not None and ev.verdict == Verdict.REFUTED:
                    reason = f"reference {ref} refutes {key[1]}={value}"
                    break
            if reason:
                rt.block(att, "verify_guard", reason)
            else:
                rt.commit(att)


class DenyAll(Defense):
    name = "Deny-all"
    family = "reference point"
    description = "never performs a side effect"

    def run(self, spec, rt, ctx):
        planner_call(rt, spec, 20)
        for t in spec.grant.templates:
            rt.abstain(t.tool, "deny-all")
