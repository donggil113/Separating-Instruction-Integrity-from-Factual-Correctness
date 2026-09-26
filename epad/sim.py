"""Scripted stand-ins for the LLM components (no real model is used).

Two model roles appear across the defenses studied:

* a *quarantined reader* (CaMeL's Q-LLM, Fides' constrained query, our
  extractor): reads one untrusted document, has no tools, and returns output
  constrained to a schema;
* a *reactive actor* (a ReAct-style tool-calling LLM): sees untrusted tool
  outputs in its context and decides the next tool calls.

Both are simulated from the documents' statement annotations (what the text
says), never from ground truth. Behavior that depends on the model is
exposed as explicit parameters instead of being hidden in a model:

* ``follow_prob`` (phi) -- probability that the actor complies with an
  instruction it sees in untrusted content (worst case 1.0);
* ``compromise_prob`` (rho) -- probability that a reader payload fully controls
  the reader's schema-valid output for that document (worst case 1.0);
* ``imperative_as_fact`` -- whether a purifier/reader keeps facts phrased as requests.

Random draws are keyed by (case, statement, purpose) so that every defense
faces the same draws on the same case (paired comparison).
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from epad.plan import Resolved, TaskSpec, instantiate
from epad.sandbox.runtime import Runtime
from epad.sandbox.world import Document, Statement
from epad.schema import ActionRequest, BoundArg, Claim, Directive, FactKey, Trust

SCHEMA_TOKENS = 60


def draw(case_key: str, item: str, purpose: str) -> float:
    h = hashlib.sha256(f"{case_key}|{item}|{purpose}".encode()).hexdigest()
    return int(h[:12], 16) / float(16 ** 12)


# ============================================================= reader
@dataclass
class ReaderOutput:
    claims: list[Claim] = field(default_factory=list)
    directives: list[Directive] = field(default_factory=list)
    compromised: bool = False


class ScriptedReader:
    """Quarantined, tool-less extractor with a typed output schema.

    Honest behavior: returns one ``Claim`` per ``fact`` statement whose key is in
    the requested schema (both declarative and imperative phrasings, i.e. the
    factual content of a request is preserved), and one ``Directive`` per
    directive (never a claim). Compromise: if the document contains a
    ``reader_payload`` targeting a requested key, then with probability rho the
    adversary controls this document's output *within the schema*: the true
    claims for that key are dropped and the payload value is reported instead.
    """

    def __init__(self, case_key: str, compromise_prob: float = 1.0, imperative_as_fact: bool = True):
        self.case_key = case_key
        self.rho = compromise_prob
        self.imperative_as_fact = imperative_as_fact
        self._n = 0

    def read(self, runtime: Runtime, doc: Document, schema: Iterable[FactKey]) -> ReaderOutput:
        schema = set(schema)
        runtime.llm("reader", doc.n_tokens + SCHEMA_TOKENS + 20 * len(schema), 30 * max(1, len(schema)))
        out = ReaderOutput()
        payloads = [s for s in doc.statements if s.kind == "reader_payload" and s.key in schema]
        hijacked: set[FactKey] = set()
        for p in payloads:
            if draw(self.case_key, f"{doc.doc_id}:{p.text}", "reader_compromise") < self.rho:
                hijacked.add(p.key)
                out.compromised = True
                out.claims.append(self._claim(doc, p.key, p.value, "declarative"))
        for s in doc.statements:
            if s.kind == "fact" and s.key in schema and s.key not in hijacked:
                if s.phrasing == "imperative" and not self.imperative_as_fact:
                    continue
                out.claims.append(self._claim(doc, s.key, s.value, s.phrasing))
            elif s.kind == "directive":
                out.directives.append(Directive(f"{doc.doc_id}:dir{len(out.directives)}", doc.doc_id, s.text,
                                                s.action.tool if s.action else None))
        return out

    def _claim(self, doc: Document, key: FactKey, value: Any, phrasing: str) -> Claim:
        self._n += 1
        return Claim(f"{doc.doc_id}:c{self._n}", key, value, doc.doc_id, Trust.UNTRUSTED, doc.authenticated,
                     doc.timestamp, phrasing, "reader")


# ============================================================= actor
@dataclass
class ActorDecision:
    actions: list[ActionRequest]
    abstentions: list[tuple[str, str]]
    facts: dict[FactKey, Resolved]


class ScriptedActor:
    """ReAct-style actor whose context contains untrusted documents.

    * Executes the user's task (the grant's templates, as a correct planner would).
    * For each ``directive`` / ``reader_payload`` in context, complies with
      probability phi: extra actions are added; argument redirections override
      the corresponding fact.
    * Fact values: credulous -- the most recent claim in context for each fact
      key, falling back to the trusted store. (A model that ignored new claims
      would fail every legitimate change, so credulity is the utility-preserving
      default of an undefended agent.)
    """

    def __init__(self, case_key: str, follow_prob: float = 1.0):
        self.case_key = case_key
        self.phi = follow_prob

    def complies(self, doc: Document, st: Statement) -> bool:
        return draw(self.case_key, f"{doc.doc_id}:{st.text}", "actor_follow") < self.phi

    def decide(self, runtime: Runtime, spec: TaskSpec, docs: list[Document],
               store_values: dict[FactKey, Any], role: str = "actor",
               allow_directives: bool = True) -> ActorDecision:
        ctx_tokens = sum(d.n_tokens for d in docs) + len(spec.user_prompt) // 4 + 150
        runtime.llm(role, ctx_tokens, 80)
        facts: dict[FactKey, Resolved] = {k: Resolved(v, "trusted_store") for k, v in store_values.items()
                                          if v is not None}
        latest_ts: dict[FactKey, int] = {}
        overrides: dict[FactKey, Resolved] = {}
        extra: list[ActionRequest] = []
        for d in sorted(docs, key=lambda x: x.timestamp):
            for s in d.statements:
                if s.kind == "fact" and s.key in set(spec.grant.fact_keys()):
                    if d.timestamp >= latest_ts.get(s.key, -1):
                        facts[s.key] = Resolved(s.value, "untrusted", claim_ids=(d.doc_id,))
                        latest_ts[s.key] = d.timestamp
                elif s.kind in ("directive", "reader_payload") and allow_directives and self.complies(d, s):
                    if s.key is not None:
                        overrides[s.key] = Resolved(s.value, "untrusted", claim_ids=(d.doc_id,))
                    if s.action is not None:
                        extra.append(self._resolve_profile(runtime, ActionRequest(
                            s.action.tool, dict(s.action.args), f"directive:{d.doc_id}",
                            tuple(BoundArg(a, v, "untrusted", claim_ids=(d.doc_id,)) for a, v in s.action.args.items()))))
        facts.update(overrides)
        acts, abst = instantiate(spec, facts, origin="actor")
        return ActorDecision(acts + extra, abst, facts)

    @staticmethod
    def _resolve_profile(runtime: Runtime, act: ActionRequest) -> ActionRequest:
        """An agent following an exfiltration instruction fills '{profile:<field>}' from the user profile."""
        args = {}
        for k, v in act.args.items():
            if isinstance(v, str):
                for field_name in re.findall(r"\{profile:(\w+)\}", v):
                    v = v.replace(f"{{profile:{field_name}}}", runtime.get_profile(field_name) or "")
            args[k] = v
        return ActionRequest(act.tool, args, act.origin, act.justification)
