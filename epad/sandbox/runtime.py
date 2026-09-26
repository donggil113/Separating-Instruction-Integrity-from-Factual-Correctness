"""Per-episode tool runtime shared by every defense.

All defenses get exactly the same interface: the same read tools, the same
trusted stores, the same independent references and the same verification
budget. The runtime is also the single place where side effects, blocked
attempts, verifications and model calls are recorded, so the metrics are
computed identically for every defense.

Ground truth is *not* reachable from here: the runtime holds the world (whose
references read from the true state, as a real reference service would), but
exposes only tool methods. ``tests/test_isolation.py`` checks that defense code
never touches the private ``_world`` attribute or imports the evaluator.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Any, Optional

from epad.schema import ActionRequest, Evidence, FactKey, Verdict
from epad.sandbox.world import Document, World

SIDE_EFFECT_TOOLS: dict[str, tuple[str, ...]] = {
    "send_payment": ("payee", "account", "amount", "reference"),
    "send_email": ("to", "subject", "body"),
    "create_event": ("title", "start", "attendees"),
    "book_room": ("room", "start"),
    "place_order": ("supplier", "sku", "qty", "unit_price"),
    "book_taxi": ("pickup_time", "origin", "destination"),
    "send_message": ("to", "text"),
}

READ_TOOLS = ("search_documents", "read_store", "get_profile")


class BudgetExhausted(RuntimeError):
    pass


@dataclass
class Attempt:
    attempt_id: int
    action: ActionRequest
    status: str = "pending"          # "committed" | "blocked"
    blocked_by: Optional[str] = None
    reason: Optional[str] = None


@dataclass
class LLMCall:
    role: str          # "planner" | "reader" | "actor" | "actor_replay" | "purifier" | ...
    in_tokens: int
    out_tokens: int


@dataclass
class EpisodeLog:
    attempts: list[Attempt] = field(default_factory=list)
    verifications: list[Evidence] = field(default_factory=list)
    llm_calls: list[LLMCall] = field(default_factory=list)
    tool_calls: list[tuple[str, dict]] = field(default_factory=list)
    abstentions: list[tuple[str, str]] = field(default_factory=list)   # (tool, reason)
    notes: list[str] = field(default_factory=list)
    budget_exhausted: bool = False

    @property
    def committed(self) -> list[ActionRequest]:
        return [a.action for a in self.attempts if a.status == "committed"]

    @property
    def blocked(self) -> list[Attempt]:
        return [a for a in self.attempts if a.status == "blocked"]


class Runtime:
    def __init__(self, world: World, verify_budget: int):
        self._world = world
        self.verify_budget = verify_budget
        self.log = EpisodeLog()
        self._ids = itertools.count()
        self._evid = itertools.count()

    # ------------------------------------------------------------------ read
    def search_documents(self, keyword: str) -> list[Document]:
        """Untrusted: third-party documents mentioning ``keyword`` (oldest first)."""
        self.log.tool_calls.append(("search_documents", {"keyword": keyword}))
        docs = [d for d in self._world.documents if keyword in d.mentions]
        return sorted(docs, key=lambda d: d.timestamp)

    def read_store(self, store: str, key: FactKey) -> Optional[Any]:
        """Trusted user-owned store (address book, itinerary, order history...).
        Integrity is trusted, freshness is not: it may be stale."""
        self.log.tool_calls.append(("read_store", {"store": store, "key": key}))
        return self._world.stores.get(store, {}).get(key)

    def get_profile(self, field_name: str) -> Optional[str]:
        self.log.tool_calls.append(("get_profile", {"field": field_name}))
        return self._world.profile.get(field_name)

    # ------------------------------------------------------------- references
    def references(self) -> list[dict]:
        return [r.public() for r in self._world.references.values()]

    def references_for(self, key: FactKey) -> list[dict]:
        return [r.public() for r in self._world.references.values() if r.covers(key)]

    @property
    def verifications_left(self) -> int:
        return self.verify_budget - len(self.log.verifications)

    def _charge(self) -> None:
        if self.verifications_left <= 0:
            self.log.budget_exhausted = True
            raise BudgetExhausted()

    def verify(self, reference: str, key: FactKey, value: Any, claim_id: Optional[str] = None) -> Evidence:
        """Ask an independent reference whether ``key == value`` (costs 1 budget unit)."""
        self._charge()
        ref = self._world.references[reference]
        verdict = ref.confirm(key, value)
        ev = Evidence(f"ev{next(self._evid)}", reference, key, value, verdict, "confirm", claim_id)
        self.log.verifications.append(ev)
        self.log.tool_calls.append(("verify", {"reference": reference, "key": key}))
        return ev

    def lookup(self, reference: str, key: FactKey) -> Evidence:
        """Ask a lookup-capable reference for the value of ``key`` (costs 1 budget unit)."""
        self._charge()
        ref = self._world.references[reference]
        value = ref.lookup(key)
        verdict = Verdict.UNKNOWN if value is None else Verdict.CONFIRMED
        ev = Evidence(f"ev{next(self._evid)}", reference, key, value, verdict, "lookup")
        self.log.verifications.append(ev)
        self.log.tool_calls.append(("lookup", {"reference": reference, "key": key}))
        return ev

    # ------------------------------------------------------------ model calls
    def llm(self, role: str, in_tokens: int, out_tokens: int = 50) -> None:
        self.log.llm_calls.append(LLMCall(role, int(in_tokens), int(out_tokens)))

    # ------------------------------------------------------------ side effects
    def propose(self, action: ActionRequest) -> Attempt:
        if action.tool not in SIDE_EFFECT_TOOLS:
            raise ValueError(f"unknown side-effect tool {action.tool}")
        att = Attempt(next(self._ids), action)
        self.log.attempts.append(att)
        return att

    def commit(self, att: Attempt) -> None:
        assert att.status == "pending"
        att.status = "committed"
        self.log.tool_calls.append((att.action.tool, dict(att.action.args)))
        self._world.execute(att.action)

    def block(self, att: Attempt, by: str, reason: str) -> None:
        assert att.status == "pending"
        att.status = "blocked"
        att.blocked_by = by
        att.reason = reason

    def abstain(self, tool: str, reason: str) -> None:
        """The defense declines to perform a permitted action (escalates to the user)."""
        self.log.abstentions.append((tool, reason))

    def note(self, msg: str) -> None:
        self.log.notes.append(msg)
