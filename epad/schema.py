"""Core schema: Policy, Fact (claims), Evidence, Authority.

The four concepts are kept in separate types so that no value can silently
change category:

* Authority  -- what the *user* permitted: which side-effecting tools may be
  called, how often, and, per argument, where the value is allowed to come
  from (``ArgSlot``).  Only the trusted planner builds an ``AuthorityGrant``,
  and only from the user's request. Nothing produced from untrusted content has
  a code path into an ``AuthorityGrant`` (see ``epad/defenses/ep.py``).
* Policy     -- static, deployment-wide rules (limits, allowed domains,
  sensitive data classes). Trusted configuration, independent of any task.
* Fact       -- a ``Claim`` that some entity has some attribute value. Claims
  come from untrusted documents (via a quarantined reader) or from trusted but
  possibly stale user stores. A claim carries *no* authority: it can at most
  fill a FACT slot of an action that the grant already permits.
* Evidence   -- the record of an *independent* verification of a claim against
  a reference service (``Evidence``). Provenance (authenticated sender) and
  content hashes are kept as metadata but are never accepted as evidence of
  truth.

Directives (imperative content that asks for an action) are preserved as
``Directive`` records for audit, but have no field that could be executed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional

FactKey = tuple[str, str]  # (entity id, attribute)


class Trust(str, Enum):
    TRUSTED = "trusted"      # user request, user-owned stores, system policy
    UNTRUSTED = "untrusted"  # third-party content (email bodies, web pages, shared files)
    REFERENCE = "reference"  # independent reference service (trusted only under assumptions V1-V3)


class SlotKind(str, Enum):
    USER_FIXED = "user_fixed"  # value fixed by the user's request itself
    FACT = "fact"              # value is (a function of) a fact about a user-authorized entity
    FREE = "free"              # low-risk value, constrained by type/length/pattern


class SlotRole(str, Enum):
    """What an argument does at the sink. Used by provenance-based baselines
    (e.g. CaMeL-style policies restrict *targets*, not content)."""
    TARGET = "target"      # recipient / destination / counterparty account
    CONTENT = "content"    # data carried to the target
    QUANTITY = "quantity"  # amount, quantity, price
    TIME = "time"          # time / schedule
    ITEM = "item"          # item identifier (sku, part number)


class VerifyRule(str, Enum):
    ALWAYS = "always"                                   # bind only reference-confirmed values
    IF_UNTRUSTED_OR_CONFLICT = "if_untrusted_or_conflict"  # trusted-store value may bind unverified if uncontested


class Verdict(str, Enum):
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    UNKNOWN = "unknown"  # reference does not cover this key


@dataclass(frozen=True)
class ArgSlot:
    name: str
    kind: SlotKind
    role: SlotRole
    value: Any = None                   # USER_FIXED: the value
    fact: Optional[FactKey] = None      # FACT: which fact this slot is bound to (entity fixed by authority)
    transform: Optional[str] = None     # FACT: name of a deterministic transform (see epad.transforms)
    verify: VerifyRule = VerifyRule.ALWAYS
    free_pattern: Optional[str] = None  # FREE: regex the value must match
    free_max_len: int = 64


@dataclass(frozen=True)
class Condition:
    """Fact-dependent guard on an action, e.g. ``price <= 40``.

    The fact is a *fact*, so it must be established by evidence under the same
    rules as a FACT slot before the condition may be evaluated."""
    fact: FactKey
    op: str          # one of "<=", ">=", "==", "!="
    operand: Any


@dataclass(frozen=True)
class ActionTemplate:
    tool: str
    slots: tuple[ArgSlot, ...]
    condition: Optional[Condition] = None
    max_calls: int = 1

    def slot(self, name: str) -> ArgSlot:
        for s in self.slots:
            if s.name == name:
                return s
        raise KeyError(name)


@dataclass(frozen=True)
class AuthorityGrant:
    """Execution authority derived from the user's request only."""
    task_id: str
    templates: tuple[ActionTemplate, ...]
    principal: str = "user"

    def fact_keys(self) -> list[FactKey]:
        keys: list[FactKey] = []
        for t in self.templates:
            for s in t.slots:
                if s.kind == SlotKind.FACT and s.fact not in keys:
                    keys.append(s.fact)
            if t.condition and t.condition.fact not in keys:
                keys.append(t.condition.fact)
        return keys

    def tools(self) -> set[str]:
        return {t.tool for t in self.templates}


@dataclass(frozen=True)
class Policy:
    """Static deployment policy (trusted configuration)."""
    max_payment: float = 10_000.0
    internal_domains: tuple[str, ...] = ("corp.example",)
    sensitive_markers: tuple[str, ...] = ("PASSPORT", "SSN", "PASSWORD", "API_KEY")


@dataclass(frozen=True)
class Claim:
    claim_id: str
    key: FactKey
    value: Any
    source: str             # doc id or store name
    source_trust: Trust
    authenticated: bool     # provenance metadata (e.g. DKIM pass); NOT evidence of truth
    timestamp: int
    phrasing: str = "declarative"  # or "imperative"
    extracted_by: str = "reader"


@dataclass(frozen=True)
class Directive:
    """Imperative content found in untrusted data. Preserved for audit only."""
    directive_id: str
    source: str
    text: str
    requested_tool: Optional[str] = None


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    reference: str
    key: FactKey
    value: Any
    verdict: Verdict
    mode: str                 # "confirm" or "lookup"
    claim_id: Optional[str] = None


@dataclass(frozen=True)
class BoundArg:
    slot: str
    value: Any
    basis: str                      # "user" | "evidence" | "trusted_store" | "free" | "untrusted" | "reference_lookup"
    evidence_ids: tuple[str, ...] = ()
    claim_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class ActionRequest:
    tool: str
    args: Mapping[str, Any]
    origin: str                          # component that proposed it (e.g. "plan", "directive:<id>")
    justification: tuple[BoundArg, ...] = field(default_factory=tuple)

    def key(self) -> tuple:
        return (self.tool, tuple(sorted((k, _norm(v)) for k, v in self.args.items())))


def _norm(v: Any) -> Any:
    if isinstance(v, float):
        return round(v, 2)
    return v
