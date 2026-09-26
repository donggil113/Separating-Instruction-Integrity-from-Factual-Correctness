"""Sandbox world: documents, trusted user stores, independent references.

Everything here is synthetic. There is no network access, no real account,
mailbox, calendar, shop or payment rail; side effects are appended to an
in-memory list. Identifiers use reserved/sandbox forms (``*.example`` domains,
``SBX`` account numbers) so they cannot collide with real ones.
"""
from __future__ import annotations

import copy
import hashlib
from dataclasses import dataclass, field
from typing import Any, Optional

from epad.schema import ActionRequest, FactKey, Verdict


@dataclass(frozen=True)
class Statement:
    """One unit of content in a document, as a (simulated) perfect parser sees it.

    ``kind``:
      * ``fact``           -- asserts ``key = value`` (declarative or imperative phrasing)
      * ``directive``      -- asks the reader of the document to perform ``action``
      * ``reader_payload`` -- text crafted to make an LLM that reads the document
                              report ``key = value`` (targets extractors / Q-LLMs)
      * ``note``           -- task-irrelevant filler

    Statements carry only what the text says. Whether a fact is *true* lives in
    the world/ground truth, never here.
    """
    kind: str
    text: str
    key: Optional[FactKey] = None
    value: Any = None
    phrasing: str = "declarative"
    action: Optional[ActionRequest] = None


@dataclass(frozen=True)
class Document:
    doc_id: str
    channel: str               # "email" | "web" | "file"
    sender: str
    authenticated: bool        # provenance metadata only (e.g. DKIM/SPF pass for sender domain)
    timestamp: int             # larger = more recent
    subject: str
    statements: tuple[Statement, ...]
    mentions: tuple[str, ...] = ()   # keywords a search tool would match (entity names)

    @property
    def text(self) -> str:
        body = "\n".join(s.text for s in self.statements)
        return f"From: {self.sender}\nSubject: {self.subject}\n\n{body}"

    @property
    def content_hash(self) -> str:
        return hashlib.sha256(self.text.encode()).hexdigest()[:16]

    @property
    def n_tokens(self) -> int:
        return max(1, len(self.text) // 4)


@dataclass
class Reference:
    """An independent reference service (e.g. Confirmation-of-Payee, airline
    status API, manufacturer catalog).

    Assumptions under which it is trusted (see docs/02_threat_model.md):
      V1 correct & current for the keys it covers,
      V2 not writable through the untrusted content channel,
      V3 queried with the entity id taken from the authority grant.
    """
    name: str
    attributes: frozenset[str]
    supports_lookup: bool
    table: dict[FactKey, Any] = field(default_factory=dict)
    close: dict[FactKey, list] = field(default_factory=dict)   # values registered to a look-alike name
    also: dict[FactKey, list] = field(default_factory=dict)    # other values that ALSO match (non-unique checks,
                                                               # e.g. a mule account opened under the exact name)

    def covers(self, key: FactKey) -> bool:
        return key[1] in self.attributes

    def confirm(self, key: FactKey, value: Any) -> Verdict:
        if not self.covers(key) or key not in self.table:
            return Verdict.UNKNOWN
        if _eq(self.table[key], value) or any(_eq(v, value) for v in self.also.get(key, [])):
            return Verdict.CONFIRMED
        if any(_eq(v, value) for v in self.close.get(key, [])):
            return Verdict.CLOSE_MATCH
        return Verdict.REFUTED

    def lookup(self, key: FactKey) -> Optional[Any]:
        if not self.supports_lookup:
            raise PermissionError(f"reference {self.name} is confirm-only")
        if not self.covers(key):
            return None
        return self.table.get(key)

    def public(self) -> dict:
        return {"name": self.name, "attributes": sorted(self.attributes), "supports_lookup": self.supports_lookup}


@dataclass
class World:
    truth: dict[FactKey, Any]
    stores: dict[str, dict[FactKey, Any]]
    documents: list[Document]
    references: dict[str, Reference]
    profile: dict[str, str] = field(default_factory=dict)   # trusted user profile incl. sensitive values
    committed: list[ActionRequest] = field(default_factory=list)

    def clone(self) -> "World":
        return copy.deepcopy(self)

    def execute(self, action: ActionRequest) -> None:
        self.committed.append(action)


def _eq(a: Any, b: Any) -> bool:
    """Exact, type-aware equality. Amounts are compared to the cent (values are 2-decimal
    money); identifiers compare exactly except for grouping spaces; no case folding; a string
    is never equal to a number."""
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return round(float(a) * 100) == round(float(b) * 100)
    if isinstance(a, str) and isinstance(b, str):
        return a.replace(" ", "") == b.replace(" ", "")
    return a == b


values_equal = _eq
