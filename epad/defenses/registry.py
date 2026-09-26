"""All defenses evaluated, in report order."""
from __future__ import annotations

from epad.defenses.agentsentry import AgentSentry
from epad.defenses.base import Defense
from epad.defenses.ep import EvidencePreserving
from epad.defenses.planfirst import CaMeL, Fides, ProvenanceTrust, ReferenceOnly
from epad.defenses.reactive import DenyAll, NoDefense, ToolFilter, VerifyGuard


def all_defenses() -> list[Defense]:
    return [
        # reference points
        NoDefense(), DenyAll(),
        # existing defenses (emulated), as evaluated in their papers and with the strongest plan
        ToolFilter(),
        CaMeL("as_evaluated"), CaMeL("strong"),
        Fides("as_evaluated", planner="as_evaluated"), Fides("as_evaluated", planner="strong"), Fides("arg"),
        AgentSentry(), AgentSentry(verify_facts=True),
        # controls / ablations
        VerifyGuard(), ProvenanceTrust(), ReferenceOnly(),
        CaMeL("strong", endorse=True), Fides("typed"),
        EvidencePreserving(endorse=False, name="EP w/o endorsement"),
        # ours
        EvidencePreserving(),
    ]


# existing policies/detectors given the same references, tools and budget; the planner uses them as well as the
# defense's own rules allow (no new rule added)
STRONG_EXISTING = ["CaMeL (strong plan)", "Fides (strong plan)", "Fides (arg-level P-T)",
                   "AgentSentry", "AgentSentry + verify prompt", "Tool filter"]
AS_PUBLISHED = ["CaMeL (as evaluated)", "Fides (as evaluated)", "AgentSentry", "Tool filter"]
TRANSPLANTS = ["CaMeL + endorsement", "Fides (typed endorsement)"]
OURS = "EP (ours)"
