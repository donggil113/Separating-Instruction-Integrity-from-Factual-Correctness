"""All defenses evaluated, in report order, and their roles in the pre-registered comparisons."""
from __future__ import annotations

from dataclasses import replace

from epad.defenses.agentsentry import AgentSentry
from epad.defenses.base import EP_POLICY, Defense
from epad.defenses.ep import EvidencePreserving, ep_pre_audit
from epad.defenses.extra import AllowlistJudge, Firewall, OriginGuard
from epad.defenses.planfirst import CaMeL, Fides, ProvenanceTrust, ReferenceOnly
from epad.defenses.reactive import DenyAll, NoDefense, ToolFilter, VerifyGuard
from epad.schema import SlotRole


def all_defenses() -> list[Defense]:
    return [
        # reference points
        NoDefense(), DenyAll(),
        # existing defenses as evaluated in their papers
        CaMeL("as_evaluated"), Fides("as_evaluated", planner="as_evaluated"),
        # existing defenses, strongest plan their own rules allow with the shared references and budget
        ToolFilter(),
        CaMeL("strong"), CaMeL("strong", readers="faithful"),
        CaMeL("strong", authority_roles=frozenset({SlotRole.TARGET})),
        Fides("as_evaluated", planner="strong"), Fides("arg"),
        AgentSentry(), AgentSentry(auth="strict"),
        Firewall(), OriginGuard(), AllowlistJudge(0.5),
        # transplants: an existing framework + EP's endorsement rule and resolver
        CaMeL("strong", endorse="authority"), CaMeL("strong", endorse="all"), Fides("typed"),
        AgentSentry(verify_facts=True), Firewall(verify_facts=True),
        # ablations / controls
        VerifyGuard(), ProvenanceTrust(), ReferenceOnly(),
        EvidencePreserving(replace(EP_POLICY, endorse=False), name="EP w/o endorsement"),
        EvidencePreserving(replace(EP_POLICY, require_unique=True), name="EP (unique confirmation)"),
        ep_pre_audit(),
        # ours
        EvidencePreserving(),
    ]


AS_PUBLISHED = ["CaMeL (as evaluated)", "Fides (as evaluated)"]
# existing policies/detectors given the same references, tools and budget; the planner uses them as well as
# the defense's own rules allow (no rule from EP added)
STRONG_EXISTING = ["CaMeL (strong plan)", "CaMeL (strong plan), faithful readers",
                   "CaMeL (strong plan), TARGET-only authority", "Fides (strong plan)", "Fides (arg-level P-T)",
                   "AgentSentry", "AgentSentry (strict Auth)", "Firewall (sanitizer+minimizer)",
                   "Origin guard (ROPE-style)", "Allowlist + judge (q=0.5)", "Tool filter"]
TRANSPLANTS = ["CaMeL + endorsement (authority args)", "CaMeL + endorsement (all fact args)",
               "Fides shell + EP resolver (typed hatch)", "AgentSentry + verify prompt", "Firewall + verify prompt"]
OURS = "EP (ours)"
