# 05 · Baselines: emulation choices and the equal-information contract

No LLM is available in this environment, so every baseline is a *scripted emulation* of
the published design's structure. Structural parts follow the paper and code closely.
Model-dependent parts are exposed as knobs (φ, ρ, ω, `p_fact_suggest`), and each is set
to the value most favorable to the baseline unless stated otherwise. The primary-source
notes these emulations are based on are summarized in `01_related_work.md`.

## Equal-information contract (requirement 6)

Every design receives the same inputs:

* the same `TaskSpec`: the correct planner's output for the user request, including which
  reference covers which fact and which trusted store holds which fact;
* the same read tools, trusted stores, reference services (confirm and lookup) and
  verification budget *k*, enforced by `Runtime`; every design's verification calls are
  counted against the same *k*;
* the same scripted reader (quarantined extraction), the same actor, and the same random
  draws per base instance.

Every design that verifies uses the same candidate order,
`defenses/base.py::verification_order` (document values that challenge the trusted store,
newest first, then the store value). So no design wins by a cleverer search.

No design sees ground truth, the variant label, or the world object
(`tests/test_isolation.py`).

## Configurations

"As evaluated" means the planner behaves as in the paper's AgentDojo evaluation: it
extracts the facts it needs from the documents the request points to, and never calls
the verifier. "Strong plan" means the planner uses the shared references as well as the
defense's *own* rules allow: lookups where the reference supports them, and the same
claim-verification plan EP uses. No new rule is added in either case.

| design | source | structural emulation | knobs / charitable choices |
|---|---|---|---|
| **No defense** | AgentDojo | ReAct actor sees documents, credulous about facts (newest claim), follows instructions with prob. φ | φ = 1 main; sweep 0.1–1 |
| **Tool filter** | AgentDojo §4.3 | tools restricted to the grant's tools before any data is read | ideal tool selection |
| **CaMeL (as evaluated)** | arXiv 2503.18813v2 + code `banking.py` | P-LLM plan from the request; Q-LLM extraction (newest value); authority arguments (target / item) must have trusted provenance; a denial halts the plan (blocked attempt + escalation) | readers checks **charitable** (non-sensitive data treated as public), which only raises CaMeL's utility; the user-approval oracle is not modeled |
| **CaMeL (strong plan)** | same | as above, plus lookups (the output is trusted when keyed by a trusted id) and verify-then-use for every fact; a confirmation keyed by an extracted value stays untrusted (`wrap_output` deps), so there is **no endorsement** | same budget and candidate order as EP |
| **Fides (as evaluated)** | arXiv 2505.23643v2 §4–6 | untrusted results hidden; `query_llm` per argument → U variable passed by reference; P-T checks the **context** label only; a condition on a U value needs expansion, which taints the context and makes P-T block | one planner turn per argument and per call (cost) |
| **Fides (strong plan)** | same | plus lookups (a lookup keyed by a trusted id is T); U verdicts cannot be used without tainting the context | – |
| **Fides (arg-level P-T)** | §4.3 / §6.1 stricter variant | critical arguments (target, item, quantity) must be T: lookup, or trusted store verified with trusted arguments | – |
| **AgentSentry** | arXiv 2602.22724v1 §3–4, App. B–C (no official code) | 4 dry-run regimes per untrusted boundary (K = 1) + Purify; IE = μ(mask) − μ(mask_san); takeover → purified context (directives and reader payloads removed, facts kept); **Auth gate is given the task's grant** | ideal detection (`p_fact_suggest` = 0; swept); Auth gets our authority check; purification keeps request-phrased facts |
| **AgentSentry + verify prompt** | strengthening (not in the paper) | the live agent is prompted to verify fact values against the shared references (EP's candidate order and *k*) | equal-information upgrade |

## Controls and ablations (not existing defenses)

| design | purpose |
|---|---|
| Deny-all | safety floor, utility floor |
| Verify-only guard | fact-checks every checkable argument, including inverted derived arguments, and blocks refuted calls; **no authority**. Isolates "verification ≠ authority". |
| Provenance-as-truth | EP's R1, but claims from authenticated senders are taken as true. Isolates "provenance ≠ truth". |
| Reference-only | never reads documents; lookup, or a verified trusted store. Isolates "are the documents needed?". |
| EP w/o endorsement | EP with confirmations of untrusted values not admitted. Isolates the endorsement rule. |
| CaMeL + endorsement | CaMeL policy extended with EP's rule R2 for authority arguments. **Transplant test.** |
| Fides (typed endorsement) | Fides' capacity escape hatch (§5.2, unused in their evaluation), with the bool taken from the shared verifier. **Transplant test.** |

## Known deviations

* **CaMeL.** P-LLM retries and redacted error channels are not modeled; the ideal
  planner never errs. Readers (confidentiality) checks are charitable, so CaMeL's
  published banking behavior (high policy-trigger rates) is *understated*.
* **Fides.** Labels are source-based (all third-party content is U). The paper's
  AgentDojo labeling used knowledge of where injections are placed, and this benchmark
  does not reproduce that.
* **AgentSentry.** The paper leaves Purify, Dev, Revise and Auth unspecified. Each is set
  to its most favorable plausible behavior. The Auth gate is handed the task's grant,
  which gives AgentSentry EP's R1 for free.
* **Cost.** LLM-call counts follow each architecture:
  * CaMeL and EP: one planner call plus one reader call per document;
  * Fides: planner turns per argument and per call, plus one `query_llm` per document;
  * AgentSentry: four replays plus one purify call per untrusted boundary, plus one
    revise call on takeover.

  Token counts are rough estimates (chars/4) with shared constants.
