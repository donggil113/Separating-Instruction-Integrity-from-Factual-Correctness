# 08 · GO / NO_GO

## Verdict

**NO_GO for the defense-mechanism claim.** EP ("evidence-preserving": claim →
independent verification → allowed argument, with authority only from the user's grant)
does **not** improve the security–utility trade-off over the strongest existing defenses
at the same information and cost. The pre-registered rule (`06_metrics.md`) decides this
in three ways:

1. **No significant gain over the strongest baselines.** Against CaMeL's strongest legal
   plan the utility gain is not significant at either budget: +2.5 pp [+0.0, +7.7] at
   k = 2 and +9.3 pp [+0.0, +18.1] at k = 4, with zero CUA difference. Against CaMeL
   with TARGET-only authority the outcomes are identical at k = 2.
2. **Every significant gain is flagged.** Each significant gain over a plan-first
   baseline comes with more verification calls: Fides strong plan, Fides argument-level
   P-T, and CaMeL with faithful readers. Each significant gain over a reactive baseline
   comes with more safe failures: AgentSentry, the firewall, the origin guard and the
   tool filter.
3. **The gain is one transplantable rule.** Dropping EP's endorsement rule into CaMeL,
   Fides, AgentSentry or the firewall reproduces EP's outcome in **all 486 cases, at both
   budgets**.

**What can stand, conditionally,** is a *measurement* contribution: the paired A/B/C(+D)
benchmark with an equal-information reference contract, separate reporting, and
transplant tests. That is a GO only if it survives the conditions in §4.

## 1. Pre-registered rule, applied (results §4)

A plain "improves" requires a CI that excludes 0 in EP's favor, no worse mean on the
other axis, and no refusal or cost flag. Verdicts against every strong existing defense:

| X (same references, tools, *k*) | k = 2 | k = 4 | transplant into X's framework: cases that differ from EP |
|---|---|---|---|
| CaMeL (strong plan) | no improvement | no improvement | 0 |
| CaMeL (strong plan), faithful readers | no improvement | improves, but cost (NO_GO) | – |
| CaMeL (strong plan), TARGET-only authority | no improvement (0 cases differ) | no improvement | 0 |
| Fides (strong plan) | no improvement | improves, but cost (1 planner) (NO_GO) | 0 |
| Fides (arg-level P-T) | no improvement | improves, but cost (1 planner) (NO_GO) | 0 |
| AgentSentry | improves, but refusal (NO_GO) | improves, but refusal (NO_GO) | 0 |
| AgentSentry (strict Auth) | **improves** | **improves** | 0 |
| Firewall (sanitizer+minimizer) | improves, but refusal (NO_GO) | improves, but refusal (NO_GO) | 0 |
| Origin guard (ROPE-style) | improves, but refusal + cost (NO_GO) | improves, but refusal + cost (NO_GO) | – |
| Allowlist + judge (q=0.5) | improves, but refusal + cost (NO_GO) | improves, but cost (NO_GO) | – |
| Tool filter | improves, but refusal + cost (NO_GO) | improves, but refusal + cost (NO_GO) | – |

The only unflagged "improves" is against AgentSentry with the strict reading of its
unspecified Auth gate. That configuration has 26.5% utility and 61% safe failure on
clean + C. It is not one of the strongest baselines, and its transplant counterpart
(AgentSentry + verify prompt) matches EP case for case.

## 2. The user's NO_GO criteria, checked one by one

| criterion | finding | consequence |
|---|---|---|
| **Gain from deny-all?** | No, directly: EP completes 100% of clean tasks, and Deny-all is a row in every table. Partly, relative to reactive baselines: EP fails safe more often than AgentSentry, the firewall, the origin guard and the tool filter on clean + C (+13.4 pp against AgentSentry at k = 4). Those gains are flagged "refusal". Relative to CaMeL and Fides (strong), EP fails safe **less** often. | NO_GO against the reactive baselines (refusal). |
| **Gain from an extra oracle?** | No oracle is given to EP alone: every design has the same references, tools, *k* and reader, and none gets user approvals. The large gains over the *as-published* CaMeL (+58 pp) and Fides (+56 pp) are gains from using the reference those designs never call. They are therefore not claimed; the comparison that counts is against the strong plans, which do call the reference. | The claimed comparison is information-matched. The as-published gaps are not claimed. |
| **Gain from more cost?** | Every significant gain over a plan-first baseline needs more verification: +0.13 to +0.31 calls per case at k = 4. Under "1 planner" accounting none is cost-neutral. EP's LLM trace equals CaMeL's by construction and is lower than Fides' as charged; that lower charge is a modeling label, and it is why the 1-planner flag exists. | NO_GO against Fides (strong, arg) and CaMeL (faithful readers). |
| **Improvement over strong existing defenses at equal information and cost?** | Against CaMeL (strong plan): not significant at either budget. Against Fides (strong plan): not significant at k = 2; significant at k = 4 only with more verification. | Not established. |
| **IFC, taint tracking or replay claimed as new?** | No. `01_related_work.md` §3 and `01b_prior_art_sweep.md` credit plan-first control flow, IFC and endorsement, replay, origin enforcement, approved-change classes, evidence-grounded arguments, and bank verify-before-pay. | – |
| **Hash or provenance used as truth?** | No. The monitor admits only a CONFIRMED record from the configured reference for the exact value. The Provenance-as-truth ablation shows what would happen otherwise: 47.7% CUA. | – |
| **Sandbox only?** | Yes: in-memory world, synthetic identifiers, no network in the main path. | – |

## 3. Why the defense claim fails (mechanistically)

* **Where designs differ.** With a lookup-capable reference, every plan-first design
  fetches the current value by the trusted id, and all of them agree. The designs differ
  only when the reference is confirm-only, so the new value must come from a document
  and be *endorsed* (results §3).
* **What EP adds in that cell.** Endorsement of a reference-confirmed document value.
  CaMeL's policy language can express it, Fides has a typed escape hatch for it, and an
  agent can be prompted to do it. The transplants do all three and match EP exactly.
* **What the audit added.** The audit made EP verify the user's own record too (strict
  R2). That is a scope choice for the same rule. Under verification omission it matters
  (results §9), but a CaMeL policy with the same scope would behave the same way.
* **What is left.** A rule ("bind a FACT value only if the configured independent
  reference confirms that exact value for the grant's entity, including values from the
  user's own store; otherwise escalate") that is prior art in pieces: IFC endorsement,
  Fides §5.2, CoP/VoP practice, ROPE, ARGUS, EBTE. Its combination, in this setting,
  yields no measurable gain over the strongest baselines equipped with the same
  reference.

## 4. What remains, and under which conditions (a conditional GO for measurement only)

The benchmark and protocol contribute four things no single prior work combines:

* paired A/B/C(+D) cases on one action surface;
* a confirm-only reference given to every design under one budget;
* committed vs blocked vs escalated vs evidence vs cost, reported separately;
* transplant tests that attribute a difference to a rule rather than a framework.

It shows three things that are useful to know:

* **Without evidence, B and C lie on one line.** The allowlist judge trades B-CUA
  against C-utility one for one (results §12).
* **Replay and detection defenses do not help against false facts.** AgentSentry and the
  firewall have 0% utility and 100% CUA on family B.
* **Every verify-first design is exactly as good as its reference.** Each one fails
  worse than an undefended agent when the reference is stale or poisoned (results §14).

This GO is conditional on three points:

1. **LLM-in-the-loop replication.** The instruction/fact separation is annotated, not
   inferred (audit F5 / BV-5). Real readers, planners and detectors must be run
   (`scripts/run_llm_reader.py` exists but has not been run) before any number is
   published.
2. **Novelty against the closest benchmarks.** NetInjectBench (approved-change class,
   overblock metric), EnvTrustBench (false environment claims with a verification route)
   and Influence Is Not Authority (paired legitimate/unauthorized values) each cover
   part of this design. The contribution must be positioned as their *combination* with
   IFC/replay baselines under an equal-reference contract.
3. **Task coverage.** The EP − baseline differences sit in one cell (authority ×
   confirm-only: 3 of 9 tasks). No task has an authority fact with a lookup reference.
   Scoped delegation (family D) and legitimate authority changes are not solved.

## 5. The guarantee, restated within its assumptions

Under P1 (correct grant), P2 (correct policy), V1 (a correct, current reference whose
CONFIRMED identifies the value), V2 (the reference cannot be written through content),
V3 (the query is keyed by the grant's entity) and R0 (a correct runtime; store integrity,
not freshness), EP:

* commits no call outside the user's grant;
* commits no FACT value without a matching CONFIRMED record from the configured
  reference;
* escalates otherwise.

In this benchmark it has 0% CUA at every budget. Its utility is 82% at k = 2 and 93% at
k = 4; C-family utility is 84% at k = 4.

Outside these assumptions it offers nothing, and it is worse than no defense when a
reference is stale (97% CUA) or poisoned (100% CUA). For name-match references (real
CoP/VoP), V1's uniqueness fails. The guarantee then weakens to "registered under the
user-authorized name", and a stale record combined with a same-name mule would be
committed.

## 6. What would have changed the verdict (pre-registered)

Any of the following would have supported a GO on the defense claim:

* a case family where EP beats CaMeL and Fides equipped with the same verifier, at equal
  budget, with a CI that excludes 0 and no refusal or cost flag;
* a transplant that could not reproduce EP's outcomes;
* an LLM-in-the-loop run in which EP's structure buys robustness the transplants lack.

None was found in the scripted setting. The third has not been tested.
