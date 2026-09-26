# 08 · GO / NO_GO

## Verdict

**NO_GO for the defense-mechanism claim.** EP ("evidence-preserving": claim →
independent verification → allowed argument, with authority only from the user's grant)
does **not** improve the security–utility trade-off over the strongest existing defenses
at the same information and cost. The NO_GO rule (`06_metrics.md`) decides this in
three ways. The rule is the pre-registered one plus one flag added after the audit
("cost (1 planner)", FID-3); where that flag matters, it is said below.

1. **No clear gain over the strongest baseline.** Against CaMeL's strongest legal plan,
   the utility gain is not significant at the pre-registered budget: +2.5 pp
   [+0.0, +7.7] at k = 2. At k = 4 it is borderline: +9.3 pp [+0.0, +18.1], with the
   lower bound above 0 for 92 of 200 bootstrap seeds, because only 3 of 9 tasks differ.
   Either way it needs more verification (+0.13 calls per case), so it would be flagged
   for cost. There is no CUA difference. Against CaMeL with TARGET-only authority the
   outcomes are identical at k = 2.
2. **Every significant gain but one is flagged.**
   * Gains over plan-first baselines come with more verification calls: Fides strong
     plan and Fides argument-level P-T (at k = 4, flagged only by the post-audit
     1-planner accounting), and CaMeL with faithful readers.
   * Gains over AgentSentry, the firewall, the origin guard and the tool filter come with
     more safe failures.
   * The gain over allowlist + judge at k = 4 comes with more calls.

   The exception is AgentSentry with the strict reading of its Auth gate (§1).
3. **The gain is one transplantable rule.** Dropping EP's endorsement rule into CaMeL,
   Fides, AgentSentry or the firewall reproduces EP's outcome in **all 486 cases, at both
   budgets** (at ω = 0). Three of these transplants match partly by construction (§3).

**What can stand, conditionally,** is a *measurement* contribution: the paired A/B/C(+D)
benchmark with an equal-information reference contract, separate reporting, and
transplant tests. That is a GO only if it survives the conditions in §4.

## 1. The NO_GO rule, applied (results §4)

A plain "improves" requires a CI that excludes 0 in EP's favor, no worse mean on the
other axis, and no refusal or cost flag. Verdicts against every strong existing defense:

| X (same references, tools, *k*) | k = 2 | k = 4 | transplant into X's framework: cases that differ from EP |
|---|---|---|---|
| CaMeL (strong plan) | no improvement | no improvement (borderline; would be cost-flagged) | 0 |
| CaMeL (strong plan), faithful readers | no improvement | improves, but cost (NO_GO) | – |
| CaMeL (strong plan), TARGET-only authority | no improvement (0 cases differ) | no improvement | 0 |
| Fides (strong plan) | no improvement | improves, but cost (1 planner) (NO_GO) | 0 |
| Fides (arg-level P-T) | no improvement | improves, but cost (1 planner) (NO_GO) | 0 |
| AgentSentry | improves, but refusal (NO_GO) | improves, but refusal (NO_GO) | 0 |
| AgentSentry (strict Auth) | **improves** | **improves** | 0 |
| Firewall (sanitizer+minimizer) | improves, but refusal (NO_GO) | improves, but refusal (NO_GO) | 0 |
| Origin guard (ROPE-style) | improves, but refusal + cost + cost (1 planner) (NO_GO) | improves, but refusal + cost + cost (1 planner) (NO_GO) | – |
| Allowlist + judge (q=0.5) | improves, but refusal + cost (NO_GO) | improves, but cost (NO_GO) | – |
| Tool filter | improves, but refusal + cost (NO_GO) | improves, but refusal + cost (NO_GO) | – |

The only unflagged "improves" is against AgentSentry with the strict reading of its
unspecified Auth gate. EP beats it with fewer safe failures and lower total cost at both
budgets. That configuration has 26.5% utility and 61% safe failure on clean + C, so it is
not one of the strongest baselines. Its transplant counterpart (AgentSentry + verify
prompt) matches EP case for case.

Under the pre-registered accounting alone (charged cost, without the 1-planner flag),
EP would "improve" on Fides (strong plan) and Fides (arg-level P-T) at k = 4, because
Fides is charged more planner turns. k = 4 is not the pre-registered budget, and at
k = 2 neither gain is significant. The verdict is NO_GO either way, through CaMeL and
through the transplants.

## 2. The user's NO_GO criteria, checked one by one

| criterion | finding | consequence |
|---|---|---|
| **Gain from deny-all?** | No, directly: EP completes 100% of clean tasks, and Deny-all is a row in every table. Partly, relative to reactive baselines: EP fails safe more often than AgentSentry, the firewall, the origin guard and the tool filter on clean + C (+13.4 pp against AgentSentry at k = 4). Those gains are flagged "refusal". Relative to CaMeL (strong), EP fails safe less often at both budgets. Relative to Fides (strong), it fails safe more often at k = 2 (34% vs 18%, +15.9 pp) and less often at k = 4 (−3.7 pp). | NO_GO against the reactive baselines (refusal). |
| **Gain from an extra oracle?** | No oracle is given to EP alone: every design has the same references, tools, *k* and reader, and none gets user approvals. The large gains over the *as-published* CaMeL (+58 pp) and Fides (+56 pp) are gains from using the reference those designs never call. They are therefore not claimed; the comparison that counts is against the strong plans, which do call the reference. | The claimed comparison is information-matched. The as-published gaps are not claimed. |
| **Gain from more cost?** | Every significant gain over a plan-first baseline needs more verification: +0.13 to +0.31 calls per case at k = 4. Under "1 planner" accounting none is cost-neutral. EP's LLM trace equals CaMeL's by construction and is lower than Fides' as charged; that lower charge is a modeling label, and it is why the 1-planner flag was added after the audit. | NO_GO against CaMeL (faithful readers); against Fides (strong, arg) at k = 4 through the post-audit flag. |
| **Improvement over strong existing defenses at equal information and cost?** | Against CaMeL (strong plan): not significant at k = 2, borderline and cost-flagged at k = 4. Against Fides (strong plan): not significant at k = 2; significant at k = 4 only with more verification. | Not established. |
| **IFC, taint tracking or replay claimed as new?** | No. `01_related_work.md` §3 and `01b_prior_art_sweep.md` credit plan-first control flow, IFC and endorsement, replay, origin enforcement, approved-change classes, evidence-grounded arguments, and bank verify-before-pay. | – |
| **Hash or provenance used as truth?** | No. The monitor admits only a CONFIRMED record from the configured reference for the exact value. The Provenance-as-truth ablation shows what would happen otherwise: 47.7% CUA. | – |
| **Sandbox only?** | Yes: in-memory world, synthetic identifiers, no network in the main path. | – |

## 3. Why the defense claim fails (mechanistically)

* **Where designs differ.** With a lookup-capable reference, every plan-first design
  fetches the current value by the trusted id, and all of them agree. The designs differ
  only when the reference is confirm-only, so the new value must come from a document
  and be *endorsed* (results §3).
* **What EP adds in that cell.** Endorsement of a reference-confirmed document value.
  CaMeL's policy language can express it and Fides has a typed escape hatch for it. An
  agent that follows a verify prompt perfectly would also do it; that is modeled with
  EP's resolver, immune to φ, not as a real prompt.
* **How much the transplants prove.** All transplants resolve facts with EP's resolver,
  so their match with EP is partly by construction. What they test is that each
  framework's own policy layer *admits* the endorsed value. Whether a real prompted agent
  follows the rule is untested.
* **What the audit added.** The audit made EP verify the user's own record too (strict
  R2), which is a scope choice for the same rule. Under verification omission it matters
  (results §9). Every transplant then diverges from EP: CaMeL + endorsement (all fact
  args) has 1–3% CUA against EP's 0%, because its policy still trusts an unverified store
  value. EP's 0% is bought with more safe failures (66% vs 58% at ω = 0.5). We expect a
  CaMeL policy that also requires evidence for store values to behave like EP; **this was
  not run**.
* **What is left.** A rule ("bind a FACT value only if the configured independent
  reference confirms that exact value for the grant's entity, including values from the
  user's own store; otherwise escalate") that is prior art in pieces: IFC endorsement,
  Fides §5.2, CoP/VoP practice, ROPE, ARGUS, EBTE. Its combination, in this setting,
  yields no measurable gain over the strongest baselines equipped with the same
  reference.

## 4. What remains, and under which conditions (a conditional GO for measurement only)

The benchmark and protocol contribute four things no single prior work combines:

* paired A/B/C(+D) cases on one action surface;
* the same independent reference given to every design under one budget (confirm-only
  for 4 of 9 tasks, lookup-capable for 5);
* committed vs blocked vs escalated vs evidence vs cost, reported separately;
* transplant tests that attribute a difference to a rule rather than a framework.

It shows three things that are useful to know:

* **Without evidence, B and C cannot be separated.** Raising the allowlist judge's
  accept rate q from 0 to 1 raises C utility from 36% to 52% only by raising B CUA from
  62% to 100% (results §12).
* **Replay and detection defenses do not help against false facts.** AgentSentry and the
  firewall have 0% utility and 100% CUA on family B.
* **Verify-first designs inherit their reference's failures.** Every one of them fails
  worse than an undefended agent when the reference is stale (87–97% vs 47% CUA). When
  the reference is poisoned, EP is no better than no defense (both 100% CUA), and CaMeL
  strong, Fides and Reference-only commit 50–83% (results §14).

This GO is conditional on three points:

1. **LLM-in-the-loop replication.** The instruction/fact separation is annotated, not
   inferred (audit F5 / BV-5). Real readers, planners, actors and detectors must be run
   before any number is published. `scripts/run_llm_reader.py` covers the reader role
   only and has not been run.
2. **Novelty against the closest benchmarks.** NetInjectBench (approved-change class,
   overblock metric), EnvTrustBench (false environment claims with a verification route)
   and Influence Is Not Authority (paired legitimate/unauthorized values) each cover
   part of this design. The contribution must be positioned as their *combination* with
   IFC/replay baselines under an equal-reference contract.
3. **Task coverage.** The EP − CaMeL (strong plan) differences sit in one cell
   (authority × confirm-only: 3 of 9 tasks). Against Fides they also appear in
   data × confirm-only (pay_rent). All differences among the strong plan-first designs
   are in the two confirm-only cells (4 of 9 tasks). No task has an authority fact with
   a lookup reference. Scoped delegation (family D) and legitimate authority changes are
   not solved.

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

Outside these assumptions it offers nothing. It is worse than no defense when a
reference is stale (97% vs 47% CUA), and no better than no defense when a reference is
poisoned (100% CUA for both). For name-match references (real
CoP/VoP), V1's uniqueness fails. The guarantee then weakens to "registered under the
user-authorized name", and a stale record combined with a same-name mule would be
committed.

## 6. What would have changed the verdict

The first criterion is the prior-art critic's decision rule (`01b_prior_art_sweep.md`),
fixed before the experiments. Any of the following would have supported a GO on the
defense claim:

* a case family where EP beats CaMeL and Fides equipped with the same verifier, at equal
  budget, with a CI that excludes 0 and no refusal or cost flag;
* a transplant that could not reproduce EP's outcomes;
* an LLM-in-the-loop run in which EP's structure buys robustness the transplants lack.

None was found at ω = 0. Under verification omission (results §9) every transplant
diverges from EP. EP's lower CUA there is bought with more safe failures and lower
utility, so it gives no unflagged improvement. The third criterion has not been tested.
