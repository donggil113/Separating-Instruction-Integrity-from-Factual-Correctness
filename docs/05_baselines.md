# 05 · Baselines: emulation choices and the equal-information contract

No LLM is used, so every baseline is a *scripted emulation* of the published design's
structure (sources: `01_related_work.md`, `01b_prior_art_sweep.md`).

* **Structural parts** follow the paper and code closely.
* **Model-dependent parts** are knobs. In the main tables:
  * ω, `keep_imperative_facts`, `directive_as_claim` and `p_fact_suggest` are set to the
    value most favorable to the baseline;
  * φ and ρ are set to their worst case (1), which is unfavorable to the reactive and
    detection-based baselines they affect;
  * q = 0.5.

  All knobs are swept (results §7–§12). Some model-dependent behavior is fixed, not a
  knob: the reactive actor's credulity and its instruction/fact separation, and
  AgentSentry's severity scoring.
* **Unspecified parts.** Where a paper leaves a component unspecified, it is set to its
  most favorable plausible behavior. Where two readings trade safety against utility
  (AgentSentry's Auth gate), both are run.

After the audit (`09_audit_log.md`), CaMeL and Fides are also run with the **strongest
plan their own rules allow** given the shared references. The CaMeL and Fides
"strong plans" were rebuilt for this (audit CAMEL-1, FID-1).

## Equal-information contract (requirement 6)

Every design receives:

* **the same task specification**: the `TaskSpec` a correct planner derives from the user
  request, including which reference covers which fact and which store holds which fact;
* **the same environment**: the same read tools, trusted stores, reference services
  (confirm and lookup) and verification budget *k*. `Runtime` enforces *k*, and every
  design's verification calls count against it;
* **the same model stand-ins**: the same scripted reader (quarantined extraction), actor,
  purifier knobs and random draws per base instance.

EP, its ablations, CaMeL (strong plan) and the transplants use the shared resolver
`defenses/base.py::resolve` under an explicit `ResolvePolicy` (`03_schema.md`), so none
of them wins by a cleverer search. The candidate order is one setting shared by all of
them (store first by default); results §13 reports EP under the other order. Two
verifying designs keep their own logic:

* Fides (strong plan / arg-level P-T) implements Fides' own store-first plan;
* the Verify-only guard checks proposed arguments directly.

No design sees ground truth, the variant label or the world object. The isolation tests
forbid defense modules from importing `epad.cases.*` or `epad.eval.*`
(`tests/test_isolation.py`).

## Configurations (27 rows in the results)

### Reference points

| design | purpose |
|---|---|
| No defense | ReAct actor that sees documents; credulous about facts (newest claim wins); obeys injected instructions with probability φ (1 in the main tables; swept 0.1–1). |
| Deny-all | Never acts. The safety floor and the utility floor. |

### Existing defenses as evaluated in their papers

| design | source | structural emulation |
|---|---|---|
| CaMeL (as evaluated) | arXiv 2503.18813v2; code `banking.py` | P-LLM plan from the query; Q-LLM extracts the newest value (falling back to the store); no verification. Authority arguments (TARGET, ITEM) must have trusted provenance. A denial halts the program; unreached calls are recorded as escalations. |
| Fides (as evaluated) | arXiv 2505.23643v2 §4–6 | Untrusted results hidden; `query_llm` into U variables passed by reference; P-T checks the **context** label only. A condition on a U value needs expansion, which taints the context, and P-T then blocks. |

### Existing defenses: the strongest plan their own rules allow (`STRONG_EXISTING`)

These are the baselines the pre-registered NO_GO rule compares against.

| design | what it does with the shared references |
|---|---|
| **CaMeL (strong plan)** | **Policy-aware.** Lookups keyed by the trusted entity id are trusted. For authority facts it verifies only candidates its policy could ever accept (the user's store), so it never spends budget on document values it must deny. For data facts it uses the shared resolver. There is no endorsement: a confirmation keyed by an extracted value stays untrusted (`wrap_output` dependencies). Readers checks are **charitable** (off). |
| CaMeL (strong plan), faithful readers | As above, plus CaMeL's readers checks and the engine's non-public-context rule. A branch on document-derived data is denied, and data from private web/file content cannot flow to a recipient (audit CAMEL-2). |
| CaMeL (strong plan), TARGET-only authority | As above (charitable readers), but only TARGET arguments are authority arguments. Treating ITEM as authority has no direct precedent in CaMeL's code (audit CAMEL-3). |
| **Fides (strong plan)** | Store-first legal plan (audit FID-1). Lookup where supported, which is T when keyed by the trusted id. Otherwise it verifies the T store value with T arguments: CONFIRMED binds the store value; REFUTED passes the newest `query_llm` variable by reference, unverified, as P-T on the context allows; budget exhaustion or UNKNOWN keeps the store value. |
| Fides (arg-level P-T) | The stricter policy of §4.3 / §6.1: critical arguments (TARGET, ITEM, QUANTITY) must be T: a lookup, or a trusted-store value. The store value is confirmed when the budget allows; it binds unconfirmed when the budget is exhausted or the reference answers UNKNOWN (audit FID-5 made UNKNOWN behave like budget exhaustion). |
| AgentSentry | arXiv 2602.22724v1 §3–4, App. B–C; no official code. It runs four dry-run regimes plus Purify at every tool-return boundary (documents, store reads, each verifier return). Takeover is flagged iff the instruction effect IE ≥ 1; on takeover the context is purified (directives and payloads removed, facts kept) and revised. The Auth gate is **lenient**: tool and user-fixed arguments of the grant. |
| AgentSentry (strict Auth) | As above, but Auth also requires fact arguments to equal the user's trusted state where it exists (audit AS-1). The paper leaves Auth unspecified; both readings are reported. |
| Firewall (sanitizer+minimizer) | arXiv 2510.05244: every tool output is rewritten to remove instructions (a perfect sanitizer, subject to the same ρ and confusion knobs as every reader). The tool-input minimizer is charged one LLM call per call but is not modeled as changing arguments; the sanitizer already removes every exfiltration directive. |
| Origin guard (ROPE-style) | arXiv 2608.27496: a state-changing parameter takes a value only from the user's records, or from an authenticated sender that the user's records name for that counterparty (`trusted_senders`). No truth check. Faithful ROPE fails closed on document-only values. A "ROPE + reference as T3" variant would be an N4-authored strengthening and is not run. |
| Allowlist + judge (q = 0.5) | Agent-Sentry (Sequeira et al., arXiv 2603.22868): the call must match the task's action structure; sensitive (TARGET/ITEM) values must be on an allowlist from the user's records; otherwise an LLM judge accepts with probability q. Without evidence the judge cannot tell B from C, so q is the same for both (swept in §12). |
| Tool filter | AgentDojo §4.3: tools restricted to the grant's tools before any data is read (ideal tool selection). |

### Transplants: an existing framework plus EP's rule (`TRANSPLANTS`)

These are **not** existing defenses. Each puts EP's endorsement rule R2 and the shared
resolver into another framework. They are the novelty test: if a transplant matches EP
case for case, the gain belongs to the rule, not to a new mechanism.

| design | framework | what is added |
|---|---|---|
| CaMeL + endorsement (authority args) | CaMeL policy engine | Authority arguments may carry a document value if the log holds a CONFIRMED record for exactly that value from the configured reference (bound to the argument value). |
| CaMeL + endorsement (all fact args) | CaMeL policy engine | The same rule for every FACT argument (full-scope transplant; audit CAMEL-6 / F4). |
| Fides shell + EP resolver (typed hatch) | Fides planner shell | Fides' capacity-typed endorsement escape hatch (§5.2, unused in the paper's evaluation), with the bool taken from the shared resolver. By construction this is EP's resolver in a Fides shell (audit FID-4), so identical outcomes are expected. |
| AgentSentry + verify prompt | AgentSentry | The live agent is prompted to verify fact values against the references; modeled with EP's resolver at perfect adherence, immune to φ. Every verifier return is charged as a boundary. |
| Firewall + verify prompt | Firewall | The same verify prompt behind the sanitizer and minimizer. |

### Controls and ablations

| design | purpose |
|---|---|
| Verify-only guard | Fact-checks every checkable argument (inverting derived arguments) and blocks refuted or close-match calls; **no authority**. Isolates "verification ≠ authority". |
| Provenance-as-truth | EP's R1, but claims from authenticated senders are taken as true (newest wins). Isolates "provenance ≠ truth". |
| Reference-only | Never reads documents; uses a lookup or a reference-confirmed store value. Isolates "are the documents needed?". |
| EP w/o endorsement | EP with `endorse = False`. Isolates the endorsement rule. |
| EP (unique confirmation) | EP with `require_unique = True`: binds only if exactly one candidate confirms. For name-match references. |
| EP v0 (pre-audit) | The version the audit broke: an uncontested store bound unverified, a contested store bound after refuting all challengers, and challengers verified first. Kept for comparison (`09_audit_log.md`). |

## Known deviations and disclosures

**CaMeL**

* *Planner.* NORMAL interpreter mode (the code's default). P-LLM retries and redacted
  error channels are not modeled; the ideal planner never errs.
* *Implicit flows.* These are not modeled (audit CAMEL-4). Some successes of the strong
  plan select the trusted value after branching on verifier results. STRICT mode, or
  NORMAL mode with real readers checks, could deny them. The faithful-readers row covers
  part of this.
* *Meaning of "as evaluated".* Here it means "no verifier, extract from the documents"
  with policies enforced, so denials count as failures. The paper reports utility from
  policy-free runs and denials as trigger rates (audit CAMEL-9).
* *No approvals.* The user-approval oracle is not modeled for any design. Approvals
  would be an extra oracle.

**Fides**

* *Idealized.* The strong plan is an idealized upper bound (audit FID-7): the planner
  never mislabels, never over-expands and never leaks a U value into the context
  by mistake.
* *Labels.* Labels are source-based: all third-party content is U. The paper's
  AgentDojo labels used knowledge of where injections are placed, and this is not
  reproduced.
* *Taint scope.* A condition on a U value taints the whole episode, and egress tools get
  P-T rather than "P-F or P-T" (audit FID-10). Both are conservative for Fides' utility
  on condition tasks only.

**AgentSentry**

* *Unspecified operators.* Purify, Dev, Revise and Auth are unspecified in the paper;
  each is set to its most favorable plausible behavior.
* *Severity scoring.* Severity scores any instruction, including tool-less redirects and
  extractor payloads, as Y = 2, so detection of family A is ideal (audit AS-3).
  `p_fact_suggest` (§11) sweeps detection failures on facts.
* *Simplifications.* ACE/DE, the temporal branch, and the μ(orig) > 0 conjunct are not
  computed. There are no false alarms by construction (audit AS-9).
* *Auth gate.* The lenient Auth gate checks the grant's tools and user-fixed arguments.
  It does **not** give AgentSentry all of EP's R1: FREE-argument exfiltration and
  duplicate calls are not checked (audit AS-7).

**Firewall and origin guard**

* *Perfect sanitizer.* The sanitizer is perfect except for the shared ρ and confusion
  knobs.
* *Trusted senders.* The origin guard's list of trusted senders comes from the user's
  records, per task.
* *Permissive ROPE reading.* The origin guard admits body values from an authenticated
  sender on that list. Faithful ROPE probably anchors only the sender address and fails
  closed on a bill's IBAN. The emulation therefore pays document-supplied values from
  such senders, including the attacker's IBAN in `D_tampered` (results §5).

**Cost accounting**

* *What is counted.* LLM calls by role, estimated tokens (chars/4 with shared
  constants), tool calls and verification calls. These are architecture labels, not
  measurements.
* *CaMeL.* CaMeL's LLM trace equals EP's by construction: one planner call plus one
  reader call per document (audit CAMEL-5). The paper reports about 2.8× tokens over an
  undefended agent; this emulation shows fewer.
* *Fides.* Fides is charged one planner turn per argument decision and per call, plus one
  `query_llm` per document. Because this charge is a modeling choice, the NO_GO rule also
  reports cost with every design's planner charged once ("1 planner"; audit FID-3).
* *AgentSentry.* Charged four replays plus one purifier call per boundary. Boundaries
  are the document return, the store return and each verifier return (audit AS-6).

**All designs**

* The reactive actor's credulity (newest claim wins) is fixed, not swept (audit F11).
  An actor that ignored new claims would fail every legitimate change.
