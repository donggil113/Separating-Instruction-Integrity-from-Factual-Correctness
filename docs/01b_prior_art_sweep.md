# 01b · Prior-art sweep beyond the five core works (novelty threats)

Three independent sweeps (September 2026) covered:

* system-level defenses;
* false-fact / "attacks by content" work;
* over-refusal benchmarks.

Every listed work was fetched from its arXiv or venue page. Ratings of *novelty threat*
are the sweepers' own and were cross-checked by a completeness critic. Details come from
abstracts and HTML pages read through a summarising fetch tool. Before any number is
quoted in a paper, re-read the PDF.

## Works that most constrain what this project may claim

| work | what it already covers | consequence for N4 |
|---|---|---|
| **Attacks by Content: Automated Fact-checking is an AI Security Issue** (Schlichtkrull, arXiv 2510.11238, EMNLP 2025) | Separates instruction attacks from content (false-claim) attacks. Argues CaMeL-style and instruction-detection defenses cannot cover content attacks. Proposes corroborating claims with external evidence and source criticism. | The conceptual split "instruction integrity vs factual correctness" and "verify claims before acting" are **not new**. |
| **AI Agents May Always Fall for Prompt Injections** (Abdelnabi & Bagdasarian, arXiv 2605.17634) | Contextual manipulation evades data–instruction separation. Rejecting such claims "will inevitably block cases where they happen to be true". Without ground truth there is an over/under-compliance trade-off. | N4's B-vs-C tension is predicted there. Any N4 result must be conditional on an explicit independent reference. |
| **ROPE: Routed Origin Policy Enforcement** (arXiv 2608.27496) | Values for state-changing parameters must originate in the user's query, a user-named authenticated origin, or the user's own records. The design deliberately fails closed on document-only values such as a bill's IBAN. | "Documents cannot supply authority-bearing arguments" is prior art. N4 emulates ROPE as *Origin guard*, under a permissive reading that admits body values from an authenticated sender the user's records name. Unlike ROPE's bill example, this emulation therefore pays document-supplied IBANs from such senders (results §5). |
| **ARGUS** (arXiv 2605.03378, AgentLure) | Argument-injection vector; evidence-grounded argument checks; clean utility, attacked utility and refusal rate reported separately. Lists "signed records, source authentication, issuer checks" as future work. | Evidence-grounded argument checking is not new. ARGUS does not verify truth against an independent reference. |
| **NetInjectBench** (arXiv 2607.10490) | Paired benign / weak / strong-injection / *approved-change* classes; unsafe-action, useful-action, block and overblock rates; a static allowlist blocks all approved changes; a metadata gate is safe "under the stated metadata-integrity assumption". | The approved-change class, overblocking metric and assumption-scoped guarantee are not new. N4 differs in having false-world-fact cases (B), IFC/replay baselines and an equal verification budget. |
| **Explanation-Bound Tool Execution** (arXiv 2607.25364) | A deterministic *claim → verification against authoritative facts → allow/review/deny* path at the tool boundary, with no self-authorizing field. | Typed claims checked by a reference monitor are not new. EBTE checks the agent's action rationale; N4 checks world facts asserted in documents. |
| **EnvTrustBench — When Agents Overtrust Environmental Evidence** (arXiv 2605.08828) | False environment claims where a verification route exists (including payments). Calls for "mandatory corroboration" before mutable claims drive action. | B-type cases with a verification route are not new. It has no legitimate-change class and no over-refusal metric. |
| **Influence Is Not Authority** (arXiv 2608.29942) | Pairs the same action with legitimately tool-sourced vs unauthorized values. Shows attribution/replay guardrails conflate influence with authority. | Paired "legitimate source vs attack" designs and the over-flagging critique of replay defenses are not new. |
| **SIEVE** (arXiv 2512.06716), **SARA** (arXiv 2608.27146), **APPA** (arXiv 2607.24625) | Argument-source checks with cost-aware escalation; action induction separated from authorization; recoverable IFC with *Authority Rulings* (a ready slot for a verifier). SIEVE states that without independent evidence the legitimate and attacker-modified values are indistinguishable. APPA concedes that validation cannot rule out "a false allowed value". SARA scopes pure data-dependency attacks out. | The gap is recognised in prior work. The enforcement slot for verification-before-admission already exists (APPA rulings, CaMeL/Fides policies). ROPE's T3 holds only records the user's own authenticated actions wrote, so it does not admit an external reference; adding one would be an N4 strengthening. |
| **Agent-Sentry** (Sequeira et al., arXiv 2603.22868; distinct from AgentSentry 2602.22724) | Per-argument provenance plus an allowlist of sensitive values learned from benign runs. An LLM judge handles the residual "legitimate new value vs injection" decisions. | This is the exact C-vs-B decision, made without evidence. N4 emulates it as *Allowlist + judge* and sweeps the judge's accept rate (results §12). |
| **Indirect Prompt Injections: Are Firewalls All You Need?** (arXiv 2510.05244) | A cheap tool-output sanitizer plus tool-input minimizer is near-perfect on existing benchmarks. | This is a strong, cheap baseline. N4 emulates it as *Firewall*. It blocks the instruction-type A variants but commits on the reader-payload variant (A-family CUA 25% at the default ρ = 1; 0% at ρ = 0, results §8), and it fails on B (0% utility, 100% CUA). |
| **Agent Data Injection** (arXiv 2607.05120) | Data-shaped (non-instruction) injection bypasses instruction defenses. CaMeL-strict stops it only at a large utility cost. | The premise of family B is not new. |
| **Design Patterns for Securing LLM Agents** (arXiv 2506.08837) | Plan-then-execute and Dual-LLM leave argument/value manipulation open. | This is the motivating premise, not a discovery. |

## Other verified work

Lower relevance. These are credited in the text where used.

**System-level defenses:**
* Progent (2504.11703): it cannot defend "within least privilege".
* RTBAS (2502.08966).
* AgentFlow (2608.22868).
* MELON (2502.05174).
* DRIFT (2506.12104).
* IPIGuard (2508.15310).
* f-secure (2409.19091).
* Willison's Dual LLM pattern (2023).
* Task Shield, ACE, AgentArmor, AgentWatcher, PromptArmor, Spotlighting, Meta SecAlign, IsolateGPT.

**Knowledge and evidence:**
* PoisonedRAG (2402.07867).
* AgentPoison (2407.12784).
* ClashEval (2404.10198).
* RAMDocs / MADAM-RAG (2504.13079).
* RobustRAG (2405.15556).
* Lazy Grounding (2608.30303): true-but-misapplied facts. This supports entity binding (V3).
* CrAIBench (2503.16248).

**Benchmarks:**
* WASP (2504.18575) and RedTeamCUA (2505.21936): attempted vs committed harm.
* ASB (2410.02644).
* PIGuard / NotInject (2410.22770): over-defense.
* InjecAgent (2403.02691).
* BIPIA (2312.14197).
* AgentHarm (2410.09024).
* OS-Harm (2506.14866).
* AgentSecBench (2605.26269), which already uses the term "instruction integrity".

## Real-world practice

Verify-before-pay is standard banking practice:
* UK Confirmation of Payee;
* EU Verification of Payee, mandatory under the Instant Payments Regulation since 9 Oct 2025.

The answers of these services are *name-match* verdicts (match / close match / no match),
not a statement that "this is the counterparty's one true account". This is why the
benchmark includes `B_same_name_mule` and why EP verifies the user's own record first
(docs/03).

## Net effect on the claim space

After this sweep, none of the following is new:
* the instruction/content split;
* verify-before-act;
* approved-change classes;
* origin enforcement;
* endorsement;
* replay;
* evidence-grounded arguments.

What remains is the **joint, equal-information measurement**:
* paired A/B/C (+D) cases on the same action surface;
* the same independent reference given to every design under one budget (confirm-only for 4 of 9 tasks, lookup-capable for 5);
* committed vs blocked vs escalated vs evidence reported separately;
* transplant tests showing *which rule* produces a difference.

The critic's decision rule is the one applied in `08_go_no_go.md`: if CaMeL and Fides
given the verifier match N4 at ≤ cost, the defense claim is NO_GO and only the
measurement contribution can stand.
