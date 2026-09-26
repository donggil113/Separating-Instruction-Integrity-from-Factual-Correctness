# Evidence-Preserving Agent Defenses: Separating Instruction Integrity from Factual Correctness

**Research question (N4).** Can a tool-using agent be *unaffected by malicious
instructions* in untrusted content, yet *react correctly* to legitimate changes in
relevant facts, and *not act* on false or contradictory ones?

This repository contains:

* a **sandbox benchmark** of 492 paired cases:
  * A: facts fixed + malicious instruction;
  * B: false or contradictory facts;
  * C: a legitimate relevant change;
  * D: a counterparty delegated to a document;
* a **schema** that keeps policy, fact, evidence and authority apart;
* an **evidence-preserving (EP)** reference design: claim → independent verification →
  allowed action argument, with authority only from the user's grant;
* **scripted emulations** of 11 strong existing-defense configurations (CaMeL, Fides,
  AgentSentry, a firewall, a ROPE-style origin guard, an allowlist + judge, a tool
  filter), plus the as-published CaMeL and Fides. Every design gets the same references,
  tools and verification budget;
* **transplant tests** that add EP's rule to CaMeL, Fides, AgentSentry and the firewall;
* a **pre-registered GO / NO_GO analysis** and an adversarial audit.

> **Verdict ([`docs/08_go_no_go.md`](docs/08_go_no_go.md)): NO_GO for the defense
> mechanism.**
>
> Under the stated assumptions, EP reaches 0% committed unauthorized actions at every
> budget, with 82% utility at k = 2 and 93% at k = 4. Its C-family utility is 84% at
> k = 4; the remaining C cases fail safe.
>
> It does **not** improve on the strongest existing configurations at the same
> information and cost:
>
> * against CaMeL's strongest legal plan the gain is not significant at the
>   pre-registered budget (+2.5 pp [+0.0, +7.7] at k = 2). At k = 4 it is borderline
>   (+9.3 pp [+0.0, +18.1]) and needs more verification calls;
> * every significant gain over other baselines comes with more verification calls or
>   more safe failures;
> * EP's endorsement rule, transplanted into CaMeL, Fides, AgentSentry or the firewall,
>   reproduces EP's outcome in all 486 clean/A/B/C cases at both budgets.
>
> The gain is a portable rule, and the rule is prior art in pieces. At most the
> *benchmark and equal-information protocol* are a conditional contribution, pending
> LLM-in-the-loop replication.

## Layout

```
epad/schema.py              AuthorityGrant, Policy, Claim, Evidence, Directive (the four-way separation)
epad/plan.py                TaskSpec (trusted planner output), grant instantiation, derived-argument transforms
epad/ids.py                 entity ids shared by tasks and defenses (defenses never import the case generator)
epad/sandbox/               in-memory world, independent references (confirm / lookup / name-match), runtime with budget k and logs
epad/cases/                 9 base tasks + 1 delegated task, x 3 seeds -> 492 cases; assumption-violation stress tests
epad/sim.py                 scripted stand-ins for the quarantined reader and the reactive actor (no LLM)
epad/llm_reader.py          optional LLM-backed reader (not run; needs EPAD_READER_MODEL and an API key)
epad/defenses/base.py       shared resolver (ResolvePolicy), retrieval, reader, fairness contract
epad/defenses/              EP (ours); CaMeL, Fides, AgentSentry, Firewall, Origin guard, Allowlist+judge,
                            tool filter; transplants; ablations; registry.py lists all 27 configurations
epad/eval/                  per-case metrics (from the episode log), aggregation, paired bootstrap, runner
scripts/run_experiments.py  all experiments -> results/RESULTS.md, results/*.csv, results/summary.json
scripts/run_llm_reader.py   optional LLM-reader track (not run)
docs/                       01 related work · 01b prior-art sweep · 02 threat model · 03 schema · 04 benchmark
                            05 baselines · 06 metrics · 07 results · 08 GO/NO_GO · 09 audit log
tests/                      isolation/fairness invariants, benchmark well-formedness, EP rules R1-R3,
                            baseline structural outcomes
```

## Reproduce

```bash
pip install pytest                   # the only dependency for tests and experiments (stdlib otherwise)
python -m pytest -q                  # 36 invariants
python scripts/run_experiments.py    # ~30 s; writes results/
```

Everything is deterministic: same code, same numbers. The optional LLM-reader track
needs `pip install anthropic`, an API key and `EPAD_READER_MODEL`; it has not been run
for the reported results.

`results/RESULTS.md` sections:

1. main tables at k = 2 and k = 4;
2. per-variant outcomes;
3. design cells;
4. paired comparisons, the NO_GO rule and leave-one-task-out ranges;
5. family D;
6. budget sweep;
7. actor compliance φ;
8. reader/purifier hijack ρ;
9. verification omission ω;
10. instruction/fact confusion knobs;
11. AgentSentry detection sensitivity;
12. judge accept rate q;
13. verification order;
14. assumption-violation stress tests.

## Scope and honesty notes

* **Sandbox only.** There are no real accounts, mail, calendars, shops or payment rails,
  and no network use in the main path (`docs/02_threat_model.md`).
* **No real LLM.** Model behavior is scripted. The main model-dependent effects are
  explicit, swept knobs: φ, ρ, ω, `keep_imperative_facts`, `directive_as_claim`,
  `p_fact_suggest` and q. Some are fixed: the reactive actor's credulity and its
  instruction/fact separation, and AgentSentry's severity scoring. Instruction-vs-fact
  separation comes from statement annotations, which a real reader would have to infer. The results characterize
  *defense structure* under an ideal planner. They are not comparable to AgentDojo or
  AgentDyn numbers.
* **Nothing credited to prior work is claimed as new** (`docs/01_related_work.md` §3,
  `docs/01b_prior_art_sweep.md`). This covers IFC, taint tracking, capabilities,
  endorsement, replay, Dual-LLM, instruction-stripping purification, origin enforcement,
  approved-change classes, evidence-grounded arguments and bank verify-before-pay.
* **Guarantees hold only under** P1, P2, V1–V3 and R0. EP is worse than no defense when a
  reference is stale (97% vs 47% CUA), no better than no defense when it is poisoned
  (100% CUA for both), and name-match references weaken V1 (results §14,
  `docs/02_threat_model.md`).
* **The NO_GO rule was extended after the audit** with a "cost (1 planner)" flag, a
  base-task resampling unit and a k = 4 repeat (`docs/06_metrics.md`). The NO_GO verdict
  holds without them: the transplants match EP, and every gain over CaMeL (strong plan)
  needs more verification calls.
* **The audit changed the design.** The pre-audit EP (kept as `EP v0`) relied on a
  benchmark regularity, and has 14.4% CUA on the extended suite (`docs/09_audit_log.md`).
