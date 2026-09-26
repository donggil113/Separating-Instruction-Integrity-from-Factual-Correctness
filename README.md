# Evidence-Preserving Agent Defenses: Separating Instruction Integrity from Factual Correctness

**Research question (N4).** Can a tool-using agent be *unaffected by malicious
instructions* in untrusted content, yet *react correctly* to legitimate changes in
relevant facts, and *not act* on false or contradictory ones?

This repository contains:

* a **sandbox benchmark** of paired cases (A: facts fixed + malicious instruction;
  B: false/contradictory facts; C: legitimate relevant change);
* a **schema** that keeps policy, fact, evidence and authority apart;
* an **evidence-preserving (EP)** reference design: claim → independent verification →
  allowed action argument;
* **scripted emulations** of CaMeL, Fides, AgentSentry and AgentDojo's tool filter, all
  given the same references, tools and verification budget;
* a **pre-registered GO / NO_GO analysis**.

> **Verdict: see [`docs/08_go_no_go.md`](docs/08_go_no_go.md).**
> In short: under the stated assumptions, EP reaches 0% committed unauthorized actions
> with 97% utility, and improves on the strongest configurations of CaMeL, Fides and
> AgentSentry at equal information and equal or lower cost. However, **the entire gain
> comes from one endorsement rule** that transplants into CaMeL's policy engine or Fides'
> typed escape hatch with *identical* results. So it is **NO_GO as a new defense
> mechanism**, and at most a conditional GO as a benchmark and design-rule
> contribution, pending LLM-in-the-loop replication.

## Layout

```
epad/schema.py            Authority grant, Policy, Claim, Evidence, Directive (the four-way separation)
epad/plan.py              TaskSpec (trusted planner output) and grant instantiation
epad/sandbox/             in-memory world, independent references, per-episode runtime (budget, logs)
epad/cases/               9 base tasks x 3 seeds -> 357 paired variants; assumption-violation stress tests
epad/sim.py               scripted stand-ins for the quarantined reader and the reactive actor (no LLM)
epad/defenses/            EP (ours), CaMeL, Fides, AgentSentry, tool filter, controls/ablations
epad/eval/                metrics (per case), report (aggregation, paired bootstrap), runner
scripts/run_experiments.py  all experiments -> results/RESULTS.md, results/*.csv, results/summary.json
docs/                     01 related work · 02 threat model · 03 schema · 04 benchmark · 05 baselines
                          06 metrics · 07 results · 08 GO/NO_GO
tests/                    isolation/fairness invariants, benchmark well-formedness, EP rules R1-R3
```

## Reproduce

```bash
pip install pytest          # the only dependency (stdlib otherwise)
python -m pytest -q         # invariants
python scripts/run_experiments.py   # ~15 s; writes results/
```

Everything is deterministic: same code, same numbers.

## Scope and honesty notes

* **Sandbox only.** There are no real accounts, mail, calendars, shops or payment rails,
  and no network use. See `docs/02_threat_model.md`.
* **No real LLM.** Model behavior is scripted, and every model-dependent effect is an
  explicit knob (φ, ρ, ω, `p_fact_suggest`) that is swept. The results characterize
  *defense structure* under an ideal planner. They are not comparable to AgentDojo or
  AgentDyn numbers.
* **Nothing credited to prior work is claimed as new** (`docs/01_related_work.md` §3):
  IFC, taint tracking, capabilities, endorsement, replay, Dual-LLM, and
  instruction-stripping purification.
* **Guarantees hold only under** P1, P2, V1–V3 and R0. What breaks when a reference is
  stale or poisoned is measured in `results/RESULTS.md` §11.
