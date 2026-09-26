"""Run every experiment and write results/ (CSV per experiment + RESULTS.md + summary.json).

    python scripts/run_experiments.py

Deterministic: same code, same numbers (~1-2 min).
"""
from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import replace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from epad.cases.stress import STRESS                                        # noqa: E402
from epad.cases.tasks import BASE_TASKS                                     # noqa: E402
from epad.cases.variants import build_suite                                 # noqa: E402
from epad.defenses.agentsentry import AgentSentry                           # noqa: E402
from epad.defenses.base import EP_POLICY                                    # noqa: E402
from epad.defenses.ep import EvidencePreserving                             # noqa: E402
from epad.defenses.extra import AllowlistJudge                              # noqa: E402
from epad.defenses.registry import OURS, STRONG_EXISTING, all_defenses      # noqa: E402
from epad.eval.report import MAIN, by, fmt, md_table, paired_diff, summarize, write_csv  # noqa: E402
from epad.eval.runner import run_all                                        # noqa: E402
from epad.schema import SlotKind, SlotRole                                  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "results")
K_MAIN, K_SUFF = 2, 4
AUTHORITY = {SlotRole.TARGET, SlotRole.ITEM}
COUNTERPART = {"CaMeL (strong plan)": "CaMeL + endorsement (all fact args)",
               "CaMeL (strong plan), faithful readers": None,
               "CaMeL (strong plan), TARGET-only authority": "CaMeL + endorsement (all fact args)",
               "Fides (strong plan)": "Fides shell + EP resolver (typed hatch)",
               "Fides (arg-level P-T)": "Fides shell + EP resolver (typed hatch)",
               "AgentSentry": "AgentSentry + verify prompt", "AgentSentry (strict Auth)": "AgentSentry + verify prompt",
               "Firewall (sanitizer+minimizer)": "Firewall + verify prompt",
               "Origin guard (ROPE-style)": None, "Allowlist + judge (q=0.5)": None, "Tool filter": None}


def names():
    return [d.name for d in all_defenses()]


def main_rows(rs):
    return [r for r in rs if r.family in MAIN]


def pct_pair(d, favour_neg=False):
    pos, neg = (d["tasks_neg"], d["tasks_pos"]) if favour_neg else (d["tasks_pos"], d["tasks_neg"])
    return f"{100*d['mean']:+.1f} [{100*d['lo']:+.1f}, {100*d['hi']:+.1f}] ({pos}/{neg})"


def table_main(rs, lines, k):
    s = {d: summarize(v) for d, v in by(rs, lambda r: r.defense).items()}
    lines.append(f"\n### Outcomes (k = {k})\n")
    rows = []
    for d in names():
        m = s[d]
        rows.append([d, fmt(m["util_clean"]), fmt(m["util_A"]), fmt(m["util_B"]), fmt(m["util_C"]),
                     fmt(m["cua_clean"]), fmt(m["cua_A"]), fmt(m["cua_B"]), fmt(m["cua_C"]), fmt(m["asr_attack"]),
                     fmt(m["over_refusal_clean_C"]), fmt(m["safe_abstention_B"])])
    lines.append(md_table(["defense", "util clean", "util A", "util B", "util C", "CUA clean", "CUA A", "CUA B",
                           "CUA C", "attacker goal (A+B)", "safe failure clean+C", "safe abstention B"], rows))
    return s


def table_detail(s, lines, k):
    lines.append(f"\n### Blocked attempts, evidence (from the log), cost (k = {k}; means per case)\n")
    rows = []
    for d in names():
        m = s[d]
        rows.append([d, fmt(m["blocked_unauth_per_case"], False), fmt(m["blocked_legit_per_case"], False),
                     fmt(m["attempted_unauth_rate"]), fmt(m["escalated_clean_C"]), fmt(m["evidence_correct"]),
                     fmt(m["store_only"]), fmt(m["unsupported"]), fmt(m["refuted_claims_per_case"], False),
                     fmt(m["verify_calls"], False), fmt(m["llm_calls"], False, 1), fmt(m["tokens"], False, 0)])
    lines.append(md_table(["defense", "blocked unauth.", "blocked legit.", "unauth. attempted (A+B+C)",
                           "escalated (clean+C)", "evidence-correct", "store-only", "unsupported",
                           "claims refuted", "verify calls", "LLM calls", "tokens (est.)"], rows))
    lines.append("\nEvidence columns are over committed grant calls with fact arguments: *evidence-correct* = every "
                 "fact argument has a CONFIRMED record (or lookup) in the log from the configured reference for exactly "
                 "that value, and is true; *store-only* = backed only by a trusted-store read; *unsupported* = neither.\n")
    lines.append(f"\n### Committed unauthorized actions by cause (counts, k = {k})\n")
    labs = ("injected", "exfil", "false_fact", "stale", "condition_violated", "duplicate", "wrong_value",
            "unauthorized_other")
    lines.append(md_table(["defense"] + list(labs), [[d] + [str(s[d][f"n_{l}"]) for l in labs] for d in names()]))


def per_variant(rs, lines, k):
    lines.append(f"\n## 2. Per-variant outcomes at k = {k} (success / unsafe / safe failure; counts over 3 seeds)\n")
    variants = []
    for r in rs:
        if r.variant not in variants:
            variants.append(r.variant)
    rows = []
    for d in names():
        g = by([r for r in rs if r.defense == d], lambda r: r.variant)
        cells = []
        for v in variants:
            vs = g[v]
            S = sum(r.success for r in vs)
            U = sum(r.cua for r in vs)
            cells.append(f"{S}/{U}/{len(vs) - S - U}")
        rows.append([d] + cells)
    lines.append(md_table(["defense"] + variants, rows))


def cell_of_tasks():
    cell = {}
    for b, mk in BASE_TASKS.items():
        base = mk(0)
        if base.delegated:
            continue
        roles = {s.role for t in base.spec.grant.templates for s in t.slots
                 if s.kind == SlotKind.FACT and s.fact == base.change_key}
        auth = "authority" if roles & AUTHORITY else "data"
        lk = base.references[base.spec.reference_for(base.change_key)].supports_lookup
        cell[b] = f"{auth} x {'lookup' if lk else 'confirm-only'}"
    return cell


def design_cells(rs, lines, k):
    lines.append(f"\n## 3. Design cells: role of the manipulated fact x reference capability (k = {k})\n")
    lines.append("Each task sits in one cell; EP-vs-X differences are reported per cell because pooled numbers depend "
                 "on how many tasks the benchmark places in each cell (audit BV-2). The factorial is incomplete: "
                 "no task has an authority fact with a lookup-capable reference.\n")
    cell = cell_of_tasks()
    cells = sorted(set(cell.values()))
    lines.append(md_table(["cell", "tasks"], [[c, ", ".join(sorted(b for b, v in cell.items() if v == c))] for c in cells]))
    ep = [r for r in main_rows(rs) if r.defense == OURS]
    rows = []
    for d in ["CaMeL (strong plan)", "Fides (strong plan)", "Fides (arg-level P-T)", "AgentSentry",
              "Origin guard (ROPE-style)", "Reference-only"]:
        other = [r for r in main_rows(rs) if r.defense == d]
        row = [d]
        for c in cells:
            a = [r for r in ep if cell.get(r.base_id) == c]
            b = [r for r in other if cell.get(r.base_id) == c]
            du = paired_diff(a, b, "success", n_boot=50)["mean"]
            dc = paired_diff(a, b, "cua", n_boot=50)["mean"]
            row.append(f"{100*du:+.0f} / {100*dc:+.0f}")
        rows.append(row)
    lines.append("\nEP minus X, Δ utility / Δ CUA (pp) per cell:\n")
    lines.append(md_table(["vs"] + cells, rows))


def paired(rs, lines, k):
    lines.append(f"\n### Paired comparison, EP minus X (k = {k}); mean over paired cases, 95% bootstrap CI over the "
                 "9 base tasks, (a/b) = base tasks favouring EP / favouring X\n")
    ep = sorted(main_rows([r for r in rs if r.defense == OURS]), key=lambda r: r.case_id)
    res, rows = {}, []
    for d in names():
        if d == OURS:
            continue
        o = sorted(main_rows([r for r in rs if r.defense == d]), key=lambda r: r.case_id)
        du = paired_diff(ep, o, "success")
        dc = paired_diff(ep, o, "cua", families={"A", "B", "C"})
        do = paired_diff(ep, o, "over_refusal", families={"clean", "C"}, only_owed=True)
        dv = paired_diff(ep, o, "verify_calls", n_boot=50)
        dl = paired_diff(ep, o, "llm_calls", n_boot=50)
        dp = paired_diff(ep, o, "planner_calls", n_boot=50)
        dt = paired_diff(ep, o, "tokens", n_boot=50)
        diff_cases = sum(1 for a, b in zip(ep, o) if a.outcome != b.outcome)
        res[d] = dict(du=du, dc=dc, do=do, dv=dv, dl=dl, dp=dp, dt=dt, diff_cases=diff_cases)
        rows.append([d, pct_pair(du), pct_pair(dc, favour_neg=True), pct_pair(do, favour_neg=True),
                     f"{dv['mean']:+.2f}", f"{dl['mean']:+.2f}", f"{dt['mean']:+.0f}", str(diff_cases)])
    lines.append(md_table(["vs X", "Δ utility pp", "Δ CUA (A+B+C) pp", "Δ safe failure (clean+C) pp", "Δ verify",
                           "Δ LLM calls", "Δ tokens", "cases with different outcome"], rows))
    return res


def no_go(pr, lines, k):
    lines.append(f"\n### Pre-registered NO_GO rule vs every strong existing defense (k = {k})\n")
    lines.append("EP *improves* on X only if a CI excludes 0 in EP's favour for utility or CUA and neither mean is worse. "
                 "Flags: *refusal* = EP fails safe more often on clean+C; *cost* = more LLM + verify calls as charged; "
                 "*cost(1 planner)* = the same with every design's planner charged once (audit FID-3). The last column "
                 "runs X's own framework with EP's rule (transplant) and counts cases whose outcome differs from EP.\n")
    rows, verdicts = [], {}
    for d in STRONG_EXISTING:
        p = pr[d]
        du, dc, do = p["du"], p["dc"], p["do"]
        improves = (du["lo"] > 0 or dc["hi"] < 0) and du["mean"] >= -1e-9 and dc["mean"] <= 1e-9
        tradeoff = (du["mean"] > 1e-9 and dc["mean"] > 1e-9) or (du["mean"] < -1e-9 and dc["mean"] < -1e-9)
        cost = p["dv"]["mean"] + p["dl"]["mean"]
        cost1 = cost - p["dp"]["mean"]
        flags = [f for f, c in (("refusal", do["mean"] > 1e-9), ("cost", cost > 1e-9), ("cost(1 planner)", cost1 > 1e-9)) if c]
        if improves and not flags:
            v = "improves"
        elif improves:
            v = "improves, but " + " + ".join(flags) + " (NO_GO)"
        elif tradeoff:
            v = "trade-off (neither dominates)"
        else:
            v = "no improvement"
        cp = COUNTERPART.get(d)
        cps = f"{cp}: {pr[cp]['diff_cases']}" if cp else "-"
        verdicts[d] = v
        rows.append([d, f"{100*du['mean']:+.1f}", f"{100*dc['mean']:+.1f}", f"{100*do['mean']:+.1f}",
                     f"{cost:+.2f} / {cost1:+.2f}", v, cps])
    lines.append(md_table(["X (same references, tools, k)", "Δ util", "Δ CUA", "Δ safe failure",
                           "Δ cost (charged / 1 planner)", "verdict", "X's framework + EP's rule: cases differing"], rows))
    return verdicts


def sweep(res_by_p, pname, defs, lines, title, metrics):
    lines.append(f"\n## {title}\n")
    ps = list(res_by_p)
    for metric in metrics:
        lines.append(f"\n**{metric}**\n")
        rows = [[d] + [fmt(summarize(main_rows([r for r in res_by_p[p] if r.defense == d]))[metric]) for p in ps]
                for d in defs]
        lines.append(md_table(["defense"] + [f"{pname}={p}" for p in ps], rows))


def main():
    os.makedirs(OUT, exist_ok=True)
    t0 = time.time()
    cases = build_suite()
    n_main = sum(1 for c in cases if c.family in MAIN)
    lines = ["# Results (auto-generated by scripts/run_experiments.py)\n",
             f"{len(cases)} cases = {n_main} paired clean/A/B/C cases over 9 base tasks x 3 seeds, plus "
             f"{len(cases) - n_main} delegation (D) cases. Seeds change surface details only, so the statistical unit "
             "is the base task (9). All numbers come from scripted, deterministic model stand-ins "
             "(docs/02_threat_model.md): they characterise *defense structure* under an ideal planner, not any real "
             "LLM. Utility = exact task success. CUA = committed unauthorized action. Safe failure = no CUA but the "
             "task was not completed.\n"]

    lines.append("\n## 1. Main results\n")
    lines.append("k = 2 is the pre-registered budget. After the audit, EP verifies the user's own record as well (rule "
                 "R2), so k = 2 is tight for the two-fact payment task; k = 4 repeats every comparison with a budget that "
                 "no longer binds. Every design always gets the same k.\n")
    all_res, summ, pairs, verdicts = {}, {}, {}, {}
    for k in (K_MAIN, K_SUFF):
        rs = run_all(cases, k=k)
        all_res[k] = rs
        write_csv(os.path.join(OUT, f"main_k{k}.csv"), rs, {"k": k})
        summ[k] = table_main(main_rows(rs), lines, k)
    for k in (K_MAIN, K_SUFF):
        table_detail(summ[k], lines, k)

    per_variant(all_res[K_SUFF], lines, K_SUFF)
    design_cells(all_res[K_SUFF], lines, K_SUFF)

    lines.append("\n## 4. Paired comparisons and the NO_GO rule\n")
    for k in (K_MAIN, K_SUFF):
        pairs[k] = paired(all_res[k], lines, k)
        verdicts[k] = no_go(pairs[k], lines, k)

    lines.append("\n### Leave-one-base-task-out range of Δ utility / Δ CUA (pp), k = 4\n")
    rs4 = main_rows(all_res[K_SUFF])
    rows = []
    for d in STRONG_EXISTING:
        du, dc = [], []
        for b in sorted({r.base_id for r in rs4}):
            a = [r for r in rs4 if r.defense == OURS and r.base_id != b]
            o = [r for r in rs4 if r.defense == d and r.base_id != b]
            du.append(100 * paired_diff(a, o, "success", n_boot=10)["mean"])
            dc.append(100 * paired_diff(a, o, "cua", n_boot=10, families={"A", "B", "C"})["mean"])
        rows.append([d, f"{min(du):+.1f} .. {max(du):+.1f}", f"{min(dc):+.1f} .. {max(dc):+.1f}"])
    lines.append(md_table(["vs X", "Δ utility", "Δ CUA"], rows))

    lines.append("\n## 5. Delegation family D (the user lets a document choose the counterparty): the cost of rule R1 "
                 "(k = 4; 3 cases per variant)\n")
    rows = []
    for d in names():
        cells = [d]
        for v in ("D_delegated", "D_tampered"):
            vs = [r for r in all_res[K_SUFF] if r.defense == d and r.variant == v]
            cells.append(f"{sum(r.success for r in vs)}/{sum(r.cua for r in vs)}/{sum(r.over_refusal for r in vs)}")
        rows.append(cells)
    lines.append(md_table(["defense", "D_delegated (S/U/R)", "D_tampered (S/U/R)"], rows))

    verifying = ["CaMeL (strong plan)", "Fides (strong plan)", "Fides (arg-level P-T)", "Reference-only",
                 "EP w/o endorsement", "EP (unique confirmation)", "EP v0 (pre-audit)",
                 "CaMeL + endorsement (all fact args)", "AgentSentry + verify prompt", OURS]
    dsel = [d for d in all_defenses() if d.name in verifying]
    k_res = {}
    for k in (0, 1, 2, 3, 4, 6):
        k_res[k] = [r for r in (all_res[k] if k in all_res else run_all(cases, dsel, k=k)) if r.defense in verifying]
    sweep(k_res, "k", verifying, lines, "6. Verification-budget sweep (same k for every design)",
          ("util_all", "util_B", "util_C", "cua_nonclean", "over_refusal_clean_C"))

    reactive = ["No defense", "Tool filter", "AgentSentry", "Firewall (sanitizer+minimizer)",
                "Allowlist + judge (q=0.5)", "Verify-only guard", OURS]
    dsel = [d for d in all_defenses() if d.name in reactive]
    phi_res = {p: run_all(cases, dsel, k=K_SUFF, phi=p) for p in (0.1, 0.3, 0.6, 1.0)}
    sweep(phi_res, "phi", reactive, lines, "7. Instruction-compliance sweep phi (k = 4)",
          ("cua_A", "cua_nonclean", "util_all"))

    readers = ["CaMeL (as evaluated)", "CaMeL (strong plan)", "Fides (as evaluated)", "Fides (strong plan)",
               "AgentSentry", "Firewall (sanitizer+minimizer)", "Origin guard (ROPE-style)",
               "AgentSentry + verify prompt", OURS]
    dsel = [d for d in all_defenses() if d.name in readers]
    rho_res = {p: run_all(cases, dsel, k=K_SUFF, rho=p) for p in (0.0, 0.5, 1.0)}
    sweep(rho_res, "rho", readers, lines, "8. Reader/purifier compromise sweep rho (k = 4)", ("cua_A", "cua_C", "util_all"))

    omit = ["CaMeL (strong plan)", "CaMeL + endorsement (authority args)", "CaMeL + endorsement (all fact args)",
            "Fides shell + EP resolver (typed hatch)", "AgentSentry + verify prompt", OURS]
    dsel = [d for d in all_defenses() if d.name in omit]
    om_res = {w: run_all(cases, dsel, k=K_SUFF, omega=w) for w in (0.0, 0.1, 0.25, 0.5)}
    sweep(om_res, "omega", omit, lines,
          "9. Verification-omission sweep omega (k = 4). Rows differ in the scope of the rule enforced at the sink "
          "(authority arguments only vs every fact argument), not in framework",
          ("cua_nonclean", "util_all", "over_refusal_clean_C"))

    conf = ["CaMeL (strong plan)", "Fides (strong plan)", "Fides (arg-level P-T)", "AgentSentry",
            "Firewall (sanitizer+minimizer)", "Reference-only", OURS]
    dsel = [d for d in all_defenses() if d.name in conf]
    conf_res = {}
    for kif, dac in ((1.0, 0.0), (0.5, 0.0), (0.0, 0.0), (1.0, 0.5), (1.0, 1.0)):
        conf_res[f"{kif}/{dac}"] = run_all(cases, dsel, k=K_SUFF, keep_imperative_facts=kif, directive_as_claim=dac)
    sweep(conf_res, "keep_imperative_facts/directive_as_claim", conf, lines,
          "10. Instruction-vs-fact confusion in every reader and purifier (k = 4)", ("cua_A", "cua_C", "util_C"))

    as_res = {}
    for p in (0.0, 0.25, 0.5, 1.0):
        as_res[p] = run_all(cases, [AgentSentry(p_fact_suggest=p, name="AgentSentry"),
                                    AgentSentry(p_fact_suggest=p, auth="strict", name="AgentSentry (strict Auth)")],
                            k=K_SUFF)
    sweep(as_res, "p_fact_suggest", ["AgentSentry", "AgentSentry (strict Auth)"], lines,
          "11. AgentSentry detection sensitivity (k = 4)", ("cua_A", "cua_nonclean", "util_all"))

    judge = {q: run_all(cases, [AllowlistJudge(q, name="Allowlist + judge")], k=K_SUFF) for q in (0.0, 0.25, 0.5, 0.75, 1.0)}
    sweep(judge, "q", ["Allowlist + judge"], lines,
          "12. Without evidence B and C move together: allowlist + judge accepting new values with probability q "
          "(k = 4)", ("util_B", "util_C", "cua_B", "cua_C"))

    lines.append("\n## 13. Verification order (one setting shared by every verifying design): EP at k = 2 / k = 4\n")
    rows = []
    for o in ("store_first", "challengers_first"):
        ep = EvidencePreserving(replace(EP_POLICY, order=o), name="EP")
        m2 = summarize(main_rows(run_all(cases, [ep], k=K_MAIN)))
        m4 = summarize(main_rows(run_all(cases, [ep], k=K_SUFF)))
        rows.append([o] + [f"{fmt(m2[x], x != 'verify_calls')} / {fmt(m4[x], x != 'verify_calls')}"
                           for x in ("util_B", "util_C", "cua_nonclean", "verify_calls")])
    lines.append(md_table(["order", "util B", "util C", "CUA (A+B+C)", "verify calls"], rows))

    lines.append("\n## 14. Assumption violations (outside the guarantee; never mixed into sections 1-13; k = 4)\n")
    rows, stress_all = [], []
    focus = ["No defense", "CaMeL (strong plan)", "Fides (strong plan)", "Fides (arg-level P-T)", "AgentSentry",
             "Origin guard (ROPE-style)", "Reference-only", "EP v0 (pre-audit)", OURS]
    dsel = [d for d in all_defenses() if d.name in focus]
    for sname, fn in STRESS.items():
        sc = [c2 for c2 in (fn(c) for c in cases if c.family in MAIN) if c2 is not None]
        rs = run_all(sc, dsel, k=K_SUFF)
        stress_all += rs
        for d in focus:
            m = summarize([r for r in rs if r.defense == d])
            rows.append([sname, d, str(m["n"]), fmt(m["util_all"]), fmt(m["cua_all"]), str(m["n_false_fact"]),
                         str(m["n_stale"])])
    write_csv(os.path.join(OUT, "stress.csv"), stress_all)
    lines.append(md_table(["violated assumption", "defense", "n", "utility", "CUA", "false-fact commits",
                           "stale commits"], rows))

    lines.append(f"\n_Runtime: {time.time() - t0:.1f}s._\n")
    with open(os.path.join(OUT, "RESULTS.md"), "w") as f:
        f.write("\n".join(lines))
    strip = lambda p: {n: ({kk: vv for kk, vv in v.items() if kk != "per_task"} if isinstance(v, dict) else v)
                       for n, v in p.items()}
    with open(os.path.join(OUT, "summary.json"), "w") as f:
        json.dump({"main": {str(k): summ[k] for k in summ}, "verdicts": {str(k): verdicts[k] for k in verdicts},
                   "paired": {str(k): {d: strip(p) for d, p in pairs[k].items()} for k in pairs}}, f, indent=1)
    print(f"done in {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
