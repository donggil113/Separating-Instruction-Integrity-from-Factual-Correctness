"""Aggregation, paired bootstrap, and markdown rendering."""
from __future__ import annotations

import csv
import random
from collections import defaultdict
from typing import Callable, Iterable, Optional

from epad.eval.metrics import CaseResult

LABELS = ["injected", "exfil", "false_fact", "stale", "duplicate", "wrong_value", "unauthorized_other"]


def _rate(rs: list[CaseResult], f: Callable[[CaseResult], bool]) -> Optional[float]:
    return sum(1 for r in rs if f(r)) / len(rs) if rs else None


def summarize(rs: list[CaseResult]) -> dict:
    fam = defaultdict(list)
    for r in rs:
        fam[r.family].append(r)
    attack = fam["A"] + fam["B"]
    nonclean = fam["A"] + fam["B"] + fam["C"]
    with_exp = [r for r in rs if r.n_expected > 0]
    committed = sum(r.committed_actions for r in rs)
    n = len(rs)
    out = {
        "n": n,
        "util_clean": _rate(fam["clean"], lambda r: r.success),
        "util_A": _rate(fam["A"], lambda r: r.success),
        "util_B": _rate(fam["B"], lambda r: r.success),
        "util_C": _rate(fam["C"], lambda r: r.success),
        "util_attack": _rate(attack, lambda r: r.success),
        "util_all": _rate(rs, lambda r: r.success),
        "cua_clean": _rate(fam["clean"], lambda r: r.cua),
        "cua_A": _rate(fam["A"], lambda r: r.cua),
        "cua_B": _rate(fam["B"], lambda r: r.cua),
        "cua_C": _rate(fam["C"], lambda r: r.cua),
        "cua_all": _rate(nonclean, lambda r: r.cua),
        "asr_attack": _rate(attack, lambda r: r.attacker_goal),
        "blocked_per_case": sum(r.blocked_attempts for r in rs) / n,
        "blocked_unauth_per_case": sum(r.blocked_unauthorized for r in rs) / n,
        "blocked_legit_per_case": sum(r.blocked_legit for r in rs) / n,
        "attempted_unauth_rate": _rate(nonclean, lambda r: r.cua or r.blocked_unauthorized > 0),
        "over_refusal": _rate(with_exp, lambda r: r.over_refusal),
        "over_refusal_clean_C": _rate([r for r in with_exp if r.family in ("clean", "C")], lambda r: r.over_refusal),
        "evidence_correct": (sum(r.evidence_actions for r in rs) / committed) if committed else None,
        "evidence_valid": (sum(r.evidence_valid_actions for r in rs) / committed) if committed else None,
        "unsupported_correct_per_case": sum(r.unsupported_correct for r in rs) / n,
        "verify_calls": sum(r.verify_calls for r in rs) / n,
        "llm_calls": sum(r.llm_calls for r in rs) / n,
        "tokens": sum(r.tokens for r in rs) / n,
        "replays": sum(r.replay_calls for r in rs) / n,
        "budget_exhausted": _rate(rs, lambda r: r.budget_exhausted),
    }
    for lab in LABELS:
        out[f"n_{lab}"] = sum(r.cua_labels.count(lab) for r in rs)
    return out


def by(rs: Iterable[CaseResult], key: Callable[[CaseResult], object]) -> dict:
    g = defaultdict(list)
    for r in rs:
        g[key(r)].append(r)
    return g


def bootstrap_ci(rs: list[CaseResult], metric: Callable[[list[CaseResult]], float], n_boot: int = 2000,
                 seed: int = 0) -> tuple[float, float]:
    """95% percentile CI, resampling base instances (base task x seed) with replacement."""
    units = by(rs, lambda r: (r.base_id, r.seed))
    keys = list(units)
    rng = random.Random(seed)
    vals = []
    for _ in range(n_boot):
        sample = [r for _ in keys for r in units[rng.choice(keys)]]
        v = metric(sample)
        if v is not None:
            vals.append(v)
    vals.sort()
    return vals[int(0.025 * len(vals))], vals[int(0.975 * len(vals)) - 1]


def paired_diff(a: list[CaseResult], b: list[CaseResult], field: str, n_boot: int = 2000, seed: int = 0,
                families: Optional[set] = None) -> tuple[float, float, float]:
    """Mean of (a - b) over paired cases, with a bootstrap CI over base instances."""
    ia = {r.case_id: r for r in a if families is None or r.family in families}
    ib = {r.case_id: r for r in b if families is None or r.family in families}
    common = sorted(set(ia) & set(ib))
    diffs = defaultdict(list)
    for cid in common:
        ra, rb = ia[cid], ib[cid]
        diffs[(ra.base_id, ra.seed)].append(float(getattr(ra, field)) - float(getattr(rb, field)))
    keys = list(diffs)
    allv = [x for k in keys for x in diffs[k]]
    mean = sum(allv) / len(allv) if allv else 0.0
    rng = random.Random(seed)
    boots = []
    for _ in range(n_boot):
        s = [x for _ in keys for x in diffs[rng.choice(keys)]]
        boots.append(sum(s) / len(s))
    boots.sort()
    return mean, boots[int(0.025 * n_boot)], boots[int(0.975 * n_boot) - 1]


def fmt(v, pct: bool = True, nd: int = 2) -> str:
    if v is None:
        return "–"
    if pct:
        return f"{100 * v:.0f}%"
    return f"{v:.{nd}f}"


def md_table(header: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(out)


def write_csv(path: str, rs: list[CaseResult], extra: Optional[dict] = None) -> None:
    rows = [dict(r.row(), **(extra or {})) for r in rs]
    if not rows:
        return
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
