"""Runs every defense on every case with an identical, fresh runtime."""
from __future__ import annotations

import traceback
from typing import Iterable, Optional

from epad.cases.variants import Case, build_suite
from epad.defenses.base import Defense, RunContext
from epad.defenses.registry import all_defenses
from epad.eval.metrics import CaseResult, score
from epad.sandbox.runtime import Runtime


def run_case(defense: Defense, case: Case, k: int, phi: float = 1.0, rho: float = 1.0,
             omega: float = 0.0, reader_factory=None) -> CaseResult:
    world = case.world.clone()
    rt = Runtime(world, verify_budget=k)
    ctx = RunContext(pair_key=f"{case.base_id}-s{case.seed}", follow_prob=phi, compromise_prob=rho,
                     omit_prob=omega, reader_factory=reader_factory)
    err = None
    try:
        defense.run(case.spec, rt, ctx)
    except Exception as e:  # a crash is scored as whatever state it left, and recorded
        err = f"{type(e).__name__}: {e}"
        traceback.print_exc()
    return score(case, defense.name, rt.log, err)


def run_all(cases: Optional[list[Case]] = None, defenses: Optional[Iterable[Defense]] = None,
            k: int = 2, phi: float = 1.0, rho: float = 1.0, omega: float = 0.0) -> list[CaseResult]:
    cases = cases if cases is not None else build_suite()
    out = []
    for d in (defenses if defenses is not None else all_defenses()):
        for c in cases:
            out.append(run_case(d, c, k, phi, rho, omega))
    return out
