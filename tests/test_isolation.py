"""Fairness/isolation invariants: no defense can see ground truth or the variant label."""
import ast
import pathlib

from epad.cases.variants import build_suite
from epad.defenses.base import RunContext
from epad.defenses.registry import all_defenses
from epad.eval.runner import run_case

DEFENSE_DIR = pathlib.Path(__file__).resolve().parents[1] / "epad" / "defenses"
FORBIDDEN_IMPORTS = {"epad.eval", "epad.eval.metrics", "epad.eval.runner", "epad.cases.variants", "epad.cases.stress"}


def test_defenses_do_not_import_evaluator_or_ground_truth():
    for f in DEFENSE_DIR.glob("*.py"):
        tree = ast.parse(f.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert node.module not in FORBIDDEN_IMPORTS, f"{f.name} imports {node.module}"
            if isinstance(node, ast.Import):
                for a in node.names:
                    assert a.name not in FORBIDDEN_IMPORTS, f"{f.name} imports {a.name}"


def test_defenses_do_not_touch_private_world():
    for f in list(DEFENSE_DIR.glob("*.py")) + [DEFENSE_DIR.parent / "sim.py"]:
        src = f.read_text()
        assert "_world" not in src, f"{f.name} reaches into Runtime._world"
        assert ".gt" not in src and "ground_truth" not in src.replace('origin="ground_truth"', ""), f.name


def test_run_context_does_not_reveal_variant():
    cases = build_suite(seeds=(0,), bases=["pay_invoice"])
    keys = {RunContext(pair_key=f"{c.base_id}-s{c.seed}").pair_key for c in cases}
    assert len(keys) == 1  # identical across all paired variants


def test_every_defense_gets_same_budget_and_never_exceeds_it():
    cases = build_suite(seeds=(0,))
    for d in all_defenses():
        for c in cases:
            for k in (0, 1, 2):
                r = run_case(d, c, k)
                assert r.verify_calls <= k, (d.name, c.case_id, k)
                assert r.error is None, (d.name, c.case_id, r.error)


def test_statement_annotations_carry_no_truth_label():
    from epad.sandbox.world import Statement
    fields = set(Statement.__dataclass_fields__)
    assert not ({"true", "is_true", "truth", "label", "malicious", "variant"} & fields)
