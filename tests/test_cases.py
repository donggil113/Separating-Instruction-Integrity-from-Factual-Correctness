"""Benchmark well-formedness: pairing, minimal differences, ground truth."""
from epad.cases.tasks import BASE_TASKS
from epad.cases.variants import VARIANTS, build_case, build_suite
from epad.sandbox.world import values_equal


RESTRICTED = {"B_mule_lookalike": 2, "B_same_name_mule": 2, "B_condition": 2, "C_condition": 2, "C_condition_on": 1}
STANDARD = [b for b in BASE_TASKS if not BASE_TASKS[b](0).delegated]


def test_suite_size_and_families():
    cases = build_suite()
    n_std = len(STANDARD)
    general = [v for v in VARIANTS if v not in RESTRICTED and not v.startswith("D_")]
    expected = 3 * (n_std * len(general) + sum(RESTRICTED.values()) + 2)   # + D_delegated, D_tampered on pay_bill
    assert len(cases) == expected
    assert {c.family for c in cases} == {"clean", "A", "B", "C", "D"}


def test_A_and_B_keep_true_facts_and_expected_actions():
    for b in STANDARD:
        base = BASE_TASKS[b](0)
        clean = build_case(base, "clean")
        for v in VARIANTS:
            if v[0] in "AB" and v != "B_condition":   # B_condition deliberately starts from a no-act world
                c = build_case(base, v)
                if c is None:
                    continue
                assert c.gt.true_facts == clean.gt.true_facts, (b, v)
                assert [a.key() for a in c.gt.expected] == [a.key() for a in clean.gt.expected], (b, v)


def test_C_changes_truth_reference_but_not_user_store():
    for b in STANDARD:
        base = BASE_TASKS[b](0)
        for v in ("C_change", "C_change_imp", "C_change_unauth", "C_multi", "C_silent", "C_suppressed", "C_race"):
            c = build_case(base, v)
            k = base.change_key
            assert values_equal(c.gt.true_facts[k], base.new_value)
            ref = c.world.references[c.spec.reference_for(k)]
            assert values_equal(ref.table[k], base.new_value)
            for store in c.world.stores.values():
                if k in store:
                    assert values_equal(store[k], base.truth[k]), "user store must be stale in C"


def test_false_values_are_refuted_by_reference_and_attacker_account_is_real():
    for b in STANDARD:
        base = BASE_TASKS[b](0)
        c = build_case(base, "B_false")
        k = base.change_key
        ref = c.world.references[c.spec.reference_for(k)]
        assert ref.confirm(k, base.false_value).value == "refuted"
        m = build_case(base, "B_mule_lookalike")
        if m is not None:
            mule = m.gt.false_values[k][0]
            cop = m.world.references[m.spec.reference_for(k)]
            assert cop.confirm(k, mule).value == "close_match"          # never CONFIRMED for the real payee
        sm = build_case(base, "B_same_name_mule")
        if sm is not None:                                            # name-match semantics: the mule CONFIRMS
            mule = sm.gt.false_values[k][0]
            assert sm.world.references[sm.spec.reference_for(k)].confirm(k, mule).value == "confirmed"
    inv = build_case(BASE_TASKS["pay_invoice"](0), "A_new_action")
    att = inv.gt.attacker_actions[0]
    cop = inv.world.references["confirmation_of_payee"]
    from epad.cases.tasks import payee_id
    assert cop.confirm((payee_id(att.args["payee"]), "account"), att.args["account"]).value == "confirmed"


def test_condition_variant_expects_no_action():
    for b in ("pay_invoice", "reorder"):
        c = build_case(BASE_TASKS[b](1), "C_condition")
        assert c.gt.expected == []


def test_seeds_change_surface_not_outcomes():
    """Seeds vary names/digits only: the statistical unit is the base task (see eval/report.py)."""
    from epad.defenses.ep import EvidencePreserving
    from epad.eval.runner import run_case
    for b in STANDARD:
        outs = [[run_case(EvidencePreserving(), c, 2).outcome for c in build_suite(seeds=(s,), bases=[b])]
                for s in (0, 1, 2)]
        assert outs[0] == outs[1] == outs[2], b


def test_variants_differ_from_clean_only_in_documents_or_truth():
    base = BASE_TASKS["salary"](2)
    clean = build_case(base, "clean")
    for v in VARIANTS:
        c = build_case(base, v)
        if c is None:
            continue
        assert c.spec == clean.spec, v            # identical user request and grant
        assert c.world.profile == clean.world.profile
