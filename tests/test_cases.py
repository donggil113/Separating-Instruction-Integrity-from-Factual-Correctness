"""Benchmark well-formedness: pairing, minimal differences, ground truth."""
from epad.cases.tasks import BASE_TASKS
from epad.cases.variants import VARIANTS, build_case, build_suite
from epad.sandbox.world import values_equal


def test_suite_size_and_families():
    cases = build_suite()
    assert len(cases) == 9 * 3 * (len(VARIANTS) - 1) + 2 * 3  # C_condition only for 2 bases
    assert {c.family for c in cases} == {"clean", "A", "B", "C"}


def test_A_and_B_keep_true_facts_and_expected_actions():
    for b, mk in BASE_TASKS.items():
        base = mk(0)
        clean = build_case(base, "clean")
        for v in VARIANTS:
            if v[0] in "AB":
                c = build_case(base, v)
                assert c.gt.true_facts == clean.gt.true_facts, (b, v)
                assert [a.key() for a in c.gt.expected] == [a.key() for a in clean.gt.expected], (b, v)


def test_C_changes_truth_reference_but_not_user_store():
    for b, mk in BASE_TASKS.items():
        base = mk(0)
        for v in ("C_change", "C_change_imp", "C_change_unauth", "C_multi"):
            c = build_case(base, v)
            k = base.change_key
            assert values_equal(c.gt.true_facts[k], base.new_value)
            ref = c.world.references[c.spec.reference_for(k)]
            assert values_equal(ref.table[k], base.new_value)
            for store in c.world.stores.values():
                if k in store:
                    assert values_equal(store[k], base.truth[k]), "user store must be stale in C"


def test_false_values_are_refuted_by_reference_and_attacker_account_is_real():
    for b, mk in BASE_TASKS.items():
        base = mk(0)
        c = build_case(base, "B_false")
        k = base.change_key
        ref = c.world.references[c.spec.reference_for(k)]
        assert ref.confirm(k, base.false_value).value == "refuted"
    inv = build_case(BASE_TASKS["pay_invoice"](0), "A_new_action")
    att = inv.gt.attacker_actions[0]
    cop = inv.world.references["confirmation_of_payee"]
    from epad.cases.tasks import payee_id
    assert cop.confirm((payee_id(att.args["payee"]), "account"), att.args["account"]).value == "confirmed"


def test_condition_variant_expects_no_action():
    for b in ("pay_invoice", "reorder"):
        c = build_case(BASE_TASKS[b](1), "C_condition")
        assert c.gt.expected == []


def test_variants_differ_from_clean_only_in_documents_or_truth():
    base = BASE_TASKS["salary"](2)
    clean = build_case(base, "clean")
    for v in VARIANTS:
        c = build_case(base, v)
        if c is None:
            continue
        assert c.spec == clean.spec, v            # identical user request and grant
        assert c.world.profile == clean.world.profile
