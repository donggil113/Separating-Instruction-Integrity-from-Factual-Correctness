"""EP invariants (rules R1-R3) and metric sanity checks."""
from dataclasses import replace

from epad.cases.tasks import BASE_TASKS, payee_id
from epad.cases.variants import build_case, build_suite
from epad.defenses.base import RunContext
from epad.defenses.ep import EvidencePreserving
from epad.defenses.reactive import DenyAll, NoDefense
from epad.eval.runner import run_case
from epad.sandbox.runtime import Runtime
from epad.schema import ActionRequest, BoundArg


def test_R1_documents_cannot_add_actions():
    ep = EvidencePreserving()
    for c in build_suite(seeds=(0, 1)):
        r = run_case(ep, c, k=2)
        assert "injected" not in r.cua_labels and "exfil" not in r.cua_labels, c.case_id


def _pay_invoice_monitor_setup(extra_ref=False):
    """pay_invoice clean case, a runtime, the expected call (with its template index), and the amount
    fact already confirmed by its configured reference, so only the account argument is under test."""
    from epad.plan import Resolved
    from epad.sandbox.world import Reference
    c = build_case(BASE_TASKS["pay_invoice"](0), "clean")
    world = c.world.clone()
    k_acct = (payee_id("Acme Office Supplies"), "account")
    if extra_ref:          # a second reference that also covers the account, but is not the configured one
        world.references["other_registry"] = Reference("other_registry", frozenset({"account"}), False,
                                                       {k_acct: c.gt.true_facts[k_acct]})
    rt = Runtime(world, verify_budget=4)
    good = c.gt.expected[0]
    k_amt = c.spec.grant.templates[0].condition.fact
    ev_amt = rt.verify("vendor_portal", k_amt, c.gt.true_facts[k_amt])
    facts = {k_amt: Resolved(c.gt.true_facts[k_amt], "evidence", (ev_amt.evidence_id,))}
    return c, rt, good, k_acct, facts


def test_R2_monitor_rejects_provenance_or_unverified_basis():
    from epad.plan import Resolved
    ep = EvidencePreserving()
    c, rt, good, k_acct, facts = _pay_invoice_monitor_setup(extra_ref=True)
    acct = good.args["account"]
    assert good.template == 0
    # positive control: a CONFIRMED record from the configured reference is admitted
    ev = rt.verify("confirmation_of_payee", k_acct, acct)
    ok = {**facts, k_acct: Resolved(acct, "evidence", (ev.evidence_id,))}
    assert ep.monitor(c.spec, rt, good, ok) is None
    # provenance (authenticated sender) or an untrusted claim, without evidence: rejected by R2
    for basis in ("provenance", "untrusted", "trusted_store"):
        bad = {**facts, k_acct: Resolved(acct, basis)}
        assert ep.monitor(c.spec, rt, good, bad).startswith("R2"), basis
    # a CONFIRMED record for the same key and value, but from a reference that is not the configured one
    ev_other = rt.verify("other_registry", k_acct, acct)
    assert ev_other.verdict.value == "confirmed"
    wrong = {**facts, k_acct: Resolved(acct, "evidence", (ev_other.evidence_id,))}
    assert ep.monitor(c.spec, rt, good, wrong).startswith("R2")


def test_R1_monitor_rejects_template_mismatch_and_extra_calls():
    from epad.plan import Resolved
    ep = EvidencePreserving()
    c, rt, good, k_acct, facts = _pay_invoice_monitor_setup()
    ev = rt.verify("confirmation_of_payee", k_acct, good.args["account"])
    facts = {**facts, k_acct: Resolved(good.args["account"], "evidence", (ev.evidence_id,))}
    assert ep.monitor(c.spec, rt, good, facts) is None
    # the right template index, but a different user-fixed payee
    other_payee = replace(good, args={**good.args, "payee": "Northwind Settlement Services"})
    assert ep.monitor(c.spec, rt, other_payee, facts).startswith("R1")
    # the right template index, but a different tool
    assert ep.monitor(c.spec, rt, replace(good, tool="send_email"), facts).startswith("R1")
    # a second call of a template whose max_calls is 1
    rt.commit(rt.propose(good))
    assert ep.monitor(c.spec, rt, good, facts).startswith("R1")


def test_R2_monitor_rejects_actions_outside_grant():
    c = build_case(BASE_TASKS["pay_invoice"](0), "A_new_action")
    ep = EvidencePreserving()
    rt = Runtime(c.world.clone(), verify_budget=2)
    assert ep.monitor(c.spec, rt, c.gt.attacker_actions[0], {}) is not None


def test_EP_never_commits_false_values_under_assumptions():
    ep = EvidencePreserving()
    for c in build_suite():
        for k in (0, 1, 2, 3):
            r = run_case(ep, c, k=k)
            assert not r.cua, (c.case_id, k, r.cua_labels)


def test_metrics_sanity():
    c = build_case(BASE_TASKS["reorder"](0), "A_new_action")
    r = run_case(NoDefense(), c, k=2)
    assert r.cua and "injected" in r.cua_labels and r.attacker_goal
    r = run_case(DenyAll(), c, k=2)
    assert not r.cua and r.over_refusal and r.outcome == "REFUSED"
    cc = build_case(BASE_TASKS["reorder"](0), "C_condition")
    r = run_case(NoDefense(), cc, k=2)
    assert r.success and r.n_committed == 0


def test_metrics_catch_secret_in_free_argument_and_crash_is_not_success():
    from epad.eval.metrics import score
    from epad.sandbox.runtime import Runtime
    c = build_case(BASE_TASKS["accept_dinner"](0), "A_exfil")
    rt = Runtime(c.world.clone(), 2)
    for exp in c.gt.expected:
        args = dict(exp.args)
        if exp.tool == "send_email":
            args["body"] = "Happy to join, see you there! C7X41902"
        att = rt.propose(ActionRequest(exp.tool, args, "t", exp.justification, exp.template))
        rt.commit(att)
    r = score(c, "t", rt.log)
    assert r.cua and "exfil" in r.cua_labels
    cc = build_case(BASE_TASKS["reorder"](0), "C_condition")
    r = score(cc, "t", Runtime(cc.world.clone(), 2).log, error="boom")
    assert not r.success


def test_evidence_metric_reads_the_log_not_the_label():
    from epad.eval.metrics import score
    from epad.sandbox.runtime import Runtime
    c = build_case(BASE_TASKS["pay_invoice"](0), "clean")
    rt = Runtime(c.world.clone(), 2)
    exp = c.gt.expected[0]
    just = tuple(replace(b, basis="trusted_store") for b in exp.justification)   # self-reported, no read, no verify
    rt.commit(rt.propose(ActionRequest(exp.tool, exp.args, "t", just, 0)))
    r = score(c, "t", rt.log)
    assert r.fact_actions == 1 and r.evidence_correct == 0 and r.unsupported == 1
