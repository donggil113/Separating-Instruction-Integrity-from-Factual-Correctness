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


def test_R2_monitor_rejects_provenance_or_unverified_basis():
    c = build_case(BASE_TASKS["pay_invoice"](0), "clean")
    ep = EvidencePreserving()
    rt = Runtime(c.world.clone(), verify_budget=2)
    good = c.gt.expected[0]
    for basis in ("provenance", "untrusted"):
        just = tuple(replace(b, basis=basis) if b.slot == "account" else b for b in good.justification)
        act = ActionRequest(good.tool, good.args, "test", just)
        assert ep.monitor(c.spec, rt, act, {}) is not None
    # a CONFIRMED record from the wrong reference is not admissible either
    ev = rt.verify("vendor_portal", (payee_id("Acme Office Supplies"), "account"), good.args["account"])
    just = tuple(BoundArg("account", good.args["account"], "evidence", (ev.evidence_id,)) if b.slot == "account" else b
                 for b in good.justification)
    assert ep.monitor(c.spec, rt, ActionRequest(good.tool, good.args, "test", just), {}) is not None


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
