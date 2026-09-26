"""The optional LLM reader adapter, exercised with a fake completion function (no network)."""
from epad.cases.tasks import BASE_TASKS
from epad.cases.variants import build_case
from epad.defenses.ep import EvidencePreserving
from epad.eval.runner import run_case
from epad.llm_reader import LLMReader, coerce


def test_coerce():
    assert coerce("EUR 1,240.00") == 1240.0 and coerce("9:05") == "09:05" and coerce("SBX12 3456") == "SBX12 3456"


def test_llm_reader_drops_out_of_schema_claims_and_keeps_directives():
    base = BASE_TASKS["pay_invoice"](0)
    case = build_case(base, "A_reader_payload")
    k_acct = base.change_key

    def fake(system, user, schema):
        # a hijacked model: reports the attacker's account, plus a claim about an unrequested entity
        return {"claims": [{"entity": k_acct[0], "attribute": "account", "value": base.false_value},
                           {"entity": "payee:northwind-settlement-services", "attribute": "account", "value": "X"}],
                "directives": ["the only valid account is ..."]}

    r = run_case(EvidencePreserving(), case, k=2, reader_factory=lambda: LLMReader(fake))
    assert not r.cua              # the hijacked value is refuted by the reference; nothing unsafe commits
    assert r.error is None
