"""Assumption-violation stress tests (the guarantee boundary).

EP's claims hold only under V1-V3 and P1 (docs/02_threat_model.md). These
transforms deliberately break an assumption on otherwise identical cases, so
the report can show what fails and how. They are never mixed into the main
results.

  V1_stale_reference   C cases: the reference has not yet learned the legitimate change
  V2_poisoned_reference B cases: the attacker can write the reference (it confirms the false value)
  V1_reference_outage  all cases: the reference does not cover the manipulated fact (UNKNOWN)
"""
from __future__ import annotations

import copy
from typing import Optional

from epad.cases.variants import Case


def _ref_for(case: Case, key):
    name = case.spec.reference_for(key)
    return case.world.references.get(name) if name else None


def _change_key(case: Case):
    keys = list(case.gt.stale_values) or list(case.gt.false_values)
    return keys[0] if keys else None


def stale_reference(case: Case) -> Optional[Case]:
    if case.family != "C":
        return None
    c = copy.deepcopy(case)
    key = _change_key(c)
    ref = _ref_for(c, key)
    if ref is None:
        return None
    ref.table[key] = c.gt.stale_values[key][0]
    c.case_id += "+V1_stale_reference"
    return c


def poisoned_reference(case: Case) -> Optional[Case]:
    if case.family != "B":
        return None
    c = copy.deepcopy(case)
    key = _change_key(c)
    ref = _ref_for(c, key)
    if ref is None:
        return None
    ref.table[key] = c.gt.false_values[key][-1]
    c.case_id += "+V2_poisoned_reference"
    return c


def reference_outage(case: Case) -> Optional[Case]:
    c = copy.deepcopy(case)
    for key in c.spec.grant.fact_keys():
        ref = _ref_for(c, key)
        if ref is not None:
            ref.table.pop(key, None)
    c.case_id += "+V1_reference_outage"
    return c


SAME_PRINCIPAL_REFS = {"org_calendar", "supplier_catalog", "compatibility_checker", "airline_status",
                       "restaurant_reservations"}   # run by the same party whose authenticated mailbox is in the case


def same_principal_compromise(case: Case) -> Optional[Case]:
    """B_false_auth where the reference belongs to the same principal as the compromised mailbox (audit BV-8)."""
    if case.variant != "B_false_auth":
        return None
    key = _change_key(case)
    if case.spec.reference_for(key) not in SAME_PRINCIPAL_REFS:
        return None
    return poisoned_reference(case)


STRESS = {"V2_same_principal_compromise": same_principal_compromise, "V1_stale_reference": stale_reference, "V2_poisoned_reference": poisoned_reference,
          "V1_reference_outage": reference_outage}
