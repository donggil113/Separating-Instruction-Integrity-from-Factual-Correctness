# 03 · Schema: policy, fact, evidence, authority

Source: `epad/schema.py`, plus the resolver in `epad/defenses/base.py` and the monitor
in `epad/defenses/ep.py`. The four concepts are separate types, so a value cannot
change category silently.

```
 user request ──(trusted planner, P1)──▶ AuthorityGrant ─────────────────────────────┐
                                            │ templates, slots, conditions            │
 untrusted document ──(quarantined reader)──▶ Claim* ──┐                              │
                    └──────────────────────▶ Directive* (audit only, never executed)  │
 trusted user store (integrity, maybe stale) ▶ candidate ┤                            ▼
                                                        ▼                 instantiate(grant, facts)
                         reference ◀── verify(key = (entity from grant, attribute), value)
                             │                                                        │
                             └──▶ Evidence(CONFIRMED | REFUTED | CLOSE_MATCH | UNKNOWN)
                                          │                                           ▼
                                          └──(R2: CONFIRMED, exact value)──▶ FACT argument ──▶ monitor ──▶ commit
 deployment Policy (limits, sensitive markers) ──────────────────────────────────────────────▶ monitor
```

| concept | type | who can create it | what it can influence |
|---|---|---|---|
| **Authority** | `AuthorityGrant` → `ActionTemplate` → `ArgSlot` (+ `Condition`) | only the trusted planner, from the user request | *which* tools, *how many* calls per template, *which* counterparties, each argument's kind, and the condition under which a template may run |
| **Policy** | `Policy` | deployment configuration | global limits (maximum payment, sensitive-data markers) |
| **Fact** | `Claim(key=(entity, attribute), value, source, source_trust, authenticated, timestamp, phrasing)` | the quarantined reader (from documents) or a trusted-store read | at most the **value** of a FACT slot or condition whose entity the grant already fixed |
| **Evidence** | `Evidence(reference, key, value, verdict, mode)` | only the runtime, by calling a reference (`verify` or `lookup`) | whether a candidate value may be bound (R2) |
| (audit) | `Directive(source, text, requested_tool)` | the quarantined reader | nothing; recorded only |

## Argument slots

`ArgSlot.kind`:

* **`USER_FIXED`**: the value comes from the request itself, e.g. payee = "Acme Office
  Supplies" or destination = "Airport". Documents cannot change it; the monitor checks
  it (R1).
* **`FACT`**: the value is a fact about an entity fixed by the grant, e.g. Acme's
  account or the flight's departure time. An optional deterministic `transform` derives
  the argument (pickup = departure − 150 min; an arrival message from the arrival time).
  The monitor applies the same transform to the confirmed value before comparing.
* **`FREE`**: a low-risk value from the planner, constrained by a regex and a length
  limit (e.g. a payment reference). The monitor enforces the constraint. The metric also
  scans every committed argument, FREE ones included, for sensitive profile values.

`ArgSlot.role` (TARGET / CONTENT / QUANTITY / TIME / ITEM) is used only by the baselines,
whose provenance policies protect *targets* (CaMeL) or *critical* arguments (Fides
argument-level P-T). EP applies R2 to **every** FACT slot and condition fact, whatever
its role.

`ArgSlot.verify` (`VerifyRule`) is kept for the pre-audit variant. EP's current
resolver policy (`verify_store = "always"`) requires evidence for every FACT value, so
the rule no longer changes EP's behavior:

* `ALWAYS`: bind only a reference-confirmed value.
* `IF_UNTRUSTED_OR_CONFLICT`: under the pre-audit policy, an uncontested trusted-store
  value could bind unverified. The audit broke this shortcut (RT-EP-1/2, F1).

`Condition(fact, op, operand)` guards a template, e.g. "pay if amount ≤ 2,000". The
condition fact goes through the same R2 path as an argument, and the monitor
re-evaluates the condition from admissible facts before commit.

## The resolver: from candidates to a bound fact

Every design that verifies uses the same function, `resolve(...)`, under an explicit
`ResolvePolicy`. Differences between designs are therefore differences in *rules*, not
in search skill.

| field | EP (`EP_POLICY`) | meaning |
|---|---|---|
| `lookup_first` | `True` | If the reference supports lookup, fetch the current value keyed by the grant's entity before anything else. |
| `verify_store` | `"always"` | The user's store value is one more *candidate*; it binds only if the reference confirms it. (`"if_contested"` is the pre-audit shortcut.) |
| `order` | `"store_first"` | Verify the user's record first, then document values that differ from it (newest first). `"challengers_first"` is the reverse; results §13 compares the two. |
| `endorse` | `True` | A document value may bind when the reference CONFIRMS it (an IFC endorsement). `False` gives provenance-only binding (`EP w/o endorsement`, `Reference-only`, CaMeL's authority facts). |
| `require_unique` | `False` | If `True`, verify every candidate and bind only if exactly one is CONFIRMED (for name-match references; results row `EP (unique confirmation)`). |
| `fallback_after_refute` | `False` | The pre-audit bug, kept only for `EP v0`: after all challengers were refuted, the contested store value was bound unverified. |

Verdict handling:

* **CONFIRMED** binds the candidate (unless `require_unique` is set).
* **REFUTED** and **CLOSE_MATCH** move on to the next candidate. The refutation is
  logged and surfaced as a detected false claim.
* **UNKNOWN** (the reference does not cover the key) stops the search, and the fact
  stays unresolved.
* **Budget exhaustion** also leaves the fact unresolved.

An unresolved fact makes its template abstain (R3).

Equality is exact (`sandbox/world.py::_eq`): amounts are compared to the cent,
identifiers exactly except for grouping spaces, with no case folding; a string never
equals a number. The audit showed that the earlier tolerant comparison let a near-miss
value confirm (RT-EP-5).

## Why documents cannot grant authority

There is no code path from a `Claim`, `Directive` or document to an `AuthorityGrant`:

* The grant is built before any document is read.
* The reader's output types have no field for tools, counterparties or call counts.
* The reader is asked only about the grant's fact keys (`AuthorityGrant.fact_keys()`), so
  a claim about any other entity is never requested.
* The monitor re-checks every proposed call before commit (R1):
  * the call carries the index of the template it instantiates;
  * the tool and user-fixed arguments must match that template;
  * the call count must stay within the template's `max_calls`.

  This is defense in depth. EP's own executor never produces an out-of-grant call, and
  `tests/test_ep.py::test_R2_monitor_rejects_actions_outside_grant` and
  `tests/test_baselines.py::test_ep_monitor_rechecks_condition_and_template` show that
  the monitor would reject one.

The flip side is family D. When the user delegates the counterparty to a document ("pay
whoever the bill says"), the counterparty is a FACT with no grant-fixed entity behind it,
and EP refuses the legitimate bill as well as the tampered one (results §5).

## Why hash or provenance never certifies truth

* `Claim.authenticated` (e.g. a DKIM pass) and `Document.content_hash` exist as
  metadata only.
* The monitor admits a FACT value only if the episode log holds a `CONFIRMED` record, or
  a lookup, from the reference configured for exactly that key, for exactly that value
  after the slot's transform.
* `tests/test_ep.py::test_R2_monitor_rejects_provenance_or_unverified_basis` checks that
  the bases `provenance` and `untrusted`, and a confirmation from the *wrong* reference,
  are all rejected.
* `tests/test_baselines.py::test_ep_never_binds_contested_store_without_evidence` checks
  that a stale store challenged only by a false claim is not bound.

The *Provenance-as-truth* ablation shows why this matters. It commits the false value in
all 27 `B_false_auth` cases (a compromised authentic mailbox) and the stale value in 24
of 27 `C_change_unauth` cases (a legitimate notice sent over an unauthenticated channel).

## Entity binding (V3)

A verification query is always `verify(reference, (entity from the grant, attribute),
claimed value)`. If a document could choose the entity, the attacker's own account would
verify as the attacker's account. Confirmation-of-Payee answers "does this account belong
to *this name*", and the name must be the one the user authorized.

Name-match semantics also mean that CONFIRMED need not be unique: a mule opened under the
exact name confirms. This is why EP verifies the user's record first, and why the
guarantee is weaker for such references (`02_threat_model.md`, V1 caveat).

## Relation to IFC endorsement (credit)

In IFC terms, R2 is an **endorsement** rule: an untrusted value is promoted to trusted
for one use. Endorsement and declassification are classical IFC (Myers & Liskov 1997;
Myers, Sabelfeld & Zdancewic 2004). Fides (§5.2) describes a capacity-based endorsement
escape hatch, and CaMeL's policies are arbitrary predicates that could call a reference.
Banks run verify-before-pay (Confirmation-of-Payee, Verification-of-Payee) as standard
practice.

What EP pins down is only *which* endorsements are admissible: a confirmation of the
exact value, by the configured independent reference, for the exact key, with the entity
fixed by the user's grant, including for values from the user's own store. The results
show this rule, dropped into CaMeL, Fides, AgentSentry or the firewall, reproduces EP
case for case (`07_results.md`). The rule is the finding, not a new mechanism.
