# 03 · Schema: policy, fact, evidence, authority

Source: `epad/schema.py`. The four concepts are separate types, so a value cannot
change category silently.

```
             user request ──(trusted planner, P1)──▶ AuthorityGrant ──────────────┐
                                                        │ templates, slots          │
 untrusted document ──(quarantined reader)──▶ Claim* ───┤                           ▼
          │                                    Directive* (audit only)   instantiate(grant, facts)
          │                                             │                           │
          │                   reference ◀──verify(key from grant, claimed value)    │
          │                        │                                                ▼
          │                        └──────────▶ Evidence ──(rule R2)──▶ FACT argument ──▶ monitor ──▶ commit
 trusted user store ──────────────────────────▶ Claim (trusted, maybe stale) ──(R2: uncontested)──┘
 deployment Policy (limits, sensitive markers) ─────────────────────────────────────────────▶ monitor
```

| concept | type | who can create it | what it can influence |
|---|---|---|---|
| **Authority** | `AuthorityGrant` → `ActionTemplate` → `ArgSlot` | only the trusted planner, from the user request | *which* tools, *how many* calls, *which* counterparties, and each argument's kind |
| **Policy** | `Policy` | deployment configuration | global limits (max payment, sensitive data markers) |
| **Fact** | `Claim(key=(entity, attribute), value, source, source_trust, authenticated, timestamp, phrasing)` | quarantined reader (from documents) or a trusted store read | at most the **value** of a FACT slot whose entity the grant already fixed |
| **Evidence** | `Evidence(reference, key, value, verdict, mode)` | only the runtime, by calling a reference | whether a claimed value may be bound (R2) |
| (audit) | `Directive(source, text, requested_tool)` | quarantined reader | nothing; recorded only |

## Argument slots

`ArgSlot.kind`:

* `USER_FIXED`: the value comes from the request itself, e.g. payee = "Acme Office
  Supplies", destination = "Airport". Documents cannot change it.
* `FACT`: the value is a fact about an entity fixed by the grant, e.g. Acme's account or
  the flight's departure time. An optional deterministic `transform` derives the
  argument; for example, pickup = departure − 150 min.
* `FREE`: a low-risk value from the planner, constrained by a regex and a length limit
  (e.g. a payment reference).

`ArgSlot.role` (TARGET / CONTENT / QUANTITY / TIME / ITEM) is used only by the baselines.
Their provenance policies protect *targets* (CaMeL) or *critical* arguments (Fides-arg).
EP applies R2 to **every** FACT slot, whatever its role.

`ArgSlot.verify`:

* `ALWAYS`: bind only a reference-confirmed value.
* `IF_UNTRUSTED_OR_CONFLICT`: a trusted-store value may bind unverified only if no
  document claim contests it.

`Condition(fact, op, operand)` guards a template, e.g. "pay if amount ≤ 2,000". The
condition's fact goes through exactly the same R2 path as an argument.

## Why documents cannot grant authority

There is no code path from a `Claim`, `Directive` or document to an `AuthorityGrant`:

* The grant is built before any document is read.
* The reader's output types have no field for tools, counterparties or call counts.
* The reader is asked only about the grant's fact keys (`AuthorityGrant.fact_keys()`), so
  a claim about any other entity is never requested.
* The monitor re-checks each proposed call against the grant (R1) before commit. This is
  defense in depth: EP's own executor never produces an out-of-grant call, and
  `tests/test_ep.py::test_R2_monitor_rejects_actions_outside_grant` shows the monitor
  would reject one.

## Why hash or provenance never certifies truth

* `Claim.authenticated` (e.g. DKIM pass) and `Document.content_hash` exist as metadata.
* The monitor's admissible bases are only `evidence` / `reference_lookup` (a matching
  `CONFIRMED` record from the configured reference) and `trusted_store`.
* `tests/test_ep.py::test_R2_monitor_rejects_provenance_or_unverified_basis` checks that
  the bases `provenance` and `untrusted`, and a confirmation from the *wrong* reference,
  are all rejected.

The *Provenance-as-truth* ablation shows why this matters: it commits the false value in
all 27 B_false_auth cases (a compromised authentic mailbox), and the stale value in 24
of 27 C_change_unauth cases (a legitimate notice sent over an unauthenticated channel).

## Entity binding (V3)

A verification query is always `verify(reference, (entity from the grant, attribute),
claimed value)`. If a document could choose the entity, the attacker's own account would
verify as the attacker's account. Confirmation-of-Payee answers "does this account belong
to *this name*", and the name must be the one the user authorized.

## Relation to IFC endorsement (credit)

In IFC terms, R2 is an **endorsement** rule: an untrusted value is promoted to trusted
for one use. Endorsement and declassification are classical IFC (Myers & Liskov 1997;
Myers, Sabelfeld & Zdancewic 2004). Fides (§5.2) already describes a capacity-based
endorsement escape hatch. What EP pins down is only *which* endorsements are admissible:
a confirmation by an independent reference of the exact value, for the exact key, with
the entity fixed by the user's grant. See `01_related_work.md`.
