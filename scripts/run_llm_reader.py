"""LLM-in-the-loop track for the READER role (not run in this repository's results).

Replaces the scripted quarantined reader with a real model for the plan-first
designs and reports (a) end-to-end metrics and (b) reader behaviour against the
scripted honest reader: hijack rate on reader payloads, recall of request-phrased
facts, and claims leaked from directives.

    pip install anthropic
    export EPAD_READER_MODEL=<a Claude model id>      # no default on purpose
    python scripts/run_llm_reader.py [--seeds 0] [--k 2]
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from epad.cases.variants import build_suite                       # noqa: E402
from epad.defenses.registry import all_defenses                   # noqa: E402
from epad.eval.report import by, fmt, md_table, summarize, write_csv  # noqa: E402
from epad.eval.runner import run_case                              # noqa: E402
from epad.llm_reader import LLMReader, anthropic_complete_json     # noqa: E402

PLAN_FIRST = ["CaMeL (as evaluated)", "CaMeL (strong plan)", "Fides (strong plan)", "Provenance-as-truth",
              "CaMeL + endorsement (all fact args)", "Fides shell + EP resolver (typed hatch)", "EP (ours)"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[0])
    ap.add_argument("--k", type=int, default=2)
    args = ap.parse_args()
    complete = anthropic_complete_json()
    factory = lambda: LLMReader(complete)
    cases = build_suite(seeds=tuple(args.seeds))
    defenses = [d for d in all_defenses() if d.name in PLAN_FIRST]
    missing = set(PLAN_FIRST) - {d.name for d in defenses}
    if missing:
        raise SystemExit(f"unknown defense names: {sorted(missing)}")
    rs = [run_case(d, c, args.k, reader_factory=factory) for d in defenses for c in cases]
    out = os.path.join(os.path.dirname(__file__), "..", "results")
    os.makedirs(out, exist_ok=True)
    write_csv(os.path.join(out, "llm_reader.csv"), rs, {"reader": "llm"})
    rows = []
    for d in PLAN_FIRST:
        m = summarize([r for r in rs if r.defense == d])
        rows.append([d, fmt(m["util_clean"]), fmt(m["util_A"]), fmt(m["util_B"]), fmt(m["util_C"]),
                     fmt(m["cua_A"]), fmt(m["cua_B"]), fmt(m["cua_C"]), fmt(m["over_refusal_clean_C"])])
    table = md_table(["defense", "util clean", "util A", "util B", "util C", "CUA A", "CUA B", "CUA C",
                      "over-refusal"], rows)
    with open(os.path.join(out, "LLM_READER.md"), "w") as f:
        f.write(f"# LLM reader track (model from EPAD_READER_MODEL, k={args.k}, seeds={args.seeds})\n\n{table}\n")
    print(table)


if __name__ == "__main__":
    main()
