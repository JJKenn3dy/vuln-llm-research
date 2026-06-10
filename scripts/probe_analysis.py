"""Read sufficiency_probe output + render gate decision tree.

Format:
  - per-arm headline table (with safe format specs)
  - (a) vs (b) gate verdict (does evidence packet move BA / MCC?)
  - (a) vs (a') verdict (does TRIAGE prompt bias matter?)
  - human-on-snippet (h) vs Sonnet-on-snippet (a) (model-proxy disclaimer)
  - per-slice disaggregation
  - bootstrap CIs
  - confusion-matrix breakdown for each arm
  - which decision branch the result implies (from project_v8_3_plan.md)
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


GATE_TREE = """\
=== Decision branches (from project_v8_3_plan.md) ===
  Branch 1: (a) ≈ random AND (b) jumps
    → snippet insufficient; evidence packet is the missing piece
    → Sprint 2 (evidence packet pipeline) becomes prerequisite to v8.3
  Branch 2: (a) ≈ (a') ≈ (b) ≈ random
    → frontier also can't solve in single-call; this is a new task class
    → re-position pitch around "we created a new triage category"
  Branch 3: (a) ≈ (b) ≈ 0.7+ AND v8.2 stays at 0.1
    → snippet sufficient; our overfit is structural artifact problem
    → v8.3 multi-source mix + LOSO + CVE dedup is the right cure
  Branch 4: (a) < (a') on Sonnet
    → TRIAGE prompt biases frontier downward
    → prompt rework needed before v8.3 train
"""


def fmt_metric_row(name: str, arm: dict) -> str:
    n = arm["n"]
    ba = arm["ba"]
    ba_ci = arm.get("ba_ci95") or [None, None]
    mcc = arm["mcc"]
    mcc_ci = arm.get("mcc_ci95") or [None, None]
    pf = arm["parse_fail"]

    ba_ci_str = f"[{ba_ci[0]:.2f},{ba_ci[1]:.2f}]" if ba_ci[0] is not None else "(n<10)"
    mcc_sign = "+" if mcc >= 0 else ""
    mcc_str = f"{mcc_sign}{mcc:.3f}"
    mcc_ci_str = (
        f"[{'+' if mcc_ci[0] >= 0 else ''}{mcc_ci[0]:.2f},"
        f"{'+' if mcc_ci[1] >= 0 else ''}{mcc_ci[1]:.2f}]"
        if mcc_ci[0] is not None else "(n<10)"
    )
    return f"  {name:<38} {n:>3}  {ba:.3f}  {ba_ci_str:<14}  {mcc_str:>7}  {mcc_ci_str:<16}  {pf:>2}"


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--probe", required=True)
    args = p.parse_args()

    r = json.loads(Path(args.probe).read_text(encoding="utf-8"))
    meta = r["meta"]

    print("=" * 80)
    print("Sufficiency probe report")
    print("=" * 80)
    print(f"Created: {meta['created_at']}")
    print(f"n cases: {meta['n_scaffold']}")
    print(f"Solvable distribution (per scaffold): {meta['scaffold_solvable_dist']}")
    print(f"Ground-truth verdict distribution: {meta['scaffold_verdict_dist']}")
    print(f"Compliance distribution: {meta['scaffold_compliance_dist']}")
    if meta.get("fp_taxonomy_dist"):
        print(f"FP taxonomy distribution: {meta['fp_taxonomy_dist']}")
    print(f"Human-on-snippet vs full-context flips:")
    for combo, n in meta.get("human_snippet_only_vs_full_context", {}).items():
        print(f"  {combo}: {n}")
    print()

    print("=" * 80)
    print("Per-arm overall metrics")
    print("=" * 80)
    print(f"  {'arm':<38} {'n':>3}  {'BA':<5}  {'BA 95% CI':<14}  {'MCC':>7}  {'MCC 95% CI':<16}  pf")
    for arm_name, arm in r["arms"].items():
        print(fmt_metric_row(arm_name, arm))
    print()

    # Strict-compliant (b) variant
    print("=" * 80)
    print("Strict (b) — compliant cases only (mechanically-extracted evidence works)")
    print("=" * 80)
    found_strict = False
    for arm_name, arm in r["arms"].items():
        sb = arm.get("strict_compliant_only")
        if sb:
            found_strict = True
            ba_ci = sb.get("ba_ci95") or [None, None]
            mcc = sb["mcc"]
            ba_ci_str = f"[{ba_ci[0]:.2f},{ba_ci[1]:.2f}]" if ba_ci[0] is not None else "(n<10)"
            mcc_sign = "+" if mcc >= 0 else ""
            print(f"  {arm_name:<38} {sb['n']:>3}  BA={sb['ba']:.3f} {ba_ci_str}  MCC={mcc_sign}{mcc:.3f}")
    if not found_strict:
        print("  (no strict-compliant subset reported)")
    print()

    # Gate decision logic
    print("=" * 80)
    print("Gate analysis")
    print("=" * 80)
    arms = r["arms"]
    a = arms.get("a_triage_snippet_sonnet") or {}
    aprime = arms.get("aprime_neutral_snippet_sonnet") or {}
    b = arms.get("b_triage_evidence_sonnet") or {}
    h = arms.get("h_human_snippet_blind") or {}

    def diff_ba(x, y):
        return (x.get("ba") or 0) - (y.get("ba") or 0)
    def diff_mcc(x, y):
        return (x.get("mcc") or 0) - (y.get("mcc") or 0)

    print(f"v8.2 on SastBench-250 reference: BA=0.559  MCC=+0.100  (from prior eval)")
    print()
    print(f"  (a) TRIAGE snippet Sonnet:    BA={a.get('ba',0):.3f}  MCC={a.get('mcc',0):+.3f}")
    print(f"  (a') neutral snippet Sonnet:  BA={aprime.get('ba',0):.3f}  MCC={aprime.get('mcc',0):+.3f}")
    print(f"  (b) TRIAGE + evidence Sonnet: BA={b.get('ba',0):.3f}  MCC={b.get('mcc',0):+.3f}")
    print(f"  (h) Sonnet-as-judge blind:    BA={h.get('ba',0):.3f}  MCC={h.get('mcc',0):+.3f}")
    print()
    print(f"  Δ (b) − (a)   = ΔBA {diff_ba(b,a):+.3f}  ΔMCC {diff_mcc(b,a):+.3f}    (evidence-packet effect)")
    print(f"  Δ (a) − (a')  = ΔBA {diff_ba(a,aprime):+.3f}  ΔMCC {diff_mcc(a,aprime):+.3f}    (TRIAGE-prompt bias)")
    print(f"  Δ (a) − (h)   = ΔBA {diff_ba(a,h):+.3f}  ΔMCC {diff_mcc(a,h):+.3f}    (model-proxy framing artifact)")
    print()

    # Pick branch
    print("=" * 80)
    print("Branch verdict")
    print("=" * 80)
    a_ba = a.get("ba", 0)
    b_ba = b.get("ba", 0)
    aprime_ba = aprime.get("ba", 0)
    b_a_gap = diff_ba(b, a)
    a_aprime_gap = diff_ba(a, aprime)

    if a_ba < 0.55 and b_ba >= 0.65 and b_a_gap >= 0.10:
        verdict = "Branch 1 — snippet insufficient, evidence packet works (jumps BA ≥ 0.10)"
    elif a_ba < 0.55 and b_ba < 0.55 and aprime_ba < 0.55:
        verdict = "Branch 2 — all single-call frontier ≈ random → new task class"
    elif a_ba >= 0.65 and b_ba >= 0.65 and b_a_gap < 0.10:
        verdict = "Branch 3 — snippet sufficient; v8.2 has structural artifact problem"
    elif abs(a_aprime_gap) >= 0.10:
        verdict = "Branch 4 — TRIAGE prompt biases Sonnet (gap ≥ 0.10)"
    else:
        verdict = "Mixed signal — see full report; manual interpretation needed"
    print(f"  → {verdict}")
    print()

    print(GATE_TREE)

    # Slices
    print("=" * 80)
    print("Disaggregation by solvable_from_snippet (HINTS at n_per_slice ≈ 15-25)")
    print("=" * 80)
    for arm_name, arm in r["arms"].items():
        slices = arm.get("by_solvable_from_snippet") or {}
        if not slices:
            continue
        print(f"\n  {arm_name}:")
        for key in ("yes", "no", "disputed"):
            if key in slices:
                d = slices[key]
                mcc_sign = "+" if d["mcc"] >= 0 else ""
                print(f"    {key:<10} n={d['n']:<3}  BA={d['ba']:.3f}  MCC={mcc_sign}{d['mcc']:.3f}")


if __name__ == "__main__":
    main()
