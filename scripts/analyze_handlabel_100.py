"""Cross-check the human-AI Pass-1 hand-labels (n=100) against the 3-judge
adjudication buckets and individual model verdicts on SastBench-250.

Per-bucket: agreement with SB / Sonnet / Gemini / v8.3.1 verdicts.
Headline: on strong_mislabel bucket, how often does AI-labeler side with the
frontier majority (Sonnet+Gemini) rather than the SB-truth.
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

ROOT = Path("f:/vuln-llm-research")
LABELS = ROOT / "data/exam/sastbench250_handlabel/ai_pass1_labels.jsonl"
MAP = ROOT / "data/exam/sastbench250_handlabel/hand_label_case_id_map.json"


def normalize(v: str) -> str:
    """Models emit TP/FP/TRUE_POSITIVE/FALSE_POSITIVE/etc. Map to canonical."""
    if not v:
        return ""
    v = v.upper().strip()
    if "TRUE" in v or v == "TP":
        return "TP"
    if "FALSE" in v or v == "FP":
        return "FP"
    return v


def main() -> None:
    labels = [json.loads(l) for l in LABELS.read_text(encoding="utf-8").splitlines() if l.strip()]
    cmap = json.loads(MAP.read_text(encoding="utf-8"))

    print(f"AI-labeler verdicts: {len(labels)}")
    print(f"Map entries: {len(cmap)}")
    print()

    merged = []
    for lab in labels:
        bid = lab["blind_id"]
        m = cmap.get(bid)
        if m is None:
            print(f"WARN no map for {bid}")
            continue
        merged.append({
            "blind_id": bid,
            "bucket": m["bucket"],
            "ai": normalize(lab["verdict"]),
            "confidence": lab["confidence"],
            "sb": normalize(m["sb_verdict"]),
            "sonnet": normalize(m["sonnet_verdict"]),
            "gemini": normalize(m["gemini_verdict"]),
            "ours": normalize(m["v8_3_1_verdict"]),
            "reasoning": lab["reasoning"],
            "original_case_id": m["original_case_id"],
        })

    # Per-bucket agreement matrix
    buckets = ["clean_consistent", "strong_mislabel", "one_frontier_dissent"]
    print(f"{'bucket':<25s} {'n':>4s}  {'AI=SB':>9s}  {'AI=Sonnet':>11s}  {'AI=Gemini':>11s}  {'AI=v8.3.1':>11s}  {'AI=frontier_maj':>17s}")
    print("-" * 95)
    for b in buckets:
        rows = [m for m in merged if m["bucket"] == b]
        n = len(rows)
        if n == 0:
            continue
        agree_sb = sum(1 for r in rows if r["ai"] == r["sb"])
        agree_son = sum(1 for r in rows if r["ai"] == r["sonnet"])
        agree_gem = sum(1 for r in rows if r["ai"] == r["gemini"])
        agree_ours = sum(1 for r in rows if r["ai"] == r["ours"])

        # frontier majority = if sonnet==gemini, that's the majority; else tie
        def frontier_maj(r):
            if r["sonnet"] == r["gemini"]:
                return r["sonnet"]
            return None

        agree_fm = sum(1 for r in rows if (fm := frontier_maj(r)) is not None and r["ai"] == fm)
        fm_total = sum(1 for r in rows if frontier_maj(r) is not None)

        print(f"{b:<25s} {n:>4d}  {agree_sb:>4d}/{n:<4d}  {agree_son:>5d}/{n:<5d}  {agree_gem:>5d}/{n:<5d}  {agree_ours:>5d}/{n:<5d}  {agree_fm:>6d}/{fm_total:<10d}")

    print()
    # Headline: strong_mislabel — does AI side with SB or with frontier majority?
    print("=" * 75)
    print("HEADLINE: strong_mislabel bucket")
    print("=" * 75)
    rows = [m for m in merged if m["bucket"] == "strong_mislabel"]
    sb_side = sum(1 for r in rows if r["ai"] == r["sb"])
    frontier_side = sum(1 for r in rows if r["ai"] == r["sonnet"] and r["ai"] == r["gemini"])
    other = len(rows) - sb_side - frontier_side
    print(f"n={len(rows)}")
    print(f"  AI sides with SB-truth        : {sb_side}/{len(rows)} = {sb_side/len(rows):.3f}")
    print(f"  AI sides with frontier majority: {frontier_side}/{len(rows)} = {frontier_side/len(rows):.3f}")
    print(f"  AI dissents from both         : {other}/{len(rows)} = {other/len(rows):.3f}")
    print()

    # Calibration: clean_consistent bucket — AI should agree with SB and frontier
    print("=" * 75)
    print("CALIBRATION: clean_consistent bucket (AI's own noise rate)")
    print("=" * 75)
    rows = [m for m in merged if m["bucket"] == "clean_consistent"]
    n = len(rows)
    if n:
        sb_agree = sum(1 for r in rows if r["ai"] == r["sb"])
        print(f"n={n}")
        print(f"  AI agrees with consensus SB+Sonnet+Gemini truth: {sb_agree}/{n} = {sb_agree/n:.3f}")
        print(f"  AI's own labeling noise rate                  : {(n-sb_agree)/n:.3f}")
        print()
        for r in rows:
            if r["ai"] != r["sb"]:
                print(f"  DISAGREE: {r['blind_id']} (conf={r['confidence']}) SB={r['sb']} AI={r['ai']}: {r['reasoning'][:120]}")
    print()

    # one_frontier_dissent: tie-breaker info
    print("=" * 75)
    print("TIE-BREAKER: one_frontier_dissent bucket")
    print("=" * 75)
    rows = [m for m in merged if m["bucket"] == "one_frontier_dissent"]
    n = len(rows)
    if n:
        sb_agree = sum(1 for r in rows if r["ai"] == r["sb"])
        son_agree = sum(1 for r in rows if r["ai"] == r["sonnet"])
        gem_agree = sum(1 for r in rows if r["ai"] == r["gemini"])
        print(f"n={n}")
        print(f"  AI sides with SB    : {sb_agree}/{n} = {sb_agree/n:.3f}")
        print(f"  AI sides with Sonnet: {son_agree}/{n} = {son_agree/n:.3f}")
        print(f"  AI sides with Gemini: {gem_agree}/{n} = {gem_agree/n:.3f}")

    # Confidence breakdown
    print()
    print("=" * 75)
    print("AI-labeler self-confidence distribution")
    print("=" * 75)
    by_conf = Counter(lab["confidence"] for lab in labels)
    for c in ("HIGH", "MEDIUM", "LOW"):
        print(f"  {c}: {by_conf[c]:>3d} / {len(labels)}")

    # v8.3.1 verdict baseline — what fraction of cases did our model side with AI-labeler?
    print()
    print("=" * 75)
    print("v8.3.1 vs AI-labeler agreement, by bucket")
    print("=" * 75)
    for b in buckets:
        rows = [m for m in merged if m["bucket"] == b]
        if not rows:
            continue
        agree = sum(1 for r in rows if r["ai"] == r["ours"])
        print(f"  {b:<25s}  v8.3.1=AI: {agree}/{len(rows)} = {agree/len(rows):.3f}")

    # Save merged for downstream
    out = ROOT / "data/exam/sastbench250_handlabel/ai_pass1_vs_all_judges.json"
    out.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nWrote merged join -> {out}")


if __name__ == "__main__":
    main()
