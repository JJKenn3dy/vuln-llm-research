"""4-judge cross-check on the 100 hand-label cases.

Joins:
  - SB (SastBench-shipped label)
  - Sonnet 4.5 verdict
  - Gemini 2.5 Pro verdict
  - v8.3.1 our model
  - Human Pass-1 (zakhar/AI-labeler in this session)
  - GPT-5.3-codex blind re-labeler

Reports per bucket:
  - Pairwise agreement matrix
  - "Frontier consensus" = Sonnet == Gemini == GPT-5.3-codex (3 independent
    frontiers all agree). On strong_mislabel, this is the cleanest signal
    of "SB is wrong" because it cannot be a one-frontier accident.
  - Human-vs-frontier-consensus agreement: triangulation strength
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

ROOT = Path("f:/vuln-llm-research")
HUMAN = ROOT / "data/exam/sastbench250_handlabel/ai_pass1_labels.jsonl"
GPT53 = ROOT / "data/exam/sastbench250_handlabel/gpt53_codex_labels.jsonl"
MAP = ROOT / "data/exam/sastbench250_handlabel/hand_label_case_id_map.json"


def normalize(v: str) -> str:
    if not v:
        return ""
    v = v.upper().strip()
    if "TRUE" in v or v == "TP":
        return "TP"
    if "FALSE" in v or v == "FP":
        return "FP"
    return v


def load_jsonl(p: Path) -> dict[str, dict]:
    out = {}
    if not p.exists():
        return out
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.strip():
            j = json.loads(line)
            out[j["blind_id"]] = j
    return out


def main() -> None:
    human = load_jsonl(HUMAN)
    gpt53 = load_jsonl(GPT53)
    cmap = json.loads(MAP.read_text(encoding="utf-8"))

    print(f"Human Pass-1: {len(human)}")
    print(f"GPT-5.3-codex: {len(gpt53)}")
    print(f"Map: {len(cmap)}")

    merged = []
    missing_human = 0
    missing_gpt = 0
    for bid, m in cmap.items():
        if bid not in human:
            missing_human += 1
            continue
        rec = {
            "blind_id": bid,
            "bucket": m["bucket"],
            "sb": normalize(m["sb_verdict"]),
            "sonnet": normalize(m["sonnet_verdict"]),
            "gemini": normalize(m["gemini_verdict"]),
            "ours": normalize(m["v8_3_1_verdict"]),
            "human": normalize(human[bid]["verdict"]),
            "human_conf": human[bid]["confidence"],
        }
        if bid in gpt53:
            rec["gpt53"] = normalize(gpt53[bid]["verdict"])
            rec["gpt53_conf"] = gpt53[bid]["confidence"]
            rec["gpt53_solv"] = gpt53[bid].get("solvable", "?")
        else:
            rec["gpt53"] = "?"
            missing_gpt += 1
        merged.append(rec)
    print(f"Missing human: {missing_human}, Missing gpt-5.3: {missing_gpt}")
    n_full = sum(1 for r in merged if r["gpt53"] in ("TP", "FP"))
    print(f"Cases with all 6 verdicts: {n_full}")
    print()

    buckets = ["clean_consistent", "strong_mislabel", "one_frontier_dissent"]

    # Pairwise agreement table
    judges = ["sb", "sonnet", "gemini", "ours", "human", "gpt53"]
    print("=" * 90)
    print("PAIRWISE AGREEMENT (full sample, only cases with all 6 verdicts)")
    print("=" * 90)
    full_rows = [r for r in merged if r["gpt53"] in ("TP", "FP")]
    print(f"n = {len(full_rows)}")
    header = "  ".join(f"{j:>8s}" for j in judges)
    print(f"          {header}")
    for j1 in judges:
        row = [f"{j1:<8s}"]
        for j2 in judges:
            if j1 == j2:
                row.append(f"{'-':>8s}")
            else:
                agree = sum(1 for r in full_rows if r[j1] == r[j2])
                row.append(f"{agree/len(full_rows)*100:>7.1f}%")
        print("  ".join(row))
    print()

    # Per-bucket pairwise vs SB
    for b in buckets:
        rows = [r for r in merged if r["bucket"] == b and r["gpt53"] in ("TP", "FP")]
        n = len(rows)
        if not n:
            continue
        print(f"--- bucket={b} (n={n}) ---")
        for j in ("sonnet", "gemini", "gpt53", "ours", "human"):
            agree_sb = sum(1 for r in rows if r[j] == r["sb"]) / n
            print(f"  {j:>8s} agrees with SB-truth: {agree_sb:.3f}")
        # Three-frontier consensus rate
        triad_match = sum(1 for r in rows if r["sonnet"] == r["gemini"] == r["gpt53"])
        triad_against_sb = sum(1 for r in rows if r["sonnet"] == r["gemini"] == r["gpt53"] and r["sonnet"] != r["sb"])
        print(f"  3-frontier consensus (S=G=G53): {triad_match}/{n} = {triad_match/n:.3f}")
        if triad_match:
            print(f"  3-frontier consensus AGAINST SB: {triad_against_sb}/{triad_match} = {triad_against_sb/triad_match:.3f}")
            # Human agreement with the 3-frontier consensus when it exists
            triad_rows = [r for r in rows if r["sonnet"] == r["gemini"] == r["gpt53"]]
            human_aligns = sum(1 for r in triad_rows if r["human"] == r["sonnet"])
            print(f"  Human aligns with 3-frontier consensus: {human_aligns}/{triad_match} = {human_aligns/triad_match:.3f}")
        print()

    # Headline: strong_mislabel — how robust is the "frontier disagrees with SB" claim
    # when we add a 3rd independent frontier?
    print("=" * 90)
    print("HEADLINE (strong_mislabel): does adding GPT-5.3-codex confirm or kill the noise claim?")
    print("=" * 90)
    rows = [r for r in merged if r["bucket"] == "strong_mislabel" and r["gpt53"] in ("TP", "FP")]
    n = len(rows)
    if n:
        # The original strong_mislabel = Sonnet==Gemini != SB. Does GPT-5.3 join them?
        triad_agree = sum(1 for r in rows if r["sonnet"] == r["gemini"] == r["gpt53"])
        gpt_with_sb = sum(1 for r in rows if r["gpt53"] == r["sb"])
        gpt_with_frontier = sum(1 for r in rows if r["gpt53"] == r["sonnet"])  # Sonnet==Gemini in this bucket
        print(f"n={n}")
        print(f"  GPT-5.3 joins Sonnet+Gemini (triad against SB): {triad_agree}/{n} = {triad_agree/n:.3f}")
        print(f"  GPT-5.3 sides with SB instead              : {gpt_with_sb}/{n} = {gpt_with_sb/n:.3f}")
        print()
        # Human ground-truth on that triad: does human align?
        triad_rows = [r for r in rows if r["sonnet"] == r["gemini"] == r["gpt53"]]
        if triad_rows:
            human_align_triad = sum(1 for r in triad_rows if r["human"] == r["sonnet"])
            print(f"  On triad-against-SB ({len(triad_rows)} cases), human also rejects SB: {human_align_triad}/{len(triad_rows)} = {human_align_triad/len(triad_rows):.3f}")
            print(f"  -> '4 independent voices reject SB' rate on strong_mislabel: {human_align_triad}/{n} = {human_align_triad/n:.3f}")

    # Calibration: gpt-5.3 noise floor
    print()
    print("=" * 90)
    print("GPT-5.3-codex calibration on clean_consistent bucket")
    print("=" * 90)
    rows = [r for r in merged if r["bucket"] == "clean_consistent" and r["gpt53"] in ("TP", "FP")]
    n = len(rows)
    if n:
        agree_consensus = sum(1 for r in rows if r["gpt53"] == r["sb"])  # SB==Sonnet==Gemini on this bucket
        print(f"  n={n}")
        print(f"  GPT-5.3 agrees with consensus truth: {agree_consensus}/{n} = {agree_consensus/n:.3f}")
        print(f"  GPT-5.3 own noise floor            : {(n-agree_consensus)/n:.3f}")

    # Save merged
    out = ROOT / "data/exam/sastbench250_handlabel/four_judge_merged.json"
    out.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nWrote 4-judge merge -> {out}")

    # Confidence distribution
    print()
    print("=" * 90)
    print("GPT-5.3-codex self-confidence distribution")
    print("=" * 90)
    confs = Counter(r["gpt53_conf"] for r in merged if r.get("gpt53_conf"))
    for c in ("HIGH", "MEDIUM", "LOW"):
        print(f"  {c}: {confs.get(c, 0)}")


if __name__ == "__main__":
    main()
