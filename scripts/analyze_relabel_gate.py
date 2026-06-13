"""Analyze the Path C critical re-labeler gate run.

Pre-committed criteria (see gpt53_critical_relabel_gate.py docstring):
  (a) relabeler <-> human agreement >= 68.7%   (blind 71.7% - 3 pp)
  (b) cave rate <= 25% on cases where blind GPT-5.3 contradicted the
      shipped SB label (cave = relabeler flips to the shipped label)

Also reported (not gating): relabeler vs gold-core, keep/reject volume,
confidence shifts vs blind run.
"""
import json
from pathlib import Path

ROOT = Path("f:/vuln-llm-research")
HL = ROOT / "data/exam/sastbench250_handlabel"


def norm(v):
    if v is None:
        return None
    v = str(v).strip().upper()
    if v in ("TP", "TRUE_POSITIVE"):
        return "TP"
    if v in ("FP", "FALSE_POSITIVE"):
        return "FP"
    return None


def main():
    merged = {r["blind_id"]: r for r in json.loads(
        (HL / "four_judge_merged.json").read_text(encoding="utf-8"))}
    relab = {}
    for line in (HL / "gpt53_relabeler_labels.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            relab[r["blind_id"]] = r

    rows = []
    for bid, m in merged.items():
        rl = relab.get(bid)
        if rl is None:
            continue
        rows.append({
            "bid": bid,
            "bucket": m["bucket"],
            "sb": norm(m["sb"]),
            "human": norm(m["human"]),
            "gpt53_blind": norm(m["gpt53"]),
            "relab": norm(rl["verdict"]),
            "relab_conf": rl["confidence"],
        })
    rows = [r for r in rows if r["relab"] is not None]
    n = len(rows)
    print(f"joined cases: {n} (of {len(relab)} relabeled)")

    # (a) agreement with human anchor
    h_rows = [r for r in rows if r["human"] is not None]
    agree_h = sum(r["relab"] == r["human"] for r in h_rows) / len(h_rows)
    blind_h = sum(r["gpt53_blind"] == r["human"] for r in h_rows
                  if r["gpt53_blind"] is not None) / sum(
        1 for r in h_rows if r["gpt53_blind"] is not None)
    print(f"\n(a) relabeler<->human = {agree_h:.1%} (n={len(h_rows)}); "
          f"blind<->human on same join = {blind_h:.1%}; threshold >= 68.7%")
    pass_a = agree_h >= 0.687

    # (b) cave rate: blind disagreed with shipped SB label
    disagreed = [r for r in rows if r["gpt53_blind"] is not None
                 and r["gpt53_blind"] != r["sb"]]
    caved = [r for r in disagreed if r["relab"] == r["sb"]]
    cave = len(caved) / len(disagreed) if disagreed else 0.0
    print(f"(b) cave rate = {len(caved)}/{len(disagreed)} = {cave:.1%}; threshold <= 25%")
    pass_b = cave <= 0.25

    # symmetric check: flips AWAY from shipped label (blind agreed, relab rejects)
    agreed = [r for r in rows if r["gpt53_blind"] is not None
              and r["gpt53_blind"] == r["sb"]]
    defected = [r for r in agreed if r["relab"] != r["sb"]]
    print(f"    flips away from label (context): {len(defected)}/{len(agreed)} = "
          f"{len(defected)/len(agreed):.1%}")

    # overall stability vs blind
    stable = sum(r["relab"] == r["gpt53_blind"] for r in rows
                 if r["gpt53_blind"] is not None)
    n_blind = sum(1 for r in rows if r["gpt53_blind"] is not None)
    print(f"    relabeler == blind verdict: {stable}/{n_blind} = {stable/n_blind:.1%}")

    # keep/reject volume
    kept = sum(r["relab"] == r["sb"] for r in rows)
    print(f"\nkeep shipped label: {kept}/{n} = {kept/n:.1%}; reject: {n-kept}/{n}")

    # vs gold-core (human==gpt53_blind)
    core = [r for r in rows if r["human"] is not None
            and r["gpt53_blind"] is not None and r["human"] == r["gpt53_blind"]]
    agree_core = sum(r["relab"] == r["human"] for r in core) / len(core)
    print(f"relabeler vs gold-core (n={len(core)}): {agree_core:.1%}")

    # per-bucket agreement with human
    print("\nper-bucket relabeler<->human:")
    for b in ("clean_consistent", "strong_mislabel", "one_frontier_dissent"):
        br = [r for r in h_rows if r["bucket"] == b]
        if br:
            a = sum(r["relab"] == r["human"] for r in br) / len(br)
            print(f"  {b:<22s} {a:.1%} (n={len(br)})")

    verdict = "PASS" if (pass_a and pass_b) else "FAIL"
    why = []
    if not pass_a:
        why.append("(a) human alignment below threshold")
    if not pass_b:
        why.append("(b) cave rate above threshold")
    print(f"\n=== GATE {verdict} {' & '.join(why)} ===")

    out = ROOT / "runs/relabel_gate_analysis.json"
    out.write_text(json.dumps({
        "n": n, "agree_human": agree_h, "blind_agree_human": blind_h,
        "cave_rate": cave, "cave_n": [len(caved), len(disagreed)],
        "defect_rate": len(defected) / len(agreed) if agreed else None,
        "stability_vs_blind": stable / n_blind,
        "keep_rate": kept / n, "agree_gold_core": agree_core,
        "gate": verdict,
    }, indent=2), encoding="utf-8")
    print(f"saved -> {out}")


if __name__ == "__main__":
    main()
