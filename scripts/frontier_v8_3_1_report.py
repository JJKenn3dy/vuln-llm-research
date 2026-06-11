"""Pre-committed-criteria comparison report for the frontier baseline.

Loads v8.3.1, Sonnet (triage + neutral), and Gemini outputs on the same
250 SastBench cases. Picks the better Sonnet variant (by point MCC),
computes cluster bootstrap MCC CI by repo_url for each, and applies the
pre-committed decision rule:

  "we beat frontier"   = v8.3.1 cluster CI lower bound >= frontier point MCC
  "we match frontier"  = mutual containment of point estimates within CIs
  "we lose to frontier"= frontier point MCC > v8.3.1 cluster CI upper bound

Also computes confusion intersection across all four configs: cases where
EVERY model is wrong relative to SastBench ground truth. Those are the
first candidates for hand-labeling investigation (likely bad benchmark
labels).
"""
from __future__ import annotations

import argparse
import json
import math
import random
from collections import defaultdict
from pathlib import Path
from typing import Optional


def _confusion(rows: list[dict]) -> tuple[int, int, int, int, int]:
    tp = fn = tn = fp = parse_fail = 0
    for r in rows:
        t, p = r["true_verdict"], r["predicted_verdict"]
        if p == "PARSE_FAIL":
            parse_fail += 1
            continue
        if t == "TRUE_POSITIVE" and p == "TRUE_POSITIVE":
            tp += 1
        elif t == "TRUE_POSITIVE" and p == "FALSE_POSITIVE":
            fn += 1
        elif t == "FALSE_POSITIVE" and p == "FALSE_POSITIVE":
            tn += 1
        elif t == "FALSE_POSITIVE" and p == "TRUE_POSITIVE":
            fp += 1
    return tp, fn, tn, fp, parse_fail


def _mcc(tp: int, fn: int, tn: int, fp: int) -> float:
    d = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return ((tp * tn) - (fp * fn)) / d if d else 0.0


def _ba(tp: int, fn: int, tn: int, fp: int) -> float:
    n_pos = tp + fn
    n_neg = tn + fp
    dr = tp / n_pos if n_pos else 0.0
    far = fp / n_neg if n_neg else 0.0
    return 0.5 * (dr + (1 - far))


def metrics_dict(rows: list[dict]) -> dict:
    tp, fn, tn, fp, pf = _confusion(rows)
    n_pos = tp + fn
    n_neg = tn + fp
    return {
        "n": len(rows),
        "TP": tp,
        "FN": fn,
        "TN": tn,
        "FP": fp,
        "PARSE_FAIL": pf,
        "DR": tp / n_pos if n_pos else 0.0,
        "FAR": fp / n_neg if n_neg else 0.0,
        "precision": tp / (tp + fp) if (tp + fp) else 0.0,
        "BA": _ba(tp, fn, tn, fp),
        "MCC": _mcc(tp, fn, tn, fp),
        "parse_fail_rate": pf / len(rows) if rows else 0.0,
    }


def cluster_bootstrap_mcc_ci(
    rows: list[dict],
    cluster_by: list[Optional[str]],
    n_boot: int = 2000,
    seed: int = 42,
) -> tuple[float, float]:
    rng = random.Random(seed)
    by_cluster: dict[str, list[dict]] = defaultdict(list)
    for r, c in zip(rows, cluster_by):
        by_cluster[c or "?"].append(r)
    clusters = list(by_cluster.keys())
    n_clusters = len(clusters)
    scores: list[float] = []
    for _ in range(n_boot):
        sampled = [rng.choice(clusters) for _ in range(n_clusters)]
        sample = [r for c in sampled for r in by_cluster[c]]
        tp, fn, tn, fp, _ = _confusion(sample)
        scores.append(_mcc(tp, fn, tn, fp))
    scores.sort()
    lo = scores[int(0.025 * n_boot)]
    hi = scores[int(0.975 * n_boot)]
    return lo, hi


def index_by_case_id(outputs: list[dict]) -> dict[str, dict]:
    out = {}
    for r in outputs:
        cid = r.get("case_id") or f"i_{r['i']}"
        out[cid] = r
    return out


def pick_sonnet_winner(sonnet_triage_path: Path, sonnet_neutral_path: Path) -> tuple[str, list[dict]]:
    triage = json.loads(sonnet_triage_path.read_text(encoding="utf-8"))
    neutral = json.loads(sonnet_neutral_path.read_text(encoding="utf-8"))
    m_triage = metrics_dict(triage)
    m_neutral = metrics_dict(neutral)
    if m_neutral["MCC"] > m_triage["MCC"]:
        return "neutral", neutral
    return "triage", triage


def confusion_intersection(
    *output_lists: list[dict],
) -> list[str]:
    """Case IDs where EVERY model is wrong vs ground truth."""
    by_case_lists = [index_by_case_id(o) for o in output_lists]
    all_ids = set(by_case_lists[0].keys())
    for d in by_case_lists[1:]:
        all_ids &= set(d.keys())
    wrong_ids = []
    for cid in sorted(all_ids):
        all_wrong = True
        for d in by_case_lists:
            r = d[cid]
            if r["predicted_verdict"] == r["true_verdict"]:
                all_wrong = False
                break
            if r["predicted_verdict"] == "PARSE_FAIL":
                pass  # still counts as not-matching ground truth
        if all_wrong:
            wrong_ids.append(cid)
    return wrong_ids


def decide(v8_lo: float, v8_hi: float, frontier_point: float) -> str:
    if v8_lo >= frontier_point:
        return "beat"
    if v8_hi < frontier_point:
        return "lose"
    return "match"


def repo_clusters(cases: list[dict]) -> dict[str, str]:
    return {c["metadata"]["case_id"]: c["metadata"].get("project_id", "?") for c in cases}


def cluster_seq(outputs: list[dict], case_to_repo: dict[str, str]) -> list[str]:
    return [case_to_repo.get(r.get("case_id") or f"i_{r['i']}", "?") for r in outputs]


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--frontier-dir", required=True)
    p.add_argument("--v8-3-1-outputs", required=True)
    p.add_argument("--cases", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--md", required=True)
    p.add_argument("--n-boot", type=int, default=2000)
    args = p.parse_args()

    fd = Path(args.frontier_dir)
    with open(args.cases, encoding="utf-8") as f:
        cases = json.load(f)
    case_to_repo = repo_clusters(cases)

    v8 = json.loads(Path(args.v8_3_1_outputs).read_text(encoding="utf-8"))
    sonnet_winner, sonnet = pick_sonnet_winner(
        fd / "sonnet_triage_outputs.json",
        fd / "sonnet_neutral_outputs.json",
    )
    gemini = json.loads((fd / "gemini_triage_outputs.json").read_text(encoding="utf-8"))

    m_v8 = metrics_dict(v8)
    m_sonnet = metrics_dict(sonnet)
    m_gemini = metrics_dict(gemini)

    ci_v8 = cluster_bootstrap_mcc_ci(v8, cluster_seq(v8, case_to_repo), args.n_boot)
    ci_sonnet = cluster_bootstrap_mcc_ci(sonnet, cluster_seq(sonnet, case_to_repo), args.n_boot)
    ci_gemini = cluster_bootstrap_mcc_ci(gemini, cluster_seq(gemini, case_to_repo), args.n_boot)

    decision_vs_sonnet = decide(ci_v8[0], ci_v8[1], m_sonnet["MCC"])
    decision_vs_gemini = decide(ci_v8[0], ci_v8[1], m_gemini["MCC"])

    all_wrong = confusion_intersection(v8, sonnet, gemini)

    report = {
        "criteria": {
            "beat": "v8.3.1 cluster CI lower bound >= frontier point MCC",
            "match": "frontier point MCC inside v8.3.1 CI",
            "lose": "frontier point MCC above v8.3.1 CI upper bound",
        },
        "v8_3_1": {**m_v8, "cluster_ci_mcc": [ci_v8[0], ci_v8[1]]},
        "sonnet_4_5": {
            "winner_prompt": sonnet_winner,
            "metrics": m_sonnet,
            "cluster_ci_mcc": [ci_sonnet[0], ci_sonnet[1]],
        },
        "gemini_2_5_pro": {
            "metrics": m_gemini,
            "cluster_ci_mcc": [ci_gemini[0], ci_gemini[1]],
        },
        "decision_vs_sonnet": decision_vs_sonnet,
        "decision_vs_gemini": decision_vs_gemini,
        "all_wrong_case_ids": all_wrong,
        "n_all_wrong": len(all_wrong),
    }

    Path(args.output).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    md = _render_md(report)
    Path(args.md).write_text(md, encoding="utf-8")
    print(md)


def _fmt(x: float, digits: int = 3) -> str:
    return f"{x:+.{digits}f}"


def _render_md(r: dict) -> str:
    lines = [
        "# Frontier baseline comparison on SastBench-250",
        "",
        "Same 250 cases, same parse regex, same cluster bootstrap by repo_url.",
        "",
        "## Pre-committed interpretation criteria",
        "",
        "- **beat**:  " + r["criteria"]["beat"],
        "- **match**: " + r["criteria"]["match"],
        "- **lose**:  " + r["criteria"]["lose"],
        "",
        "## Results (cluster bootstrap MCC CI by repo_url)",
        "",
        "| Model | MCC | Cluster CI | BA | FAR | DR | Precision | parse_fail |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for label, key, prompt_note in [
        ("v8.3.1 specialist", "v8_3_1", ""),
        (f"Sonnet 4.5 ({r['sonnet_4_5']['winner_prompt']} prompt won)", "sonnet_4_5", ""),
        ("Gemini 2.5 Pro (TRIAGE)", "gemini_2_5_pro", ""),
    ]:
        block = r[key]
        m = block.get("metrics", block)
        ci = block["cluster_ci_mcc"]
        lines.append(
            f"| {label} | {_fmt(m['MCC'])} | [{_fmt(ci[0])}, {_fmt(ci[1])}] | "
            f"{m['BA']:.3f} | {m['FAR']*100:.1f}% | {m['DR']*100:.1f}% | "
            f"{m['precision']*100:.1f}% | {m['parse_fail_rate']*100:.1f}% |"
        )
    lines += [
        "",
        f"## Decisions",
        "",
        f"- vs Sonnet 4.5: **{r['decision_vs_sonnet']}**",
        f"- vs Gemini 2.5 Pro: **{r['decision_vs_gemini']}**",
        "",
        f"## All-models-wrong cases (priority for hand-labeling)",
        "",
        f"n_all_wrong = {r['n_all_wrong']}",
        "",
        "These case IDs are where v8.3.1, Sonnet, and Gemini all disagree with",
        "the SastBench ground truth. Likely candidates for mislabeled benchmark",
        "cases; prioritize them in the 50-case hand-labeling round.",
        "",
    ]
    if r["all_wrong_case_ids"]:
        lines.append("```")
        for cid in r["all_wrong_case_ids"][:50]:
            lines.append(cid)
        if len(r["all_wrong_case_ids"]) > 50:
            lines.append(f"... ({len(r['all_wrong_case_ids']) - 50} more)")
        lines.append("```")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
