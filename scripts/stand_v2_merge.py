"""Stand v2 merge: Claude-subagent verdicts + Gemini verdicts -> consensus eval set.

Judge A: Claude (Fable 5) subagents via Claude Code subscription, blind batches
runs/stand_v2_blind/batch_*.json -> runs/stand_v2_claude/batch_*.json ($0).
Judge B: Gemini 3.1 Pro via OpenRouter -> runs/stand_v2_gemini.partial.jsonl.
Bonus cross-check: 27 Opus-4.8 API verdicts from the aborted dual run.

Consensus (A==B, no PARSE_FAIL) -> data/eval/stand_v2_eval.json, truth =
consensus verdict; SB label kept as sb_verdict. Disagreements -> quarantine.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("f:/vuln-llm-research")


def norm(v):
    v = (v or "").strip().upper()
    if v in ("TP", "TRUE_POSITIVE"):
        return "TRUE_POSITIVE"
    if v in ("FP", "FALSE_POSITIVE"):
        return "FALSE_POSITIVE"
    return "PARSE_FAIL"


def main():
    pool = json.loads((ROOT / "data/exam/exam_a_in_scope_300.json").read_text(encoding="utf-8"))

    claude = {}
    for f in sorted((ROOT / "runs/stand_v2_claude").glob("batch_*.json")):
        for r in json.loads(f.read_text(encoding="utf-8")):
            claude[r["case_id"]] = {"verdict": norm(r["verdict"]), "reason": r.get("reason", "")}

    gemini = {}
    for ln in (ROOT / "runs/stand_v2_gemini.partial.jsonl").read_text(encoding="utf-8").splitlines():
        if ln.strip():
            r = json.loads(ln)
            gemini[r["case_id"]] = norm(r["gemini_verdict"])

    opus = {}
    dual = ROOT / "runs/stand_v2_raw.partial.jsonl"
    if dual.exists():
        for ln in dual.read_text(encoding="utf-8").splitlines():
            if ln.strip():
                r = json.loads(ln)
                opus[r["case_id"]] = norm(r["opus_verdict"])

    eval_out, quarantine = [], []
    n_both = 0
    for c in pool:
        m = c["metadata"]; cid = m["case_id"]
        cv = claude.get(cid, {}).get("verdict", "MISSING")
        gv = gemini.get(cid, "MISSING")
        if "MISSING" in (cv, gv):
            continue
        n_both += 1
        rec = {"case_id": cid, "claude_verdict": cv, "gemini_verdict": gv,
               "sb_verdict": norm(m.get("verdict")),
               "opus_verdict": opus.get(cid, ""),
               "claude_reason": claude[cid]["reason"]}
        if cv == gv and cv != "PARSE_FAIL":
            sysmsg = [x for x in c["messages"] if x["role"] == "system"][0]
            usermsg = [x for x in c["messages"] if x["role"] == "user"][0]
            eval_out.append({
                "messages": [sysmsg, usermsg],
                "metadata": {**m, "verdict": cv, "sb_verdict": rec["sb_verdict"],
                             "judges": "fable-5-subagent+gemini-3.1-pro",
                             "protocol": "blind"},
            })
        else:
            quarantine.append(rec)

    agree = len(eval_out)
    dist = Counter(e["metadata"]["verdict"] for e in eval_out)
    flips = sum(1 for e in eval_out
                if e["metadata"]["verdict"] != e["metadata"]["sb_verdict"])
    opus_overlap = [(cid, claude[cid]["verdict"]) for cid in opus if cid in claude]
    opus_agree = sum(1 for cid, cv in opus_overlap if cv == opus[cid])
    projects = Counter(e["metadata"]["project_id"] for e in eval_out)

    audit = {
        "judges": ["claude-fable-5-subagent (subscription, $0)",
                   "google/gemini-3.1-pro-preview (openrouter)"],
        "pool": "data/exam/exam_a_in_scope_300.json",
        "n_pool": len(pool), "n_both_judged": n_both,
        "n_consensus": agree, "n_quarantine": len(quarantine),
        "agreement_rate": round(agree / n_both, 4) if n_both else 0.0,
        "consensus_dist": dict(dist),
        "flips_vs_sb": flips,
        "flip_rate_vs_sb": round(flips / agree, 4) if agree else 0.0,
        "opus_crosscheck": {"n": len(opus_overlap),
                            "claude_opus_agree": opus_agree},
        "top_projects": projects.most_common(5),
        "n_projects": len(projects),
    }

    (ROOT / "data/eval/stand_v2_eval.json").write_text(
        json.dumps(eval_out, ensure_ascii=False, indent=1), encoding="utf-8")
    (ROOT / "runs/stand_v2_quarantine.json").write_text(
        json.dumps(quarantine, ensure_ascii=False, indent=1), encoding="utf-8")
    (ROOT / "runs/stand_v2_audit.json").write_text(
        json.dumps(audit, ensure_ascii=False, indent=1), encoding="utf-8")

    print(json.dumps(audit, ensure_ascii=False, indent=1))
    print(f"\neval -> data/eval/stand_v2_eval.json (n={agree})")
    print(f"quarantine -> runs/stand_v2_quarantine.json (n={len(quarantine)})")


if __name__ == "__main__":
    main()
