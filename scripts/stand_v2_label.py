"""Stand v2: blind dual-judge relabel of exam_a for a trusted confirmation set.

Purpose (docs/AUDIT_FULL_2026-07-02.md, step 1): exp5's 0.695 was selected on
gold-core n=71 whose judge (GPT-5.3) shares a family with exp5's teacher
(GPT-5.5). Stand v2 breaks that: judges are Opus 4.8 (Anthropic) and
Gemini 3.1 Pro (Google), both independent of the teacher pair GPT-5.5+GLM-5.2.

Pool: data/exam/exam_a_in_scope_300.json — carved 2026-06-10 from val558,
NEVER loaded by any eval/diagnostic script (verified 2026-07-03), so it is
untouched by exp2-exp9 model selection. SB labels are kept as sb_verdict for
reference only; truth = judge consensus (blind, label hidden).

Known limitation (documented, accepted): consensus-of-two inherits the judges'
correlation and biases toward unambiguous cases, same as gold-core did. This
stand confirms/denies exp5 at coarse resolution; it is not absolute truth.

Outputs (prefix default runs/stand_v2):
  <prefix>_eval.json        consensus cases, eval format (metadata.verdict = consensus)
  <prefix>_quarantine.json  judge disagreements + parse fails
  <prefix>_audit.json       agreement/flip/cost summary
Resume: <prefix>_raw.partial.jsonl. Budget guard: hard stop at --budget.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("f:/vuln-llm-research")
sys.path.insert(0, str(ROOT / "scripts"))
from gpt53_relabel_handlabel100 import find_token  # noqa: E402

OR_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
JUDGE_A = "anthropic/claude-opus-4.8"
JUDGE_B = "google/gemini-3.1-pro-preview"

VERDICT_RE = re.compile(r"Verdict:\s*(TRUE_POSITIVE|FALSE_POSITIVE|TP|FP)", re.I)


def norm(v):
    v = (v or "").strip().upper()
    if v in ("TP", "TRUE_POSITIVE"):
        return "TRUE_POSITIVE"
    if v in ("FP", "FALSE_POSITIVE"):
        return "FALSE_POSITIVE"
    return "PARSE_FAIL"


def call(token, model, system, user, max_tokens=1500, retry=3):
    body = json.dumps({
        "model": model,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "max_tokens": max_tokens,
        "reasoning": {"effort": "low"},
    }).encode("utf-8")
    req = urllib.request.Request(
        OR_ENDPOINT, data=body, method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                 "HTTP-Referer": "https://github.com/JJKenn3dy/vuln-llm-research",
                 "X-Title": "stand v2 dual-judge labeling"})
    last = None
    for attempt in range(retry):
        try:
            with urllib.request.urlopen(req, timeout=180) as resp:
                d = json.loads(resp.read().decode("utf-8"))
            msg = d["choices"][0]["message"]
            raw = (msg.get("content") or msg.get("reasoning") or "").strip()
            cost = (d.get("usage", {}) or {}).get("cost", 0.0) or 0.0
            return raw, cost
        except urllib.error.HTTPError as e:
            m = (e.read()[:200].decode("utf-8", "replace") if hasattr(e, "read") else "")
            last = f"HTTP {e.code}: {m}"
            if e.code == 402:
                raise RuntimeError(f"OUT_OF_CREDITS: {last}")
            if e.code in (429, 500, 502, 503, 504):
                time.sleep(2 * (2 ** attempt)); continue
            raise RuntimeError(last)
        except Exception as e:  # noqa: BLE001
            last = str(e); time.sleep(2 * (2 ** attempt))
    raise RuntimeError(f"failed after {retry}: {last}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", default="data/exam/exam_a_in_scope_300.json")
    ap.add_argument("--n", type=int, default=0, help="0 = all cases, pool order")
    ap.add_argument("--balanced-smoke", type=int, default=0,
                    help="N cases, N/2 per SB class (smoke only; full run uses pool order)")
    ap.add_argument("--prefix", default="runs/stand_v2")
    ap.add_argument("--budget", type=float, default=7.0)
    ap.add_argument("--max-tokens", type=int, default=1500)
    args = ap.parse_args()

    token = find_token()
    pool = json.loads((ROOT / args.pool).read_text(encoding="utf-8"))
    if args.balanced_smoke:
        half = args.balanced_smoke // 2
        tp = [c for c in pool if norm(c["metadata"]["verdict"]) == "TRUE_POSITIVE"]
        fp = [c for c in pool if norm(c["metadata"]["verdict"]) == "FALSE_POSITIVE"]
        sample = tp[:half] + fp[:args.balanced_smoke - half]
    else:
        sample = pool[:args.n] if args.n else pool
    by_cid = {c["metadata"]["case_id"]: c for c in sample}

    raw_partial = ROOT / f"{args.prefix}_raw.partial.jsonl"
    done = {}
    if raw_partial.exists():
        for ln in raw_partial.read_text(encoding="utf-8").splitlines():
            if ln.strip():
                r = json.loads(ln); done[r["case_id"]] = r

    spent = 0.0
    raws = []
    for i, c in enumerate(sample):
        m = c["metadata"]; cid = m["case_id"]
        if cid in done:
            raws.append(done[cid]); spent += done[cid].get("cost", 0.0); continue
        if spent > args.budget:
            print(f"  [BUDGET STOP] ${spent:.2f} > ${args.budget} at {i}/{len(sample)}"); break
        system = [x for x in c["messages"] if x["role"] == "system"][0]["content"]
        user = [x for x in c["messages"] if x["role"] == "user"][0]["content"]
        try:
            a_raw, a_cost = call(token, JUDGE_A, system, user, args.max_tokens)
            b_raw, b_cost = call(token, JUDGE_B, system, user, args.max_tokens)
        except RuntimeError as e:
            if "OUT_OF_CREDITS" in str(e):
                print(f"  [402] out of credits at {i}/{len(sample)}"); break
            print(f"  {cid}: ERROR {e}"); continue
        av = VERDICT_RE.search(a_raw); av = norm(av.group(1)) if av else "PARSE_FAIL"
        bv = VERDICT_RE.search(b_raw); bv = norm(bv.group(1)) if bv else "PARSE_FAIL"
        cost = a_cost + b_cost
        spent += cost
        rec = {"case_id": cid, "claimed_cwe": m.get("claimed_cwe", ""),
               "sb_verdict": norm(m.get("verdict")), "opus_verdict": av,
               "gemini_verdict": bv, "opus_raw": a_raw, "gemini_raw": b_raw,
               "cost": cost, "agree": av == bv and av != "PARSE_FAIL"}
        raws.append(rec)
        with raw_partial.open("a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        tag = f"AGREE={av[:2]}" if rec["agree"] else f"DIFF(o={av[:2]},g={bv[:2]})"
        print(f"  {i+1:>3d}/{len(sample)} {cid[:26]:<26} {m.get('claimed_cwe',''):<8} "
              f"{tag:<16} ${spent:.2f}")

    n = len(raws)
    agree = [r for r in raws if r["agree"]]
    eval_out, quarantine = [], []
    for r in raws:
        if not r["agree"]:
            quarantine.append(r); continue
        c = by_cid[r["case_id"]]
        sysmsg = [x for x in c["messages"] if x["role"] == "system"][0]
        usermsg = [x for x in c["messages"] if x["role"] == "user"][0]
        eval_out.append({
            "messages": [sysmsg, usermsg],
            "metadata": {**c["metadata"], "verdict": r["opus_verdict"],
                         "sb_verdict": r["sb_verdict"],
                         "judges": "opus-4.8+gemini-3.1-pro", "protocol": "blind"},
        })
    label_dist = Counter(r["opus_verdict"] for r in agree)
    audit = {
        "judges": [JUDGE_A, JUDGE_B], "pool": args.pool, "n_requested": len(sample),
        "n_done": n, "spent_usd": round(spent, 4), "n_agree": len(agree),
        "n_quarantine": len(quarantine),
        "agreement_rate": round(len(agree) / n, 4) if n else 0.0,
        "consensus_label_dist": dict(label_dist),
        "vs_sb_flip_rate": round(
            sum(1 for r in agree if r["opus_verdict"] != r["sb_verdict"]) / len(agree), 4
        ) if agree else 0.0,
        "parse_fail_cases": [r["case_id"] for r in raws
                             if "PARSE_FAIL" in (r["opus_verdict"], r["gemini_verdict"])],
    }
    (ROOT / f"{args.prefix}_eval.json").write_text(
        json.dumps(eval_out, ensure_ascii=False, indent=2), encoding="utf-8")
    (ROOT / f"{args.prefix}_quarantine.json").write_text(
        json.dumps(quarantine, ensure_ascii=False, indent=2), encoding="utf-8")
    (ROOT / f"{args.prefix}_audit.json").write_text(
        json.dumps(audit, ensure_ascii=False, indent=2), encoding="utf-8")

    print("\n" + "=" * 64)
    print(f"done={n}  spent=${spent:.3f}")
    print(f"agree={len(agree)}/{n}={audit['agreement_rate']*100:.0f}%  "
          f"consensus labels: {dict(label_dist)}")
    print(f"consensus DIFFERS from SB label on {audit['vs_sb_flip_rate']*100:.0f}% of agreed")
    print(f"eval set -> {args.prefix}_eval.json (n={len(eval_out)})")
    print(f"quarantine -> {args.prefix}_quarantine.json (n={len(quarantine)})")


if __name__ == "__main__":
    main()
