"""Dual-teacher blind labeling for distillation (exp5 pilot).

Two independent strong teachers (GPT-5.5 + GLM 5.2) relabel pool cases BLIND
(snippet-grounded, label hidden). We keep ONLY cases where both agree -> clean
consensus label with no single-judge anchoring (feedback_llm_judge_anchoring,
feedback_judges_defining_buckets_contaminate). The pool's own labels are CVE-level
boilerplate (proven garbage in the smoke), so they are NOT used as truth here.

GPT-5.5 over-flags (paranoid); GLM 5.2 is balanced and 10x cheaper. Agreement
neutralizes both biases. Agreed reasoning target = GLM 5.2's (aligned with the
false-positive-cutting goal; both agree on the verdict anyway).

Outputs (prefix default runs/exp5_dual):
  <prefix>_train.json       AGREE-only, messages format -> distillation train set
  <prefix>_quarantine.json  disagreements (for inspection)
  <prefix>_audit.json       per-case both verdicts + agreement/cost summary
Resume: <prefix>_raw.partial.jsonl (one line per case, both raw responses).
Budget guard: live cost from usage.cost, hard stop at --budget.
"""
from __future__ import annotations

import argparse
import json
import random
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
GPT = "openai/gpt-5.5"
GLM = "z-ai/glm-5.2"

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
                 "X-Title": "exp5 dual-teacher labeling"})
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


def gold_of(meta):
    return norm(meta.get("verdict") or meta.get("true_verdict"))


def sample_balanced(pool, n, seed):
    rng = random.Random(seed)
    tp = [c for c in pool if gold_of(c["metadata"]) == "TRUE_POSITIVE"]
    fp = [c for c in pool if gold_of(c["metadata"]) == "FALSE_POSITIVE"]
    rng.shuffle(tp); rng.shuffle(fp)
    half = n // 2
    out = tp[:half] + fp[:n - half]
    rng.shuffle(out)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", default="data/train/triage_v8_3_clean/train_dedup_balanced.json")
    ap.add_argument("--n", type=int, default=450)
    ap.add_argument("--prefix", default="runs/exp5_dual")
    ap.add_argument("--budget", type=float, default=8.0)
    ap.add_argument("--max-tokens", type=int, default=1500)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    token = find_token()
    pool = json.loads((ROOT / args.pool).read_text(encoding="utf-8"))
    sample = sample_balanced(pool, args.n, args.seed)
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
            gpt_raw, gpt_cost = call(token, GPT, system, user, args.max_tokens)
            glm_raw, glm_cost = call(token, GLM, system, user, args.max_tokens)
        except RuntimeError as e:
            if "OUT_OF_CREDITS" in str(e):
                print(f"  [402] out of credits at {i}/{len(sample)}"); break
            print(f"  {cid}: ERROR {e}"); continue
        gv = VERDICT_RE.search(gpt_raw); gv = norm(gv.group(1)) if gv else "PARSE_FAIL"
        lv = VERDICT_RE.search(glm_raw); lv = norm(lv.group(1)) if lv else "PARSE_FAIL"
        cost = gpt_cost + glm_cost
        spent += cost
        rec = {"case_id": cid, "claimed_cwe": m.get("claimed_cwe", ""),
               "pool_label": gold_of(m), "gpt_verdict": gv, "glm_verdict": lv,
               "gpt_raw": gpt_raw, "glm_raw": glm_raw, "cost": cost,
               "agree": gv == lv and gv != "PARSE_FAIL"}
        raws.append(rec)
        with raw_partial.open("a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        tag = f"AGREE={gv[:2]}" if rec["agree"] else f"DIFF(g={gv[:2]},l={lv[:2]})"
        print(f"  {i+1:>3d}/{len(sample)} {cid[:26]:<26} {m.get('claimed_cwe',''):<8} "
              f"{tag:<16} ${spent:.2f}")

    n = len(raws)
    agree = [r for r in raws if r["agree"]]
    train, quarantine = [], []
    for r in raws:
        c = by_cid[r["case_id"]]
        sysmsg = [x for x in c["messages"] if x["role"] == "system"][0]
        usermsg = [x for x in c["messages"] if x["role"] == "user"][0]
        if r["agree"]:
            train.append({
                "messages": [sysmsg, usermsg,
                             {"role": "assistant", "content": r["glm_raw"]}],
                "metadata": {**c["metadata"], "consensus_verdict": r["gpt_verdict"],
                             "reasoning_source": "glm-5.2", "dual_teacher": "gpt-5.5+glm-5.2"},
            })
        else:
            quarantine.append(r)

    (ROOT / f"{args.prefix}_train.json").write_text(
        json.dumps(train, ensure_ascii=False, indent=2), encoding="utf-8")
    (ROOT / f"{args.prefix}_quarantine.json").write_text(
        json.dumps(quarantine, ensure_ascii=False, indent=2), encoding="utf-8")
    label_dist = Counter(r["gpt_verdict"] for r in agree)
    audit = {
        "teachers": [GPT, GLM], "pool": args.pool, "n_requested": args.n, "n_done": n,
        "spent_usd": round(spent, 4), "n_agree": len(agree), "n_quarantine": len(quarantine),
        "agreement_rate": round(len(agree) / n, 4) if n else 0.0,
        "consensus_label_dist": dict(label_dist),
        "disagree_by_cwe": dict(Counter(r["claimed_cwe"] for r in quarantine)),
        "vs_pool_flip_rate": round(
            sum(1 for r in agree if r["gpt_verdict"] != r["pool_label"]) / len(agree), 4
        ) if agree else 0.0,
    }
    (ROOT / f"{args.prefix}_audit.json").write_text(
        json.dumps(audit, ensure_ascii=False, indent=2), encoding="utf-8")

    print("\n" + "=" * 64)
    print(f"done={n}  spent=${spent:.3f}")
    print(f"agree={len(agree)}/{n}={audit['agreement_rate']*100:.0f}%  "
          f"consensus labels: {dict(label_dist)}")
    print(f"consensus DIFFERS from pool label on {audit['vs_pool_flip_rate']*100:.0f}% "
          f"of agreed cases (confirms pool labels were noisy)")
    print(f"train (AGREE) -> {args.prefix}_train.json (n={len(train)})")
    print(f"quarantine -> {args.prefix}_quarantine.json (n={len(quarantine)})")


if __name__ == "__main__":
    main()
