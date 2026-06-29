"""Blind teacher labeling with GPT-5.5 for distillation (exp5).

The teacher sees ONLY code + finding (label hidden) and returns a verdict +
code-grounded reasoning. Code then compares the teacher verdict to the pool's
trusted label (no anchoring, per feedback_llm_judge_anchoring):
  - AGREE  -> goes into the distilled train set; teacher's grounded reasoning
              replaces the existing NVD-boilerplate reasoning.
  - DISAGREE -> quarantined (snippet-window blindspot vs bad label is
                undecidable from the window alone, feedback_snippet_window_scope).

Outputs:
  <prefix>_audit.json   all records + agreement summary + reasoning-quality stats
  <prefix>_train.json   AGREE-only, messages format (assistant = teacher output)

Budget guard: live cost meter from OpenRouter usage, hard stop at --budget.
Resume: <prefix>_audit.partial.jsonl.
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

MODEL = "openai/gpt-5.5"
OR_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
IN_PER_TOK = 0.000005
OUT_PER_TOK = 0.00003

VERDICT_RE = re.compile(r"Verdict:\s*(TRUE_POSITIVE|FALSE_POSITIVE|TP|FP)", re.I)
CONF_RE = re.compile(r"Confidence:\s*(HIGH|MEDIUM|LOW)", re.I)
REALCWE_RE = re.compile(r"RealCWE:\s*(CWE-\d+|N/A)", re.I)
REASON_RE = re.compile(r"Reasoning:\s*(.+?)(?:\nRealCWE:|\nSuggestedFix:|\Z)", re.I | re.S)
# NVD-boilerplate / cargo-cult markers we want the teacher to eliminate
BOILER_RE = re.compile(r"open source platform|prior to version|is patched in|tests-passed|CVE-\d{4}-", re.I)


def norm(v):
    v = (v or "").strip().upper()
    if v in ("TP", "TRUE_POSITIVE"):
        return "TRUE_POSITIVE"
    if v in ("FP", "FALSE_POSITIVE"):
        return "FALSE_POSITIVE"
    return "PARSE_FAIL"


def call(token, system, user, max_tokens, effort, retry=3):
    body = json.dumps({
        "model": MODEL,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "max_tokens": max_tokens,
        "reasoning": {"effort": effort},
    }).encode("utf-8")
    req = urllib.request.Request(
        OR_ENDPOINT, data=body, method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                 "HTTP-Referer": "https://github.com/JJKenn3dy/vuln-llm-research",
                 "X-Title": "exp5 teacher labeling gpt-5.5"})
    last = None
    for attempt in range(retry):
        try:
            with urllib.request.urlopen(req, timeout=180) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            msg = (e.read()[:300].decode("utf-8", "replace") if hasattr(e, "read") else "")
            last = f"HTTP {e.code}: {msg}"
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


def sample_balanced(pool, n, seed=42):
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
    ap.add_argument("--n", type=int, default=25)
    ap.add_argument("--prefix", default="runs/exp5_teacher_smoke")
    ap.add_argument("--effort", default="medium", choices=["low", "medium", "high"])
    ap.add_argument("--max-tokens", type=int, default=1800)
    ap.add_argument("--budget", type=float, default=2.0)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    token = find_token()
    pool = json.loads((ROOT / args.pool).read_text(encoding="utf-8"))
    sample = sample_balanced(pool, args.n, args.seed)

    audit_path = ROOT / f"{args.prefix}_audit.json"
    train_path = ROOT / f"{args.prefix}_train.json"
    partial = audit_path.with_suffix(".partial.jsonl")
    done = {}
    if partial.exists():
        for ln in partial.read_text(encoding="utf-8").splitlines():
            if ln.strip():
                r = json.loads(ln); done[r["case_id"]] = r

    spent = 0.0
    records = []
    for i, c in enumerate(sample):
        m = c["metadata"]; cid = m["case_id"]
        gold = gold_of(m)
        if cid in done:
            records.append(done[cid]); continue
        if spent > args.budget:
            print(f"  [BUDGET STOP] ${spent:.3f} > ${args.budget} at {i}/{len(sample)}"); break
        system = [x for x in c["messages"] if x["role"] == "system"][0]["content"]
        user = [x for x in c["messages"] if x["role"] == "user"][0]["content"]
        old_reason = [x for x in c["messages"] if x["role"] == "assistant"][0]["content"]
        try:
            resp = call(token, system, user, args.max_tokens, args.effort)
        except RuntimeError as e:
            if "OUT_OF_CREDITS" in str(e):
                print(f"  [402] out of credits at {i}/{len(sample)}"); break
            print(f"  {cid}: ERROR {e}"); continue
        msg = resp["choices"][0]["message"]
        raw = (msg.get("content") or msg.get("reasoning") or "").strip()
        u = resp.get("usage", {})
        spent += u.get("cost") or (u.get("prompt_tokens", 0) * IN_PER_TOK
                                   + u.get("completion_tokens", 0) * OUT_PER_TOK)
        tv = VERDICT_RE.search(raw)
        tv = norm(tv.group(1)) if tv else "PARSE_FAIL"
        conf = CONF_RE.search(raw)
        rc = REALCWE_RE.search(raw)
        tr = REASON_RE.search(raw)
        rec = {
            "case_id": cid, "claimed_cwe": m.get("claimed_cwe", ""),
            "gold": gold, "teacher_verdict": tv,
            "teacher_confidence": conf.group(1).upper() if conf else "",
            "teacher_real_cwe": rc.group(1).upper() if rc else "",
            "teacher_reasoning": tr.group(1).strip() if tr else raw,
            "teacher_full": raw,
            "old_reasoning": old_reason,
            "agree": tv == gold and tv != "PARSE_FAIL",
            "old_was_boiler": bool(BOILER_RE.search(old_reason)),
            "new_is_boiler": bool(BOILER_RE.search(raw)),
        }
        records.append(rec)
        with partial.open("a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        tag = "AGREE" if rec["agree"] else f"DIFF(g={gold[:2]},t={tv[:2]})"
        print(f"  {i+1:>3d}/{len(sample)} {cid[:30]:<30} {m.get('claimed_cwe',''):<8} "
              f"{tag:<14} ${spent:.3f}")

    # summaries
    n = len(records)
    agree = sum(1 for r in records if r["agree"])
    old_b = sum(1 for r in records if r["old_was_boiler"])
    new_b = sum(1 for r in records if r["new_is_boiler"])
    audit = {
        "model": MODEL, "pool": args.pool, "n_requested": args.n, "n_done": n,
        "effort": args.effort, "spent_usd": round(spent, 4),
        "agreement_rate": round(agree / n, 4) if n else 0.0,
        "n_agree": agree, "n_disagree": n - agree,
        "old_boilerplate_rate": round(old_b / n, 4) if n else 0.0,
        "new_boilerplate_rate": round(new_b / n, 4) if n else 0.0,
        "disagree_by_cwe": dict(Counter(r["claimed_cwe"] for r in records if not r["agree"])),
        "records": records,
    }
    audit_path.write_text(json.dumps(audit, ensure_ascii=False, indent=2), encoding="utf-8")

    # distilled train set: AGREE-only, teacher reasoning as the target
    train = []
    for r in records:
        if not r["agree"]:
            continue
        c = next(x for x in sample if x["metadata"]["case_id"] == r["case_id"])
        sysmsg = [x for x in c["messages"] if x["role"] == "system"][0]
        usermsg = [x for x in c["messages"] if x["role"] == "user"][0]
        train.append({
            "messages": [sysmsg, usermsg,
                         {"role": "assistant", "content": r["teacher_full"]}],
            "metadata": {**c["metadata"], "reasoning_source": "gpt-5.5-teacher"},
        })
    train_path.write_text(json.dumps(train, ensure_ascii=False, indent=2), encoding="utf-8")

    print("\n" + "=" * 60)
    print(f"done={n}  spent=${spent:.3f}  agreement={agree}/{n}"
          f"={audit['agreement_rate']*100:.0f}%")
    print(f"boilerplate: old {old_b}/{n}={audit['old_boilerplate_rate']*100:.0f}% "
          f"-> teacher {new_b}/{n}={audit['new_boilerplate_rate']*100:.0f}%")
    print(f"distilled train rows (AGREE-only) -> {train_path}  (n={len(train)})")
    print(f"audit -> {audit_path}")


if __name__ == "__main__":
    main()
