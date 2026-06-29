"""Re-run the current-frontier comparison for GPT-5.5 only (Gemini skipped).

Reproduces the 2026-06-14 frontier harness 1:1: same eval sets, same
system+user prompt taken verbatim from each case's messages, same parse regex,
same output schema as runs/frontier_current_opus48_*.json so the numbers are
directly comparable to Opus 4.8.

The 2026-06-14 GPT-5.5 run died mid-way on OpenRouter 402 (credits). Credits are
topped up now. GPT-5.5 is a reasoning model (output tokens are expensive), so:
  - reasoning effort = low (a TP/FP triage verdict needs no deep chain),
  - live cost meter from the usage field, HARD STOP before exceeding --budget.
Sets: gold-core (71, trusted) + controlled escaping (40, the killer test).
Mined (142, hard for everyone, least informative, biggest) is skipped on purpose
to protect the budget.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("f:/vuln-llm-research")
sys.path.insert(0, str(ROOT / "scripts"))
from gpt53_relabel_handlabel100 import find_token  # noqa: E402

MODEL = "openai/gpt-5.5"  # overridden by --model
OR_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
IN_PER_TOK = 0.000005   # fallback only; real cost read from usage.cost
OUT_PER_TOK = 0.00003
REASONING = "low"       # overridden by --reasoning ("none" omits the param)
TAG = "gpt55_rerun"     # output filename tag, set in main()

VERDICT_RE = re.compile(r"Verdict:\s*(TRUE_POSITIVE|FALSE_POSITIVE|TP|FP)", re.I)
CONF_RE = re.compile(r"Confidence:\s*(HIGH|MEDIUM|LOW)", re.I)
REALCWE_RE = re.compile(r"RealCWE:\s*(CWE-\d+|N/A)", re.I)

SETS = {
    "goldcore": "data/eval/goldcore_71.json",
    "controlled": "data/eval/cwe79_controlled_pairs.json",
}


def norm(v):
    v = (v or "").strip().upper()
    if v in ("TP", "TRUE_POSITIVE"):
        return "TRUE_POSITIVE"
    if v in ("FP", "FALSE_POSITIVE"):
        return "FALSE_POSITIVE"
    return "PARSE_FAIL"


def call(token, system, user, max_tokens, retry=3):
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "max_tokens": max_tokens,
    }
    if REASONING != "none":
        payload["reasoning"] = {"effort": REASONING}
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OR_ENDPOINT, data=body, method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/JJKenn3dy/vuln-llm-research",
            "X-Title": "frontier gpt-5.5 rerun",
        },
    )
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
                time.sleep(2 * (2 ** attempt))
                continue
            raise RuntimeError(last)
        except Exception as e:  # noqa: BLE001
            last = str(e)
            time.sleep(2 * (2 ** attempt))
    raise RuntimeError(f"failed after {retry}: {last}")


def metrics(rows):
    tp = fn = tn = fp = pf = 0
    for r in rows:
        t, p = r["true_verdict"], r["predicted_verdict"]
        if p == "PARSE_FAIL":
            pf += 1
            continue
        if t == "TRUE_POSITIVE" and p == "TRUE_POSITIVE":
            tp += 1
        elif t == "TRUE_POSITIVE" and p == "FALSE_POSITIVE":
            fn += 1
        elif t == "FALSE_POSITIVE" and p == "FALSE_POSITIVE":
            tn += 1
        elif t == "FALSE_POSITIVE" and p == "TRUE_POSITIVE":
            fp += 1
    import math
    d = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn) - (fp * fn)) / d if d else 0.0
    npos, nneg = tp + fn, tn + fp
    dr = tp / npos if npos else 0.0
    far = fp / nneg if nneg else 0.0
    return {"n": len(rows), "TP": tp, "FN": fn, "TN": tn, "FP": fp, "PARSE_FAIL": pf,
            "DR": round(dr, 4), "FAR": round(far, 4),
            "BA": round(0.5 * (dr + (1 - far)), 4), "MCC": round(mcc, 4),
            "parse_fail_rate": round(pf / len(rows), 4) if rows else 0.0}


def pair_discrimination(rows, cases):
    by_cid = {c["metadata"]["case_id"]: c["metadata"] for c in cases}
    pairs = {}
    for r in rows:
        m = by_cid[r["case_id"]]
        pairs.setdefault(m["pair_id"], {})[m["variant"]] = r["predicted_verdict"]
    disc = sum(1 for p in pairs.values()
               if p.get("vuln") == "TRUE_POSITIVE" and p.get("safe") == "FALSE_POSITIVE")
    both_tp = sum(1 for p in pairs.values()
                  if p.get("vuln") == "TRUE_POSITIVE" and p.get("safe") == "TRUE_POSITIVE")
    return {"n_pairs": len(pairs), "discriminates": disc, "blind_both_tp": both_tp}


def run_set(name, path, token, budget, spent, max_tokens):
    cases = json.loads((ROOT / path).read_text(encoding="utf-8"))
    out_path = ROOT / f"runs/frontier_{TAG}_{name}_outputs.json"
    partial = out_path.with_suffix(".partial.jsonl")
    done = {}
    if partial.exists():
        for ln in partial.read_text(encoding="utf-8").splitlines():
            if ln.strip():
                r = json.loads(ln)
                done[r["case_id"]] = r
    rows = []
    for i, c in enumerate(cases):
        m = c["metadata"]
        cid = m["case_id"]
        gold = norm(m.get("true_verdict") or m.get("verdict"))
        if cid in done:
            rows.append(done[cid])
            continue
        if spent[0] > budget:
            print(f"  [BUDGET STOP] spent ${spent[0]:.3f} > ${budget}; stopping at {i}/{len(cases)}")
            break
        system = [x for x in c["messages"] if x["role"] == "system"][0]["content"]
        user = [x for x in c["messages"] if x["role"] == "user"][0]["content"]
        try:
            resp = call(token, system, user, max_tokens)
        except RuntimeError as e:
            if "OUT_OF_CREDITS" in str(e):
                print(f"  [402] out of credits at {i}/{len(cases)}: {e}")
                break
            print(f"  {cid}: ERROR {e}")
            continue
        msg = resp["choices"][0]["message"]
        raw = (msg.get("content") or msg.get("reasoning") or "").strip()
        u = resp.get("usage", {})
        cost = u.get("cost") or (u.get("prompt_tokens", 0) * IN_PER_TOK
                                 + u.get("completion_tokens", 0) * OUT_PER_TOK)
        spent[0] += cost
        v = VERDICT_RE.search(raw)
        conf = CONF_RE.search(raw)
        rcwe = REALCWE_RE.search(raw)
        rec = {
            "i": i, "case_id": cid,
            "claimed_cwe": m.get("claimed_cwe", ""),
            "real_cwe": m.get("real_cwe", ""),
            "true_verdict": gold,
            "predicted_verdict": norm(v.group(1)) if v else "PARSE_FAIL",
            "predicted_confidence": conf.group(1).upper() if conf else "",
            "predicted_real_cwe": rcwe.group(1).upper() if rcwe else "",
            "model_response": raw,
        }
        rows.append(rec)
        with partial.open("a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        ok = "OK" if rec["predicted_verdict"] == gold else "XX"
        print(f"  {i+1:>2d}/{len(cases)} {cid[:34]:<34} gold={gold[:2]} "
              f"pred={rec['predicted_verdict'][:2]} ct={u.get('completion_tokens',0):>4d} "
              f"${spent[0]:.3f} [{ok}]")
    out_path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    m = metrics(rows)
    result = {"set": name, "model": MODEL, "metrics": m}
    if name == "controlled":
        result["pair_discrimination"] = pair_discrimination(rows, cases)
    (ROOT / f"runs/frontier_{TAG}_{name}_metrics.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=float, default=2.70, help="hard USD ceiling")
    ap.add_argument("--max-tokens", type=int, default=1500)
    ap.add_argument("--only", default="", help="comma list: goldcore,controlled")
    ap.add_argument("--model", default="openai/gpt-5.5")
    ap.add_argument("--tag", default="", help="output filename tag; default derived from model")
    ap.add_argument("--reasoning", default="low", choices=["low", "medium", "high", "none"])
    args = ap.parse_args()
    global MODEL, TAG, REASONING
    MODEL = args.model
    REASONING = args.reasoning
    TAG = args.tag or ("gpt55_rerun" if MODEL == "openai/gpt-5.5"
                       else MODEL.split("/")[-1].replace(".", "").replace("-", ""))
    token = find_token()
    spent = [0.0]
    sets = args.only.split(",") if args.only else list(SETS)
    results = []
    for name in sets:
        name = name.strip()
        if name not in SETS:
            continue
        print(f"\n=== GPT-5.5 on {name} (budget left ${args.budget - spent[0]:.2f}) ===")
        results.append(run_set(name, SETS[name], token, args.budget, spent, args.max_tokens))
    print("\n" + "=" * 60)
    print(f"TOTAL SPENT: ${spent[0]:.3f}")
    for r in results:
        m = r["metrics"]
        line = (f"{r['set']:11s} MCC={m['MCC']:+.3f} BA={m['BA']:.3f} "
                f"DR={m['DR']*100:.0f}% FAR={m['FAR']*100:.0f}% "
                f"parse_fail={m['PARSE_FAIL']}/{m['n']}")
        if "pair_discrimination" in r:
            pd = r["pair_discrimination"]
            line += f"  disc={pd['discriminates']}/{pd['n_pairs']} blind_both_tp={pd['blind_both_tp']}"
        print(line)


if __name__ == "__main__":
    main()
