"""GLM-5.2 solo blind labeling for exp6 distillation set.

Decision (2026-07-01): GLM-solo, not dual. GLM is our best cheap judge (gold-core
0.868, less paranoid than GPT-5.5, 0 parse fails, fast). DeepSeek weaker+slower.

PROVIDER/QUANT PINNING (important): the same GLM-5.2 is served by many providers
at different quantization (fp4/fp8/unknown). Our validated 0.868 came from the
cheapest fp4 route. We PIN provider order + fp4 quant so the whole run is
consistent (OpenRouter won't silently mix quant tiers mid-run) and cheapest.

Blind: teacher sees only code+finding (pool label hidden), returns verdict +
code-grounded reasoning. GLM's verdict becomes the label (single source, uniform).
Pool's own labels are noisy CVE-boilerplate and are NOT used as truth.

Outputs (prefix runs/exp6_glm):
  <prefix>_train.json   all labeled rows, messages format -> distillation set
  <prefix>_audit.json   verdict dist, vs-pool flip rate, parse fails, cost
Resume: <prefix>_train.partial.jsonl. Budget guard via usage.cost.
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

MODEL = "z-ai/glm-5.2"
OR_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
# Pin cheapest provider + fp4 quant (our validated 0.868 route). allow_fallbacks
# stays within fp4 so quality tier is consistent even if DeepInfra hiccups.
PROVIDER = {"order": ["DeepInfra"], "quantizations": ["fp4"], "allow_fallbacks": True}

VERDICT_RE = re.compile(r"Verdict:\s*(TRUE_POSITIVE|FALSE_POSITIVE|TP|FP)", re.I)


def norm(v):
    v = (v or "").strip().upper()
    if v in ("TP", "TRUE_POSITIVE"):
        return "TRUE_POSITIVE"
    if v in ("FP", "FALSE_POSITIVE"):
        return "FALSE_POSITIVE"
    return "PARSE_FAIL"


def call(token, system, user, max_tokens=1500, retry=3):
    body = json.dumps({
        "model": MODEL,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "max_tokens": max_tokens,
        "reasoning": {"effort": "low"},
        "provider": PROVIDER,
    }).encode("utf-8")
    req = urllib.request.Request(
        OR_ENDPOINT, data=body, method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                 "HTTP-Referer": "https://github.com/JJKenn3dy/vuln-llm-research",
                 "X-Title": "exp6 glm-solo labeling"})
    last = None
    for attempt in range(retry):
        try:
            with urllib.request.urlopen(req, timeout=180) as resp:
                d = json.loads(resp.read().decode("utf-8"))
            msg = d["choices"][0]["message"]
            raw = (msg.get("content") or msg.get("reasoning") or "").strip()
            u = d.get("usage", {}) or {}
            prov = d.get("provider", "?")
            return raw, u.get("cost", 0.0) or 0.0, prov
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", default="data/train/triage_v8_3_clean/train_dedup_balanced.json")
    ap.add_argument("--n", type=int, default=0, help="0 = whole pool")
    ap.add_argument("--prefix", default="runs/exp6_glm")
    ap.add_argument("--budget", type=float, default=4.0)
    ap.add_argument("--max-tokens", type=int, default=1500)
    args = ap.parse_args()

    token = find_token()
    pool = json.loads((ROOT / args.pool).read_text(encoding="utf-8"))
    if args.n:
        pool = pool[:args.n]

    train_partial = ROOT / f"{args.prefix}_train.partial.jsonl"
    done = {}
    if train_partial.exists():
        for ln in train_partial.read_text(encoding="utf-8").splitlines():
            if ln.strip():
                r = json.loads(ln); done[r["case_id"]] = r

    spent = 0.0
    recs = []
    provider_seen = Counter()
    for i, c in enumerate(pool):
        m = c["metadata"]; cid = m["case_id"]
        if cid in done:
            recs.append(done[cid]); spent += done[cid].get("cost", 0.0); continue
        if spent > args.budget:
            print(f"  [BUDGET STOP] ${spent:.2f} > ${args.budget} at {i}/{len(pool)}"); break
        system = [x for x in c["messages"] if x["role"] == "system"][0]["content"]
        user = [x for x in c["messages"] if x["role"] == "user"][0]["content"]
        try:
            raw, cost, prov = call(token, system, user, args.max_tokens)
        except RuntimeError as e:
            if "OUT_OF_CREDITS" in str(e):
                print(f"  [402] out of credits at {i}/{len(pool)}"); break
            print(f"  {cid}: ERROR {e}"); continue
        spent += cost
        provider_seen[prov] += 1
        v = VERDICT_RE.search(raw)
        verdict = norm(v.group(1)) if v else "PARSE_FAIL"
        rec = {"case_id": cid, "claimed_cwe": m.get("claimed_cwe", ""),
               "pool_label": gold_of(m), "glm_verdict": verdict,
               "glm_raw": raw, "cost": cost, "provider": str(prov)}
        recs.append(rec)
        with train_partial.open("a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        if (i + 1) % 20 == 0 or i < 3:
            print(f"  {i+1:>3d}/{len(pool)} {cid[:24]:<24} {verdict[:2]} "
                  f"prov={prov} ${spent:.3f}")

    # build train.json (drop parse fails) + audit
    ok = [r for r in recs if r["glm_verdict"] != "PARSE_FAIL"]
    pool_by = {c["metadata"]["case_id"]: c for c in pool}
    train = []
    for r in ok:
        c = pool_by[r["case_id"]]
        sysm = [x for x in c["messages"] if x["role"] == "system"][0]
        usrm = [x for x in c["messages"] if x["role"] == "user"][0]
        train.append({
            "messages": [sysm, usrm, {"role": "assistant", "content": r["glm_raw"]}],
            "metadata": {**c["metadata"], "glm_verdict": r["glm_verdict"],
                         "reasoning_source": "glm-5.2-fp4"},
        })
    (ROOT / f"{args.prefix}_train.json").write_text(
        json.dumps(train, ensure_ascii=False, indent=2), encoding="utf-8")
    vd = Counter(r["glm_verdict"] for r in ok)
    flips = sum(1 for r in ok if r["glm_verdict"] != r["pool_label"])
    audit = {"model": MODEL, "provider_pin": PROVIDER, "providers_used": dict(provider_seen),
             "n_done": len(recs), "n_labeled": len(ok),
             "parse_fail": len(recs) - len(ok), "spent_usd": round(spent, 4),
             "verdict_dist": dict(vd),
             "vs_pool_flip_rate": round(flips / len(ok), 4) if ok else 0.0}
    (ROOT / f"{args.prefix}_audit.json").write_text(
        json.dumps(audit, ensure_ascii=False, indent=2), encoding="utf-8")
    print("\n" + "=" * 60)
    print(f"done={len(recs)} labeled={len(ok)} parse_fail={len(recs)-len(ok)} spent=${spent:.3f}")
    print(f"verdicts: {dict(vd)}  | providers: {dict(provider_seen)}")
    print(f"flips vs pool label: {audit['vs_pool_flip_rate']*100:.0f}%")
    print(f"-> {args.prefix}_train.json ({len(train)} rows)")


if __name__ == "__main__":
    main()
