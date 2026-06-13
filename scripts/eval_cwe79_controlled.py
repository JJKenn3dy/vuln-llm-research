"""Run a judge on the controlled CWE-79 pairs; report accuracy + pair discrimination.

Pair discrimination = the killer metric: for a matched pair (vuln, safe) that
differ ONLY by escaping, does the judge give vuln=TP AND safe=FP? A judge that
pattern-matches on surface features (both have an HTML sink) will fail this even
if its raw accuracy looks ok.

Default judge: GPT-5.3-codex via OpenRouter (validates the set is unambiguous +
gives a frontier reference). The same analysis (analyze=...) consumes v8.3.1
outputs.json from a pod run later.
"""
import argparse
import json
import re
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("f:/vuln-llm-research")
SET = ROOT / "data/eval/cwe79_controlled_pairs.json"

sys.path.insert(0, str(ROOT / "scripts"))
from blind_relabel_train import call_model
from gpt53_relabel_handlabel100 import find_token

JUDGE_SYS = ("You are a security triage assistant. Decide if the SAST finding is a true "
             "positive or false positive based on the code. Output exactly:\n"
             "Verdict: TRUE_POSITIVE or FALSE_POSITIVE\nConfidence: HIGH/MEDIUM/LOW\n"
             "Reasoning: one sentence")
V_RE = re.compile(r"Verdict:\s*(TRUE_POSITIVE|FALSE_POSITIVE|TP|FP)", re.I)


def norm(v):
    v = (v or "").strip().upper()
    return "TP" if v in ("TP", "TRUE_POSITIVE") else "FP" if v in ("FP", "FALSE_POSITIVE") else None


def analyze(rows):
    """rows: list of dicts with pair_id, variant, gold, pred."""
    n = len(rows)
    acc = sum(1 for r in rows if r["pred"] == r["gold"]) / n
    tp = [r for r in rows if r["gold"] == "TP"]
    fp = [r for r in rows if r["gold"] == "FP"]
    dr = sum(1 for r in tp if r["pred"] == "TP") / len(tp) if tp else 0
    spec = sum(1 for r in fp if r["pred"] == "FP") / len(fp) if fp else 0
    pairs = defaultdict(dict)
    for r in rows:
        pairs[r["pair_id"]][r["variant"]] = r["pred"]
    disc = sum(1 for p in pairs.values()
               if p.get("vuln") == "TP" and p.get("safe") == "FP")
    both_tp = sum(1 for p in pairs.values() if p.get("vuln") == "TP" and p.get("safe") == "TP")
    both_fp = sum(1 for p in pairs.values() if p.get("vuln") == "FP" and p.get("safe") == "FP")
    inverted = sum(1 for p in pairs.values() if p.get("vuln") == "FP" and p.get("safe") == "TP")
    print(f"n={n}  accuracy={acc:.0%}  DR(vuln caught)={dr:.0%}  spec(safe cleared)={spec:.0%}")
    print(f"\nPAIR DISCRIMINATION (the killer metric), {len(pairs)} pairs:")
    print(f"  discriminates (vuln=TP, safe=FP): {disc}/{len(pairs)} = {disc/len(pairs):.0%}")
    print(f"  blind-to-escaping both=TP:        {both_tp}/{len(pairs)}  (sees sink, ignores escape)")
    print(f"  over-clears both=FP:              {both_fp}/{len(pairs)}")
    print(f"  inverted:                         {inverted}/{len(pairs)}")
    failed = [pid for pid, p in pairs.items() if not (p.get("vuln") == "TP" and p.get("safe") == "FP")]
    if failed:
        print(f"  failed pairs: {failed}")
    return {"n": n, "accuracy": acc, "dr": dr, "spec": spec,
            "discrimination": disc / len(pairs), "n_pairs": len(pairs),
            "both_tp": both_tp, "both_fp": both_fp, "inverted": inverted}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--judge", default="gpt53", choices=["gpt53"])
    ap.add_argument("--analyze", help="path to a triage outputs.json (e.g. v8.3.1 pod run) instead of calling a judge")
    ap.add_argument("--out", default=str(ROOT / "runs/cwe79_controlled_gpt53.json"))
    args = ap.parse_args()
    cases = json.loads(SET.read_text(encoding="utf-8"))

    rows = []
    if args.analyze:
        outs = {o["case_id"]: o for o in json.loads(Path(args.analyze).read_text(encoding="utf-8"))}
        for c in cases:
            m = c["metadata"]; o = outs.get(m["case_id"])
            if not o:
                continue
            rows.append({"pair_id": m["pair_id"], "variant": m["variant"],
                         "gold": norm(m["verdict"]), "pred": norm(o.get("predicted_verdict"))})
    else:
        token = find_token()
        partial = Path(args.out).with_suffix(".partial.jsonl")
        done = {}
        if partial.exists():
            for l in partial.read_text(encoding="utf-8").splitlines():
                if l.strip():
                    r = json.loads(l); done[r["case_id"]] = r
        t0 = time.time()
        recs = []
        for i, c in enumerate(cases):
            m = c["metadata"]
            if m["case_id"] in done:
                recs.append(done[m["case_id"]]); continue
            user = [x for x in c["messages"] if x["role"] == "user"][0]["content"]
            try:
                resp = call_model(token, JUDGE_SYS, user, max_tokens=1500)
                raw = (resp["choices"][0]["message"].get("content") or
                       resp["choices"][0]["message"].get("reasoning") or "")
                v = V_RE.search(raw)
                pred = norm(v.group(1)) if v else None
            except Exception as e:
                print(f"  {m['case_id']}: ERROR {e}"); continue
            rec = {"case_id": m["case_id"], "pair_id": m["pair_id"], "variant": m["variant"],
                   "gold": norm(m["verdict"]), "pred": pred}
            recs.append(rec)
            with partial.open("a", encoding="utf-8", newline="\n") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            ok = "OK" if pred == rec["gold"] else "XX"
            print(f"  {i+1:>2d}/{len(cases)} {m['case_id']:<28} gold={rec['gold']} pred={pred} [{ok}]")
        rows = recs

    print()
    res = analyze(rows)
    Path(args.out).write_text(json.dumps({"rows": rows, "summary": res}, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nsaved -> {args.out}")


if __name__ == "__main__":
    main()
