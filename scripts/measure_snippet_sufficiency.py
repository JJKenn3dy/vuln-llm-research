"""Size the snippet-insufficiency problem in v8.x train data (Path C step C).

The blind-relabel smoke showed 42% verdict disagreement, 9/10 being ship=TP
-> blind=FP, and hand-inspection showed the cause is snippet-window: the CVE
is real but the sink/context is not inside the extracted snippet. This script
quantifies that at n~200 so we can choose:
  A (reasoning-regen on sufficient rows) vs B (context expansion).

For each row we ask GPT-5.3 (code only, blind to shipped verdict) for:
  Verdict + Solvable(yes/partial/no: is the snippet alone enough) + Reasoning.

Key cross-tab: among ship=TP, what fraction does the judge mark Solvable!=yes,
and do the TP->FP disagreements coincide with Solvable!=yes (snippet too thin)
rather than Solvable=yes+FP (genuine label challenge)?

Stratified ~50 / (source x shipped_verdict) cell. Partial every 10. ~$1.5.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

ROOT = Path("f:/vuln-llm-research")
TRAIN = ROOT / "data/train/triage_v8_3_1/train_merged.json"
OUTDIR = ROOT / "data/train/triage_v8_4_relabel"
OUT = OUTDIR / "sufficiency_measure.jsonl"
PARTIAL = OUTDIR / "sufficiency_measure.partial.jsonl"

sys.path.insert(0, str(ROOT / "scripts"))
from blind_relabel_train import call_model  # reuses our system-explicit caller
from gpt53_relabel_handlabel100 import find_token  # noqa: E402

SYSTEM = (
    "You are an application-security engineer auditing static-analysis findings. "
    "Judge ONLY from the code snippet shown. Two separate judgments:\n"
    "1. Verdict: is this a TRUE_POSITIVE (real exploitable bug visible in this code) "
    "or FALSE_POSITIVE (noise)?\n"
    "2. Solvable: is the snippet ALONE sufficient to decide confidently? Answer "
    "'yes' (the bug or its absence is fully visible here), 'partial' (suggestive but "
    "the deciding sink/source/guard is probably outside this snippet), or 'no' (the "
    "snippet does not contain what is needed to judge this CWE).\n"
    "Be honest about Solvable: a vulnerability whose sink is in another function/file "
    "is 'partial' or 'no', not 'yes'.\n\n"
    "Output exactly three lines, no markdown:\n"
    "Verdict: TRUE_POSITIVE or FALSE_POSITIVE\n"
    "Solvable: yes or partial or no\n"
    "Reasoning: one sentence naming the code element (or the missing element)\n"
)

V_RE = re.compile(r"Verdict:\s*(TRUE_POSITIVE|FALSE_POSITIVE|TP|FP)", re.I)
S_RE = re.compile(r"Solvable:\s*(yes|partial|no)", re.I)


def norm(v):
    if v is None:
        return None
    v = str(v).strip().upper()
    return "TP" if v in ("TP", "TRUE_POSITIVE") else "FP" if v in ("FP", "FALSE_POSITIVE") else None


def extract_code(user_msg: str) -> str:
    if "Code:" in user_msg:
        tail = user_msg.split("Code:", 1)[1]
        for stop in ("\nOutput exactly", "\nVersion:", "\nStable tag:"):
            if stop in tail:
                tail = tail.split(stop, 1)[0]
        return tail.strip()
    return user_msg


def build_prompt(code: str, cwe: str, tool: str) -> str:
    return (f"SAST tool: {tool}\nClaimed CWE: {cwe}\n\nCode:\n{code}\n\n"
            "Give Verdict, Solvable, Reasoning per the format.")


def stratified(rows, per_cell):
    cells = defaultdict(list)
    for i, r in enumerate(rows):
        cells[(r["metadata"].get("source", "?"), norm(r["metadata"].get("verdict")))].append(i)
    pick = []
    for key in sorted(cells, key=lambda k: (str(k[0]), str(k[1]))):
        idxs = cells[key]
        step = max(1, len(idxs) // per_cell)
        pick.extend(idxs[::step][:per_cell])
    return sorted(pick)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-cell", type=int, default=50)
    args = ap.parse_args()
    OUTDIR.mkdir(parents=True, exist_ok=True)
    token = find_token()
    rows = json.loads(TRAIN.read_text(encoding="utf-8"))
    idxs = stratified(rows, args.per_cell)
    print(f"measuring {len(idxs)} rows, {args.per_cell}/cell\n")

    done = set()
    if PARTIAL.exists():
        for l in PARTIAL.read_text(encoding="utf-8").splitlines():
            if l.strip():
                try:
                    done.add(json.loads(l)["row_idx"])
                except Exception:
                    pass
        print(f"resume: {len(done)} done")

    res, tin, tout, t0 = [], 0, 0, time.time()
    for i in idxs:
        if i in done:
            continue
        m = rows[i]["metadata"]
        user = [x for x in rows[i]["messages"] if x["role"] == "user"][0]["content"]
        prompt = build_prompt(extract_code(user), m.get("claimed_cwe", "?"), m.get("tool", "semgrep"))
        try:
            resp = call_model(token, SYSTEM, prompt, max_tokens=2000)
        except Exception as e:
            print(f"  {i:>4d}: ERROR {e}")
            continue
        msg = resp["choices"][0]["message"]
        raw = (msg.get("content") or msg.get("reasoning") or "").strip()
        if not raw:
            print(f"  {i:>4d}: EMPTY")
            continue
        u = resp.get("usage", {})
        tin += u.get("prompt_tokens", 0); tout += u.get("completion_tokens", 0)
        v = V_RE.search(raw); s = S_RE.search(raw)
        bv = norm(v.group(1)) if v else None
        solv = s.group(1).lower() if s else "?"
        ship = norm(m.get("verdict"))
        rec = {"row_idx": i, "source": m.get("source"), "claimed_cwe": m.get("claimed_cwe"),
               "shipped": ship, "blind": bv, "solvable": solv, "agree": (bv == ship) if bv else None}
        res.append(rec)
        with PARTIAL.open("a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        if len(res) % 10 == 0:
            print(f"  {len(res):>3d}/{len(idxs)-len(done)}  ({(time.time()-t0)/len(res):.1f}s/row)")

    # merge to final
    recs = [json.loads(l) for l in PARTIAL.read_text(encoding="utf-8").splitlines() if l.strip()]
    with OUT.open("w", encoding="utf-8", newline="\n") as f:
        for r in recs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # ---- analysis ----
    n = len(recs)
    print(f"\n=== n={n} ===")
    agr = sum(1 for r in recs if r["agree"])
    print(f"verdict agreement with shipped: {agr}/{n} = {agr/n:.0%}")
    print("\nsolvability distribution (snippet alone enough?):")
    for s in ("yes", "partial", "no", "?"):
        c = sum(1 for r in recs if r["solvable"] == s)
        if c:
            print(f"  {s:<8} {c:>3} = {c/n:.0%}")

    print("\nsolvability by shipped verdict:")
    for ship in ("TP", "FP"):
        sub = [r for r in recs if r["shipped"] == ship]
        if not sub:
            continue
        dist = Counter(r["solvable"] for r in sub)
        insuf = sum(1 for r in sub if r["solvable"] in ("partial", "no"))
        print(f"  ship={ship} (n={len(sub)}): {dict(dist)}  -> insufficient {insuf}/{len(sub)} = {insuf/len(sub):.0%}")

    # The decisive cross-tab: TP->FP disagreements, are they snippet-thin or genuine?
    tp_fp = [r for r in recs if r["shipped"] == "TP" and r["blind"] == "FP"]
    if tp_fp:
        thin = sum(1 for r in tp_fp if r["solvable"] in ("partial", "no"))
        print(f"\nTP->FP disagreements (n={len(tp_fp)}):")
        print(f"  snippet-insufficient (solvable!=yes): {thin}/{len(tp_fp)} = {thin/len(tp_fp):.0%}  [=> context expansion would help]")
        print(f"  genuine challenge (solvable=yes, says FP): {len(tp_fp)-thin}/{len(tp_fp)} = {(len(tp_fp)-thin)/len(tp_fp):.0%}  [=> real label question]")

    # learnable-as-is: agreement AND solvable=yes
    learnable = sum(1 for r in recs if r["agree"] and r["solvable"] == "yes")
    print(f"\nlearnable-as-is (agree AND solvable=yes): {learnable}/{n} = {learnable/n:.0%}")
    print(f"  -> A (reasoning-regen) cleanly applies to ~{learnable/n:.0%} of rows")
    print(f"cost: in={tin} out={tout} ${tin*1.75e-6+tout*14e-6:.2f}")


if __name__ == "__main__":
    main()
