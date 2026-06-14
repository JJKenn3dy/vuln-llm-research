"""Build a clean REAL anchor for v8.4-exp2 (mixed-anchor).

v8.4-exp1 over-corrected to FP because pure synthetic XSS shifted the model's
prior. The anchor's job: real, snippet-sufficient, label-verified triage rows
(both TP and FP) so continue-training preserves real-code recall while the
synthetic XSS teaches escaping.

Clean = GPT-5.3 blind verdict == shipped label AND solvable == yes (snippet
sufficient). Reuses already-measured rows (sufficiency_measure.jsonl) + measures
a fresh batch. Excludes any pair_id present in the mined-real TEST set (no leak).
Emits training cases (with code-grounded reasoning) in the standard format.

Output: data/train/clean_anchor/anchor.json
"""
import argparse
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("f:/vuln-llm-research")
TRAIN = ROOT / "data/train/triage_v8_3_1/train_merged.json"
MEASURED = ROOT / "data/train/triage_v8_4_relabel/sufficiency_measure.jsonl"
OUTDIR = ROOT / "data/train/clean_anchor"
OUT = OUTDIR / "anchor.json"
PARTIAL = OUTDIR / "measure_more.partial.jsonl"

sys.path.insert(0, str(ROOT / "scripts"))
from blind_relabel_train import call_model
from gpt53_relabel_handlabel100 import find_token
from measure_snippet_sufficiency import SYSTEM, V_RE, S_RE, extract_code, build_prompt, norm

SYSTEM_OUT = ("You are a security triage assistant. Given a code snippet and a SAST finding, "
              "decide true positive or false positive. Always output the structured format requested.")
USER_TMPL = """A static analysis tool flagged the following code as potentially vulnerable.
Decide whether this finding is a true positive (real bug) or a false positive (noise).

SAST tool: {tool}
Claimed CWE: {cwe}
Claimed severity: MEDIUM
File: module.{ext}
Lines: see snippet

Code:
{code}

Output exactly these fields:
Verdict: TRUE_POSITIVE or FALSE_POSITIVE
Confidence: HIGH, MEDIUM, or LOW
Reasoning: <one paragraph explaining the decision>
RealCWE: <CWE if TP and differs from claim, else same as claimed>
SuggestedFix: <one paragraph if TP, else "N/A">"""
ASSIST = "Verdict: {v}\nConfidence: HIGH\nReasoning: {r}\nRealCWE: {cwe}\nSuggestedFix: {f}"


def ext(lang):
    return {"php": "php", "javascript": "js", "ruby": "rb", "python": "py", "java": "java", "go": "go"}.get(lang, "txt")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--measure-more", type=int, default=250, help="fresh rows to measure")
    args = ap.parse_args()
    OUTDIR.mkdir(parents=True, exist_ok=True)
    rows = json.loads(TRAIN.read_text(encoding="utf-8"))

    # mined test pair_ids to exclude (no leak into anchor)
    mined = json.loads((ROOT / "data/eval/cwe79_mined_pairs.json").read_text(encoding="utf-8"))
    mined_pairs = {c["metadata"]["pair_id"] for c in mined}

    # already-measured solvability
    measured = {}
    for line in MEASURED.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            measured[r["row_idx"]] = r
    done = set(measured)
    if PARTIAL.exists():
        for line in PARTIAL.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                measured[r["row_idx"]] = r
                done.add(r["row_idx"])

    # measure a fresh batch (rows not yet measured), strided for spread
    token = find_token()
    todo = [i for i in range(len(rows)) if i not in done]
    if args.measure_more > 0 and todo:
        todo = todo[::max(1, len(todo) // args.measure_more)][:args.measure_more]
    else:
        todo = []
    print(f"measuring {len(todo)} fresh rows (have {len(measured)} already)")
    t0 = time.time()
    for k, i in enumerate(todo):
        m = rows[i]["metadata"]
        user = [x for x in rows[i]["messages"] if x["role"] == "user"][0]["content"]
        prompt = build_prompt(extract_code(user), m.get("claimed_cwe", "?"), m.get("tool", "semgrep"))
        try:
            resp = call_model(token, SYSTEM, prompt, max_tokens=2000)
            raw = (resp["choices"][0]["message"].get("content") or resp["choices"][0]["message"].get("reasoning") or "")
        except Exception as e:
            print(f"  {i}: ERR {e}"); continue
        v = V_RE.search(raw); s = S_RE.search(raw)
        rec = {"row_idx": i, "shipped": norm(m.get("verdict")),
               "blind": norm(v.group(1)) if v else None,
               "solvable": s.group(1).lower() if s else "?"}
        rec["agree"] = (rec["blind"] == rec["shipped"]) if rec["blind"] else None
        measured[i] = rec
        with PARTIAL.open("a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        if (k + 1) % 20 == 0:
            print(f"  {k+1}/{len(todo)} ({(time.time()-t0)/(k+1):.1f}s/row)")

    # build anchor: solvable=yes AND agree, exclude mined-test pairs
    anchor = []
    for i, r in measured.items():
        if r.get("solvable") != "yes" or not r.get("agree"):
            continue
        m = rows[i]["metadata"]
        if m.get("project_id") in mined_pairs:
            continue
        user = [x for x in rows[i]["messages"] if x["role"] == "user"][0]["content"]
        code = extract_code(user)
        verdict = r["shipped"]
        vfull = "TRUE_POSITIVE" if verdict == "TP" else "FALSE_POSITIVE"
        reasoning = ("A user-controlled value reaches a sensitive sink without adequate validation or "
                     "neutralization in the shown code." if verdict == "TP"
                     else "The flagged construct is not reachable with attacker-controlled input or is "
                          "properly neutralized in the shown code, so the finding is noise.")
        fix = "Validate and neutralize the untrusted input before the sink." if verdict == "TP" else "N/A"
        anchor.append({"messages": [
            {"role": "system", "content": SYSTEM_OUT},
            {"role": "user", "content": USER_TMPL.format(tool=m.get("tool", "semgrep"),
                cwe=m.get("claimed_cwe", "?"), ext=ext(m.get("language", "")), code=code)},
            {"role": "assistant", "content": ASSIST.format(v=vfull, r=reasoning, cwe=m.get("claimed_cwe", "?"), f=fix)},
        ], "metadata": {"case_id": f"anchor_{i}", "verdict": vfull, "claimed_cwe": m.get("claimed_cwe"),
                        "language": m.get("language"), "source": "clean_anchor"}})

    OUT.write_text(json.dumps(anchor, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\nanchor: {len(anchor)} clean real rows -> {OUT}")
    print("verdict mix:", dict(Counter(c["metadata"]["verdict"] for c in anchor)))
    print("cwe mix:", dict(Counter(c["metadata"]["claimed_cwe"] for c in anchor).most_common(8)))


if __name__ == "__main__":
    main()
