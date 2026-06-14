"""Scale the real anchor for v8.4-exp3: more real TP/FP from CrossVul.

exp2 lifted gold-core MCC to +0.517 but recall on balanced real pairs stayed
low (only 40 mined + 9 old TPs in train). Lever: more REAL snippet-sufficient
vulnerable examples. Mine CrossVul localized vuln/fixed pairs across web CWEs
(79/89/78/94/22), window around the main changed hunk, label vuln->TP / fixed->FP.

Strictly exclude the 31 CWE-79 held-out TEST pairs (no leak). The 40 CWE-79
pairs already used in exp2 train are fine to reuse.

Output: data/train/real_anchor_scaled/anchor.json  (training format w/ targets)
"""
import difflib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("f:/vuln-llm-research")
TRAIN = ROOT / "data/train/triage_v8_3_1/train_merged.json"
HELDOUT = ROOT / "data/eval/cwe79_mined_heldout.json"
OUTDIR = ROOT / "data/train/real_anchor_scaled"
OUT = OUTDIR / "anchor.json"

WEB_CWES = {"CWE-79", "CWE-89", "CWE-78", "CWE-94", "CWE-22"}

SYSTEM = ("You are a security triage assistant. Given a code snippet and a SAST finding, "
          "decide true positive or false positive. Always output the structured format requested.")
USER_TMPL = """A static analysis tool flagged the following code as potentially vulnerable.
Decide whether this finding is a true positive (real bug) or a false positive (noise).

SAST tool: semgrep
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


def code_of(r):
    u = [x for x in r["messages"] if x["role"] == "user"][0]["content"]
    return u.split("Code:", 1)[1].split("\nOutput exactly", 1)[0].strip() if "Code:" in u else u


def window(lines, idx, ctx=14, mx=45):
    if not idx:
        return "\n".join(lines[:mx])
    lo = max(0, min(idx) - ctx); hi = min(len(lines), max(idx) + 1 + ctx)
    if hi - lo > mx:
        hi = lo + mx
    return "\n".join(lines[lo:hi])


def ext(lang):
    return {"php": "php", "javascript": "js", "ruby": "rb", "python": "py", "java": "java", "go": "go"}.get(lang, "txt")


def main():
    OUTDIR.mkdir(parents=True, exist_ok=True)
    rows = json.loads(TRAIN.read_text(encoding="utf-8"))
    heldout_pairs = {c["metadata"]["pair_id"] for c in json.loads(HELDOUT.read_text(encoding="utf-8"))}

    cv = [r for r in rows if r["metadata"].get("source") == "crossvul"
          and r["metadata"].get("claimed_cwe") in WEB_CWES]
    bypair = defaultdict(dict)
    for r in cv:
        bypair[r["metadata"]["project_id"]][r["metadata"]["verdict"]] = r

    anchor = []
    kept_pairs = 0
    for pid, d in sorted(bypair.items()):
        if pid in heldout_pairs:
            continue  # NO leak
        if "TRUE_POSITIVE" not in d or "FALSE_POSITIVE" not in d:
            continue
        vuln = code_of(d["TRUE_POSITIVE"]).splitlines()
        safe = code_of(d["FALSE_POSITIVE"]).splitlines()
        sm = difflib.SequenceMatcher(None, vuln, safe)
        total = max(len(vuln), len(safe))
        changed = sum(max(i2 - i1, j2 - j1) for t, i1, i2, j1, j2 in sm.get_opcodes() if t != "equal")
        if total == 0 or changed / total >= 0.25:
            continue  # not localized
        # window around the largest changed hunk (proxy for the fix site)
        best, bv, bs = 0, [], []
        for t, i1, i2, j1, j2 in sm.get_opcodes():
            if t == "equal":
                continue
            sz = max(i2 - i1, j2 - j1)
            if sz > best:
                best, bv, bs = sz, list(range(i1, i2)), list(range(j1, j2))
        cwe = d["TRUE_POSITIVE"]["metadata"].get("claimed_cwe", "CWE-79")
        lang = d["TRUE_POSITIVE"]["metadata"].get("language", "?")
        vw, sw = window(vuln, bv or [0]), window(safe, bs or [0])
        if vw.strip() == sw.strip():
            continue
        kept_pairs += 1
        for code, verdict in [(vw, "TRUE_POSITIVE"), (sw, "FALSE_POSITIVE")]:
            if verdict == "TRUE_POSITIVE":
                r = "A user-controlled value reaches a sensitive sink without adequate neutralization in the shown code."
                f = "Validate and neutralize the untrusted input before the sink."
            else:
                r = "The flagged construct is neutralized or not reachable with attacker input in the shown code."
                f = "N/A"
            anchor.append({"messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": USER_TMPL.format(cwe=cwe, ext=ext(lang), code=code)},
                {"role": "assistant", "content": ASSIST.format(v=verdict, r=r, cwe=cwe, f=f)},
            ], "metadata": {"case_id": f"ra_{pid}_{verdict[:2]}", "pair_id": pid, "verdict": verdict,
                            "claimed_cwe": cwe, "language": lang, "source": "real_anchor_scaled"}})

    OUT.write_text(json.dumps(anchor, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"scaled real anchor: {len(anchor)} cases / {kept_pairs} pairs -> {OUT}")
    print("verdict mix:", dict(Counter(c["metadata"]["verdict"] for c in anchor)))
    print("cwe mix:", dict(Counter(c["metadata"]["claimed_cwe"] for c in anchor)))
    print("lang mix:", dict(Counter(c["metadata"]["language"] for c in anchor)))


if __name__ == "__main__":
    main()
