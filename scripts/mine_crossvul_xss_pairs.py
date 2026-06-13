"""Mine real matched CWE-79 vuln/safe pairs from CrossVul vuln/fixed files.

CrossVul ships vulnerable + patched versions of the same file. Our train data
preserves the pairing (project_id=crossvul-pair-N, verdict TP=vulnerable,
FP=fixed). The fix is the real-world escaping change. We diff the two, locate
the changed hunk (= the sink + the escape that was added), and extract a
focused window around it from BOTH versions -> a matched pair where the ONLY
difference is the escaping, the sink is in-window by construction, the code is
real, and the labels are grounded in a real CVE fix.

This is the v8.4 training signal: escaping = the discriminator (the thing the
killer test proved v8.3.1 is blind to). Output split into train/test, with a
GPT-5.3-validatable sample.

Output: data/eval/cwe79_mined_pairs.json
"""
import argparse
import difflib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("f:/vuln-llm-research")
TRAIN = ROOT / "data/train/triage_v8_3_1/train_merged.json"
OUT = ROOT / "data/eval/cwe79_mined_pairs.json"

SYSTEM = ("You are a security triage assistant. Given a code snippet and a SAST finding "
          "(alleged vulnerability), decide whether the finding is a true positive or a "
          "false positive. Always output plain text in the structured format requested.")
USER_TMPL = """A static analysis tool flagged the following code as potentially vulnerable.
Decide whether this finding is a true positive (real bug) or a false positive (noise).

SAST tool: semgrep
Claimed CWE: CWE-79
Claimed severity: MEDIUM
File: {fname}
Lines: see snippet

Code:
{code}

Output exactly these fields:
Verdict: TRUE_POSITIVE or FALSE_POSITIVE
Confidence: HIGH, MEDIUM, or LOW
Reasoning: <one paragraph explaining the decision>
RealCWE: <CWE if TP and differs from claim, else same as claimed>
SuggestedFix: <one paragraph if TP, else "N/A">"""

ESC_KW = ["htmlspecialchars", "htmlentities", "escape", "sanitiz", "encodeur", "strip_tags",
          "filter_var", "ent_quotes", "purify", "textcontent", "bluemonday", "->text(",
          ".text(", "escapehtml", "esc_html", "esc_attr", "h(", "cgi.escape", "markupsafe",
          "dompurify", "encode(", "htmlescape", "e(", "safe_join"]


def code_of(r):
    u = [x for x in r["messages"] if x["role"] == "user"][0]["content"]
    return u.split("Code:", 1)[1].split("\nOutput exactly", 1)[0].strip() if "Code:" in u else u


def extract_window(lines, changed_idx, ctx=14, max_lines=45):
    """Window around the changed line indices, capped."""
    if not changed_idx:
        return "\n".join(lines[:max_lines])
    lo = max(0, min(changed_idx) - ctx)
    hi = min(len(lines), max(changed_idx) + 1 + ctx)
    if hi - lo > max_lines:
        hi = lo + max_lines
    return "\n".join(lines[lo:hi])


def mine():
    tr = json.loads(TRAIN.read_text(encoding="utf-8"))
    tr79 = [r for r in tr if r["metadata"].get("claimed_cwe") == "CWE-79"
            and r["metadata"].get("source") == "crossvul"]
    bypair = defaultdict(dict)
    for r in tr79:
        bypair[r["metadata"]["project_id"]][r["metadata"]["verdict"]] = r

    mined = []
    for pid, d in sorted(bypair.items()):
        if "TRUE_POSITIVE" not in d or "FALSE_POSITIVE" not in d:
            continue
        vuln = code_of(d["TRUE_POSITIVE"]).splitlines()   # vulnerable (pre-fix)
        safe = code_of(d["FALSE_POSITIVE"]).splitlines()  # fixed (post-fix)
        sm = difflib.SequenceMatcher(None, vuln, safe)
        total = max(len(vuln), len(safe))
        changed = sum(max(i2 - i1, j2 - j1) for t, i1, i2, j1, j2 in sm.get_opcodes() if t != "equal")
        if total == 0 or changed / total >= 0.25:
            continue  # not localized
        # Find the SPECIFIC changed hunk whose added lines contain an escape
        # call, and window around THAT (not the first/union of all diffs, which
        # may be a docblock/whitespace edit). This keeps the visible difference
        # = the escaping, not noise.
        v_idx, s_idx = [], []
        for t, i1, i2, j1, j2 in sm.get_opcodes():
            if t == "equal":
                continue
            added_here = " ".join(safe[j] for j in range(j1, j2)).lower()
            if any(k in added_here for k in ESC_KW):
                v_idx += list(range(i1, i2))
                s_idx += list(range(j1, j2))
        if not (v_idx or s_idx):
            continue  # no escaping hunk -> skip ambiguous pair
        # for pure-insert escaping (i1==i2), anchor vuln window near the sink line
        if not v_idx and s_idx:
            # map: vuln line nearest the inserted safe region
            v_anchor = min(len(vuln) - 1, s_idx[0])
            v_idx = [v_anchor]
        lang = d["TRUE_POSITIVE"]["metadata"].get("language", "?")
        fname = f"{lang}_module"
        vuln_win = extract_window(vuln, v_idx)
        safe_win = extract_window(safe, s_idx)
        if vuln_win.strip() == safe_win.strip():
            continue  # window didn't capture the diff
        for variant, win, verdict in [("vuln", vuln_win, "TRUE_POSITIVE"),
                                      ("safe", safe_win, "FALSE_POSITIVE")]:
            mined.append({
                "messages": [
                    {"role": "system", "content": SYSTEM},
                    {"role": "user", "content": USER_TMPL.format(fname=f"{fname}.{('php' if lang=='php' else 'js')}", code=win)},
                ],
                "metadata": {
                    "case_id": f"mined79_{pid}_{variant}", "pair_id": pid, "variant": variant,
                    "claimed_cwe": "CWE-79", "real_cwe": "CWE-79", "verdict": verdict,
                    "language": lang, "tool": "semgrep", "source": "crossvul_mined",
                },
            })
    return mined


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--test-frac", type=float, default=0.3)
    args = ap.parse_args()
    mined = mine()
    n_pairs = len({c["metadata"]["pair_id"] for c in mined})
    print(f"mined {len(mined)} cases from {n_pairs} real crossvul XSS-fix pairs")
    from collections import Counter
    print("langs:", dict(Counter(c["metadata"]["language"] for c in mined)))
    OUT.write_text(json.dumps(mined, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"saved -> {OUT}")


if __name__ == "__main__":
    main()
