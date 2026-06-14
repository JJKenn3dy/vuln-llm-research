"""Build a filtered web-CWE training set from CyberNative DPO pairs (v8.4).

Source: CyberNative/Code_Vulnerability_Security_DPO (HF, Apache 2.0), 4656
synthetic vuln/safe pairs. `rejected`=vulnerable, `chosen`=fixed. Inspection
(2026-06-14): right shape (self-contained, snippet-sufficient, escaping is the
discriminator) but ~9% have generation garbage (CJK/non-ASCII injected into
code) and ~29% of XSS use encodeURIComponent (weak HTML fix). GPT-5.3 still
discriminates 94% -> the core "raw=vuln, processed=safe" signal is clean.

This is the v8.4 training signal (the thing v8.3.1 is blind to per the killer
test). Filtering:
  - drop pairs with non-ASCII garbage in either code (unparseable)
  - strip markdown fences
  - drop empty / identical pairs
  - keep web-relevant CWEs (XSS / SQLi / injection), tag each
  - dedup by code hash

NOT mixed with the old snippet-insufficient pile (that taught the blindness).
Old-model knowledge is preserved by continue-training FROM the v8.3.1 adapter,
not by re-feeding old rows. Test sets (hand-built 20, mined-real) stay separate
to measure generalization, not memorization.

Output: data/train/cwe_web_cybernative/train.json (+ per-CWE counts)
"""
import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("f:/vuln-llm-research")
PARQUET = Path("f:/tmp/cybernative_dpo.parquet")
OUTDIR = ROOT / "data/train/cwe_web_cybernative"

SYSTEM = ("You are a security triage assistant. Given a code snippet and a SAST finding "
          "(alleged vulnerability), decide whether the finding is a true positive or a "
          "false positive. Always output plain text in the structured format requested.")
USER_TMPL = """A static analysis tool flagged the following code as potentially vulnerable.
Decide whether this finding is a true positive (real bug) or a false positive (noise).

SAST tool: semgrep
Claimed CWE: {cwe}
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

ASSIST = """Verdict: {verdict}
Confidence: {conf}
Reasoning: {reasoning}
RealCWE: {cwe}
SuggestedFix: {fix}"""

CWE_MAP = [  # (keyword in 'vulnerability' text, CWE id)
    ("cross-site", "CWE-79"), ("xss", "CWE-79"),
    ("sql injection", "CWE-89"), ("sql-injection", "CWE-89"),
    ("command injection", "CWE-78"), ("os command", "CWE-78"),
    ("code injection", "CWE-94"), ("eval", "CWE-94"),
    ("deserializ", "CWE-502"), ("pickle", "CWE-502"),
    ("path traversal", "CWE-22"), ("directory traversal", "CWE-22"),
]
WEB_CWES = {"CWE-79", "CWE-89", "CWE-78", "CWE-94", "CWE-22", "CWE-502"}


def cwe_of(vtext):
    v = (vtext or "").lower()
    for kw, cwe in CWE_MAP:
        if kw in v:
            return cwe
    return None


def strip_md(s):
    s = (s or "").strip()
    s = re.sub(r"^```[a-zA-Z+#]*\n?", "", s)
    s = s.replace("```", "").strip()
    return s


def has_garbage(s):
    # CJK / private-use / injected non-code unicode in the 0x2000-0xFFFF band
    return any(0x2000 < ord(c) < 0xFFFF for c in (s or ""))


def ext(lang):
    return {"php": "php", "javascript": "js", "ruby": "rb", "python": "py",
            "java": "java", "c#": "cs", "go": "go"}.get(lang, "txt")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cwes", default="CWE-79", help="comma list or 'all-web'")
    ap.add_argument("--drop-encodeuri", action="store_true",
                    help="drop XSS pairs whose fix is encodeURIComponent (weak HTML fix)")
    ap.add_argument("--with-reasoning", action="store_true",
                    help="include a short generic reasoning in assistant target")
    args = ap.parse_args()
    want = WEB_CWES if args.cwes == "all-web" else set(args.cwes.split(","))

    import pyarrow.parquet as pq
    rows = pq.read_table(str(PARQUET)).to_pylist()

    OUTDIR.mkdir(parents=True, exist_ok=True)
    cases, seen = [], set()
    drop_cwe = drop_garbage = drop_dup = drop_weakfix = drop_empty = 0
    for i, r in enumerate(rows):
        cwe = cwe_of(r["vulnerability"])
        if cwe not in want:
            drop_cwe += 1
            continue
        vuln = strip_md(r["rejected"]); safe = strip_md(r["chosen"])
        if not vuln or not safe or vuln == safe:
            drop_empty += 1
            continue
        if has_garbage(vuln) or has_garbage(safe):
            drop_garbage += 1
            continue
        if args.drop_encodeuri and cwe == "CWE-79" and "encodeuricomponent" in safe.lower():
            drop_weakfix += 1
            continue
        h = hashlib.md5((vuln + "|" + safe).encode()).hexdigest()[:12]
        if h in seen:
            drop_dup += 1
            continue
        seen.add(h)
        lang = r["lang"]
        pid = f"cn_{cwe.replace('CWE-','')}_{i:04d}"
        for variant, code, verdict in [("vuln", vuln, "TRUE_POSITIVE"), ("safe", safe, "FALSE_POSITIVE")]:
            msgs = [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": USER_TMPL.format(cwe=cwe, fname=f"module.{ext(lang)}", code=code)},
            ]
            if args.with_reasoning:
                reasoning = ("User-controlled input reaches an output sink without proper "
                             "context-aware escaping." if verdict == "TRUE_POSITIVE"
                             else "User input is escaped/sanitized before the sink, so the finding is noise.")
                fix = ("Apply context-appropriate output escaping before the sink." if verdict == "TRUE_POSITIVE" else "N/A")
                msgs.append({"role": "assistant", "content": ASSIST.format(
                    verdict=verdict, conf="HIGH", reasoning=reasoning, cwe=cwe, fix=fix)})
            cases.append({"messages": msgs, "metadata": {
                "case_id": f"{pid}_{variant}", "pair_id": pid, "variant": variant,
                "claimed_cwe": cwe, "real_cwe": cwe, "verdict": verdict,
                "language": lang, "tool": "semgrep", "source": "cybernative"}})

    # train/val split by pair_id (last 10% of pairs -> val), keeps both
    # variants of a pair on the same side. Deterministic (sorted), no RNG.
    pair_ids = sorted({c["metadata"]["pair_id"] for c in cases})
    n_val = max(2, len(pair_ids) // 10)
    val_ids = set(pair_ids[-n_val:])
    train_cases = [c for c in cases if c["metadata"]["pair_id"] not in val_ids]
    val_cases = [c for c in cases if c["metadata"]["pair_id"] in val_ids]
    (OUTDIR / "train.json").write_text(json.dumps(train_cases, ensure_ascii=False, indent=1), encoding="utf-8")
    (OUTDIR / "val.json").write_text(json.dumps(val_cases, ensure_ascii=False, indent=1), encoding="utf-8")
    cases = train_cases  # downstream meta reflects train
    npairs = len({c["metadata"]["pair_id"] for c in cases})
    print(f"split: {len(train_cases)} train / {len(val_cases)} val cases (val pairs={n_val})")
    meta = {
        "n_cases": len(cases), "n_pairs": npairs,
        "cwe_mix": dict(Counter(c["metadata"]["claimed_cwe"] for c in cases)),
        "lang_mix": dict(Counter(c["metadata"]["language"] for c in cases)),
        "dropped": {"wrong_cwe": drop_cwe, "garbage": drop_garbage, "dup": drop_dup,
                    "weak_fix_encodeuri": drop_weakfix, "empty_or_identical": drop_empty},
        "with_reasoning": args.with_reasoning, "cwes": sorted(want),
    }
    (OUTDIR / "build_meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"train: {len(cases)} cases / {npairs} pairs -> {OUTDIR/'train.json'}")
    print("cwe mix:", meta["cwe_mix"])
    print("lang mix:", meta["lang_mix"])
    print("dropped:", meta["dropped"])


if __name__ == "__main__":
    main()
