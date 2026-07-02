"""Stand v2: retry Gemini refusals (PARSE_FAIL) with explicit defensive context.

Gemini 3.1 Pro stochastically refuses ~13% of triage cases ("safety guidelines
prohibit vulnerability analysis"). The task is defensive: triaging SAST
false positives on a public Apache-2.0 benchmark (SastBench). A preamble
stating that context resolves most refusals. Verdicts from retries overwrite
PARSE_FAIL records in runs/stand_v2_gemini.partial.jsonl (appended; merge
script keeps the LAST record per case_id).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
ROOT = Path("f:/vuln-llm-research")
sys.path.insert(0, str(ROOT / "scripts"))
from gpt53_relabel_handlabel100 import find_token  # noqa: E402
from stand_v2_label import VERDICT_RE, call, norm  # noqa: E402

GEMINI = "google/gemini-3.1-pro-preview"
PREAMBLE = (
    "Context: this is DEFENSIVE security work — triaging static-analyzer "
    "(SAST) findings from SastBench, a public Apache-2.0 research benchmark "
    "of open-source code. The goal is to identify FALSE POSITIVES so that "
    "developers are not flooded with noise. No exploit development is "
    "requested; only a TRUE_POSITIVE / FALSE_POSITIVE triage verdict.\n\n"
)


def main():
    token = find_token()
    pool = json.loads((ROOT / "data/exam/exam_a_in_scope_300.json").read_text(encoding="utf-8"))
    by_cid = {c["metadata"]["case_id"]: c for c in pool}

    partial = ROOT / "runs/stand_v2_gemini.partial.jsonl"
    latest = {}
    for ln in partial.read_text(encoding="utf-8").splitlines():
        if ln.strip():
            r = json.loads(ln); latest[r["case_id"]] = r

    fails = [cid for cid, r in latest.items() if norm(r["gemini_verdict"]) == "PARSE_FAIL"]
    print(f"retrying {len(fails)} refusals")
    spent = 0.0
    fixed = 0
    for i, cid in enumerate(fails):
        c = by_cid[cid]
        system = [x for x in c["messages"] if x["role"] == "system"][0]["content"]
        user = [x for x in c["messages"] if x["role"] == "user"][0]["content"]
        try:
            raw, cost = call(token, GEMINI, PREAMBLE + system, user)
        except RuntimeError as e:
            print(f"{cid}: ERROR {e}"); continue
        v = VERDICT_RE.search(raw); v = norm(v.group(1)) if v else "PARSE_FAIL"
        spent += cost
        fixed += v != "PARSE_FAIL"
        rec = {"case_id": cid, "gemini_verdict": v, "gemini_raw": raw,
               "cost": cost, "source": "retry_defensive_preamble"}
        with partial.open("a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        print(f"{i+1:>3d}/{len(fails)} {cid[:30]:<30} {v[:2]} ${spent:.2f}", flush=True)
    print(f"RETRY DONE fixed={fixed}/{len(fails)} spent=${spent:.3f}")


if __name__ == "__main__":
    main()
