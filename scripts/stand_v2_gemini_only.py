"""Stand v2, judge B only: Gemini 3.1 Pro blind verdicts for exam_a.

Cost-reduction rework (2026-07-03): judge A (Anthropic side) moved to Claude
subscription agents ($0, precedent: exp5 Opus-as-teacher smoke), so the paid
OpenRouter part is Gemini only (~$0.007/case). Cases that already have a
gemini verdict in runs/stand_v2_raw.partial.jsonl (27 from the dual run) are
reused, not re-paid.

Output: runs/stand_v2_gemini.partial.jsonl (one line per case: case_id,
gemini_verdict, gemini_raw, cost). Resume-safe.
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
BUDGET = 3.0


def main():
    token = find_token()
    pool = json.loads((ROOT / "data/exam/exam_a_in_scope_300.json").read_text(encoding="utf-8"))

    done = {}
    dual = ROOT / "runs/stand_v2_raw.partial.jsonl"
    if dual.exists():
        for ln in dual.read_text(encoding="utf-8").splitlines():
            if ln.strip():
                r = json.loads(ln)
                if norm(r.get("gemini_verdict")) != "PARSE_FAIL":
                    done[r["case_id"]] = {"case_id": r["case_id"],
                                          "gemini_verdict": r["gemini_verdict"],
                                          "gemini_raw": r["gemini_raw"], "cost": 0.0,
                                          "source": "dual_run"}
    out = ROOT / "runs/stand_v2_gemini.partial.jsonl"
    if out.exists():
        for ln in out.read_text(encoding="utf-8").splitlines():
            if ln.strip():
                r = json.loads(ln); done[r["case_id"]] = r
    else:
        with out.open("w", encoding="utf-8", newline="\n") as f:
            for r in done.values():
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    spent = 0.0
    for i, c in enumerate(pool):
        cid = c["metadata"]["case_id"]
        if cid in done:
            continue
        if spent > BUDGET:
            print(f"[BUDGET STOP] ${spent:.2f} at {i}/{len(pool)}"); break
        system = [x for x in c["messages"] if x["role"] == "system"][0]["content"]
        user = [x for x in c["messages"] if x["role"] == "user"][0]["content"]
        try:
            raw, cost = call(token, GEMINI, system, user)
        except RuntimeError as e:
            if "OUT_OF_CREDITS" in str(e):
                print(f"[402] at {i}/{len(pool)}"); break
            print(f"{cid}: ERROR {e}"); continue
        v = VERDICT_RE.search(raw); v = norm(v.group(1)) if v else "PARSE_FAIL"
        spent += cost
        rec = {"case_id": cid, "gemini_verdict": v, "gemini_raw": raw,
               "cost": cost, "source": "gemini_only"}
        done[cid] = rec
        with out.open("a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        print(f"{i+1:>3d}/{len(pool)} {cid[:30]:<30} {v[:2]} ${spent:.2f}", flush=True)

    print(f"DONE total={len(done)}/{len(pool)} new_spent=${spent:.3f}")


if __name__ == "__main__":
    main()
