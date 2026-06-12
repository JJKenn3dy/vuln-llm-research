"""Take a ranker SARIF, pick top-K findings by p_tp, emit messages-format
JSON for src.eval.run_triage_eval (filter mode → reasoning + verdict).

Output rows are aligned by index to the input top-K, so the report renderer
can match them back without case_id round-trip.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from src.utils.prompts import TRIAGE_SYSTEM, TRIAGE_USER_TEMPLATE
from src.product.report import extract_findings


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ranker-sarif", required=True)
    p.add_argument("--top-k", type=int, default=15)
    p.add_argument("--out", required=True)
    args = p.parse_args()

    sarif = json.loads(Path(args.ranker_sarif).read_text(encoding="utf-8"))
    rows = extract_findings(sarif)
    rows.sort(key=lambda r: (-(r["p_tp"] if r["p_tp"] is not None else -1.0)))
    top = rows[:args.top_k]

    out = []
    for i, r in enumerate(top):
        user = TRIAGE_USER_TEMPLATE.format(
            tool=r.get("tool") or "unknown",
            cwe=r.get("claimed_cwe") or "unknown",
            severity="HIGH",
            file_path=r.get("file_path") or "unknown",
            line_range=f'{r.get("line_start") or 1}-{r.get("line_end") or r.get("line_start") or 1}',
            code=r.get("snippet") or "",
        )
        out.append({
            "case_id": f"top_{i}",
            "messages": [
                {"role": "system", "content": TRIAGE_SYSTEM},
                {"role": "user", "content": user},
            ],
            "metadata": {
                "finding_key": r["finding_key"],
                "rank": i + 1,
                "p_tp": r["p_tp"],
                "claimed_cwe": r["claimed_cwe"],
                "file_path": r["file_path"],
                "line_start": r["line_start"],
            },
        })
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {len(out)} eval rows to {args.out}")


if __name__ == "__main__":
    main()
