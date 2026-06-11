"""Convert the raw ywh_dvwa_eval.json into the messages format that
src.eval.run_triage_eval expects.
"""
import json
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from src.utils.prompts import TRIAGE_SYSTEM, TRIAGE_USER_TEMPLATE

IN = Path("f:/vuln-llm-research/data/eval/ywh_dvwa_eval.json")
OUT = Path("f:/vuln-llm-research/data/eval/ywh_dvwa_messages.json")


def main():
    cases = json.loads(IN.read_text(encoding="utf-8"))
    out = []
    for c in cases:
        user = TRIAGE_USER_TEMPLATE.format(
            tool=c.get("tool", "manual"),
            cwe=c["claimed_cwe"],
            severity=c.get("severity", "HIGH"),
            file_path=c.get("file_path", "unknown"),
            line_range="1",
            code=c["code"],
        )
        out.append({
            "case_id": c["case_id"],
            "messages": [
                {"role": "system", "content": TRIAGE_SYSTEM},
                {"role": "user", "content": user},
            ],
            "metadata": {
                "claimed_cwe": c["claimed_cwe"],
                "truth": c["truth"],
                "source": c["source"],
                "category": c["category"],
                "defense_level": c.get("defense_level", "vulnerable"),
                "language": c.get("language", "?"),
            },
        })
    OUT.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {len(out)} eval rows to {OUT}")


if __name__ == "__main__":
    main()
