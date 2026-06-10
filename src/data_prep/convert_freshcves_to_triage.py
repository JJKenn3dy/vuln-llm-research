"""Convert the fresh-CVE detection eval (60 hand-crafted post-Sep-2024 cases)
into our triage TP/FP format.

Source: imported from the BSc archive at f:/diplom/_freshtest/. Each pair is a
hand-crafted CVE + its fixed counterpart, covering 11 CWEs across PHP / Python /
JavaScript. Original detection eval reported F1=0.76, BalAcc=0.80 by v5b.

Why we need it as a triage eval:
1. **Post-pretrain validation.** Qwen2.5-Coder-7B pretrain cutoff is ~Sep 2024.
   These cases were crafted after that, so they are anti-contamination.
2. **Real differential pairs.** Each vuln has its exact post-fix counterpart in
   the same file. This is the pre/post structure v8.1 lacked.
3. **Free.** Already validated, no cost to convert.

Mapping:
  - label = "vulnerable" -> TRUE_POSITIVE (SAST correctly flagged a real bug)
  - label = "safe" (post-fix) -> FALSE_POSITIVE (SAST would still flag the same
    code pattern under the same CWE, but the fix is applied)

This file is detection-format; we re-emit as triage chat with
TRIAGE_USER_TEMPLATE.

Usage:
    python -m src.data_prep.convert_freshcves_to_triage \\
        --input data/eval/fresh_cves_60_detection.json \\
        --output data/eval/fresh_cves_60_triage.json
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path

from src.utils.prompts import TRIAGE_SYSTEM, TRIAGE_USER_TEMPLATE


def extract_code(user_message: str) -> str:
    m = re.search(r"Code:\s*\n(.*?)(?:\n\nAnswer:|\Z)", user_message, re.DOTALL)
    return m.group(1).strip() if m else user_message


def extract_language(user_message: str) -> str:
    m = re.search(r"Language/Context:\s*\n([A-Za-z0-9+/_\- ]+)", user_message)
    return m.group(1).strip() if m else "unknown"


def base_cve_id(cve_id: str) -> str:
    """Strip the '-fix' suffix so each pair has the same project_id."""
    return cve_id.rsplit("-fix", 1)[0] if cve_id.endswith("-fix") else cve_id


def build_triage_example(detection_item: dict) -> dict | None:
    md = detection_item["metadata"]
    label = md.get("label")
    if label not in {"vulnerable", "safe"}:
        return None

    user_msg = detection_item["messages"][1]["content"]
    code = extract_code(user_msg)
    language = extract_language(user_msg)
    cwe = md.get("cwe_id", "CWE-?")
    cve = md.get("cve_id", "")
    project_id = base_cve_id(cve)

    if label == "vulnerable":
        verdict = "TRUE_POSITIVE"
        # We do not synthesise a per-sample reasoning here. The reasoning field
        # is filled at eval time by the model under test. For the gold answer
        # we use a short placeholder; the eval scorer reads `metadata.verdict`,
        # not the reasoning, so this is fine for a test-only set.
        reasoning = f"The flagged code does contain a {cwe} vulnerability."
        real_cwe = cwe
        suggested_fix = "Refer to the fixed counterpart in the pair."
    else:
        verdict = "FALSE_POSITIVE"
        reasoning = (
            f"This code is the post-fix counterpart of the matching pre-fix sample. "
            f"The {cwe} vulnerability has been remediated."
        )
        real_cwe = "N/A"
        suggested_fix = "N/A"

    user = TRIAGE_USER_TEMPLATE.format(
        tool="semgrep",
        cwe=cwe,
        severity="MEDIUM",
        file_path=f"<{cve}>",
        line_range="see snippet",
        code=code,
    )

    assistant = (
        f"Verdict: {verdict}\n"
        f"Confidence: HIGH\n"
        f"Reasoning: {reasoning}\n"
        f"RealCWE: {real_cwe}\n"
        f"SuggestedFix: {suggested_fix}\n"
    )

    return {
        "messages": [
            {"role": "system", "content": TRIAGE_SYSTEM},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "metadata": {
            "case_id": cve,
            "project_id": project_id,
            "claimed_cwe": cwe,
            "real_cwe": real_cwe if verdict == "TRUE_POSITIVE" else cwe,
            "verdict": verdict,
            "language": language,
            "tool": "semgrep",
            "source": "fresh_cves_60",
            "post_pretrain_cutoff": True,
        },
    }


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Convert fresh-CVE detection eval to triage format")
    p.add_argument("--input", required=True)
    p.add_argument("--output", required=True)
    return p.parse_args()


def main() -> None:
    args = parse_args()
    with open(args.input, encoding="utf-8") as f:
        detection = json.load(f)

    examples = [e for e in (build_triage_example(d) for d in detection) if e is not None]

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(examples, f, ensure_ascii=False, indent=2)

    verdicts = Counter(e["metadata"]["verdict"] for e in examples)
    langs = Counter(e["metadata"]["language"] for e in examples)
    cwes = Counter(e["metadata"]["claimed_cwe"] for e in examples)
    projects = len({e["metadata"]["project_id"] for e in examples})

    print(f"Wrote {len(examples)} triage examples to {args.output}")
    print(f"  TP={verdicts.get('TRUE_POSITIVE', 0)} FP={verdicts.get('FALSE_POSITIVE', 0)}")
    print(f"  unique project_ids (CVE bases): {projects}")
    print(f"  by language: {dict(langs.most_common())}")
    print(f"  by CWE: {dict(cwes.most_common())}")


if __name__ == "__main__":
    main()
