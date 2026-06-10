"""Convert CVEFixes detection pairs into SAST triage TP/FP pairs.

Methodology (matches SastBench's conceptual framework):
- Each pre-fix code snippet from CVEFixes is a real vulnerability with CVE-validated
  CWE -> TRUE_POSITIVE triage example (the SAST tool's claim matches reality)
- Each post-fix code snippet from CVEFixes is the same code after the fix, with the
  same claimed CWE -> FALSE_POSITIVE triage example (the SAST tool would have flagged
  it but the vulnerability is gone)

This avoids running Semgrep at data-prep time (we don't actually have the tool's
findings on these snippets, but the SastBench logic of "real CVE = TP, fixed code =
FP under the same claim" holds methodologically).

For each output example:
- Prompt: TRIAGE_USER_TEMPLATE rendered with code + claimed CWE + (fake) tool name
- Assistant: structured Verdict / Confidence / Reasoning / RealCWE / SuggestedFix

Project-stratified split (lesson from HISTORY.md: random split inflates OOD by 2x).

Example:

    python -m src.data_prep.prepare_triage_dataset \\
        --input data/train/train_v5b_train.json \\
        --output-dir data/train/triage_v8 \\
        --train-frac 0.7 --val-frac 0.15 --seed 42
"""
from __future__ import annotations

import argparse
import json
import random
import re
from collections import Counter
from pathlib import Path

from src.utils.prompts import TRIAGE_SYSTEM, TRIAGE_USER_TEMPLATE


SAST_TOOLS = ["semgrep", "codeql", "sonarqube", "snyk-code", "bandit"]


def extract_code(user_message: str) -> str:
    """Pull the 'Code:' section out of the v5-style detection prompt."""
    m = re.search(r"Code:\s*\n?(.*?)$", user_message, re.DOTALL)
    return m.group(1).strip() if m else user_message


def extract_language(user_message: str) -> str:
    m = re.search(r"Language/Context:\s*\n?([A-Za-z0-9+/_\- ]+?)(?:\n\n|\nCode:)", user_message)
    return m.group(1).strip() if m else "unknown"


def extract_field(assistant_message: str, field: str) -> str:
    """Pull a single named field out of the v5 structured assistant output."""
    pattern = rf"{field}:\s*(.+?)(?:\n[A-Z]\w+:|$)"
    m = re.search(pattern, assistant_message, re.DOTALL)
    return m.group(1).strip() if m else ""


def make_triage_example(
    code: str,
    language: str,
    claimed_cwe: str,
    real_label: str,
    real_cwe: str,
    original_cause: str,
    original_fix: str,
    project_id: str,
    cve_id: str,
    tool: str,
) -> dict:
    """Build one triage chat example with TP/FP label."""
    user = TRIAGE_USER_TEMPLATE.format(
        tool=tool,
        cwe=claimed_cwe,
        severity="MEDIUM",
        file_path="<redacted>",
        line_range="see snippet",
        code=code,
    )

    if real_label == "vulnerable":
        verdict = "TRUE_POSITIVE"
        reasoning = (
            f"The flagged code does contain a {claimed_cwe} vulnerability. "
            f"{original_cause}".strip()
        )
        suggested_fix = original_fix or "Apply the upstream patch."
    else:
        verdict = "FALSE_POSITIVE"
        reasoning = (
            f"This code does not contain a {claimed_cwe} vulnerability. "
            "Either the alleged sink is protected by validation, the tainted path is "
            "not actually reachable, or the dangerous pattern was already remediated."
        )
        suggested_fix = "N/A"

    assistant = (
        f"Verdict: {verdict}\n"
        f"Confidence: HIGH\n"
        f"Reasoning: {reasoning}\n"
        f"RealCWE: {real_cwe if verdict == 'TRUE_POSITIVE' else 'N/A'}\n"
        f"SuggestedFix: {suggested_fix}\n"
    )

    return {
        "messages": [
            {"role": "system", "content": TRIAGE_SYSTEM},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "metadata": {
            "cve_id": cve_id,
            "project_id": project_id,
            "claimed_cwe": claimed_cwe,
            "real_cwe": real_cwe,
            "verdict": verdict,
            "language": language,
            "tool": tool,
        },
    }


def build_triage_pairs(detection_data: list[dict], seed: int) -> list[dict]:
    """For each detection example produce one triage example.

    The claimed_cwe equals the real CWE (Semgrep correctly identified the class).
    Vulnerable -> TP, Safe -> FP. This matches the SastBench TP/FP framework.
    """
    rng = random.Random(seed)
    out = []
    for entry in detection_data:
        md = entry["metadata"]
        user_msg = entry["messages"][1]["content"]
        assistant_msg = entry["messages"][2]["content"]

        code = extract_code(user_msg)
        language = extract_language(user_msg)
        real_label = md["label"]
        real_cwe = md.get("cwe_id", "CWE-?")
        cve_id = md.get("cve_id", "")
        # project_id resolution order: repo (CVEFixes), cve_id, file_pair_id prefix
        # (CrossVul uses "<project_idx>_<file_idx>" so we strip the file suffix)
        project_id = md.get("repo") or cve_id
        if not project_id and md.get("file_pair_id"):
            project_id = md["file_pair_id"].split("_")[0]
        if not project_id:
            project_id = f"unknown_{cve_id}_{md.get('vuln_code_hash', '')[:8]}"

        # Detection-style assistant message has Cause: and Fix: fields. Reuse them
        # for the triage reasoning so we keep the model's grounded knowledge.
        original_cause = extract_field(assistant_msg, "Cause") if real_label == "vulnerable" else ""
        original_fix = extract_field(assistant_msg, "Fix") if real_label == "vulnerable" else ""
        tool = rng.choice(SAST_TOOLS)

        out.append(make_triage_example(
            code=code,
            language=language,
            claimed_cwe=real_cwe,
            real_label=real_label,
            real_cwe=real_cwe,
            original_cause=original_cause,
            original_fix=original_fix,
            project_id=project_id,
            cve_id=cve_id,
            tool=tool,
        ))
    return out


def stratified_split(
    examples: list[dict], train_frac: float, val_frac: float, seed: int
) -> tuple[list[dict], list[dict], list[dict]]:
    """Split by project_id so the same repo never appears in train and eval.

    Lesson from HISTORY.md: random split inflates OOD performance by 2x.
    """
    rng = random.Random(seed)
    projects = sorted({e["metadata"]["project_id"] for e in examples
                       if e["metadata"].get("project_id")})
    rng.shuffle(projects)

    n_train = int(len(projects) * train_frac)
    n_val = int(len(projects) * val_frac)
    train_p = set(projects[:n_train])
    val_p = set(projects[n_train:n_train + n_val])
    test_p = set(projects[n_train + n_val:])

    train, val, test = [], [], []
    for e in examples:
        pid = e["metadata"].get("project_id")
        if pid in train_p:
            train.append(e)
        elif pid in val_p:
            val.append(e)
        elif pid in test_p:
            test.append(e)
    return train, val, test


def write_json(path: Path, data: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def summarise(name: str, data: list[dict]) -> None:
    verdicts = Counter(e["metadata"]["verdict"] for e in data)
    projects = len({e["metadata"]["project_id"] for e in data})
    cwes = Counter(e["metadata"]["claimed_cwe"] for e in data)
    print(f"  {name}: {len(data)} examples, {projects} projects, "
          f"TP={verdicts.get('TRUE_POSITIVE', 0)} FP={verdicts.get('FALSE_POSITIVE', 0)}, "
          f"top CWEs={list(cwes.most_common(5))}")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build SAST triage training data from CVEFixes pairs")
    p.add_argument("--input", required=True, help="Path to detection-style JSON (e.g., train_v5b_train.json)")
    p.add_argument("--output-dir", required=True)
    p.add_argument("--train-frac", type=float, default=0.7)
    p.add_argument("--val-frac", type=float, default=0.15)
    p.add_argument("--seed", type=int, default=42)
    return p.parse_args()


def main() -> None:
    args = parse_args()
    with open(args.input, encoding="utf-8") as f:
        detection_data = json.load(f)
    print(f"Loaded {len(detection_data)} detection examples from {args.input}")

    examples = build_triage_pairs(detection_data, args.seed)
    print(f"Built {len(examples)} triage examples")

    train, val, test = stratified_split(
        examples, args.train_frac, args.val_frac, args.seed
    )

    out = Path(args.output_dir)
    write_json(out / "triage_train.json", train)
    write_json(out / "triage_val.json", val)
    write_json(out / "triage_test.json", test)

    print(f"Wrote triage_train/val/test.json to {out}")
    summarise("train", train)
    summarise("val", val)
    summarise("test", test)


if __name__ == "__main__":
    main()
