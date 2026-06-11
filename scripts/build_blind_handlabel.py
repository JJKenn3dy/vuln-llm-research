"""Build a blind (ground-truth-stripped) version of hand_label_cases.json.

Removes everything that would leak the SastBench verdict from a case
during Pass 1 labeling:
  - case_id suffix `:true_positive` / `:false_positive` → strip
  - metadata.verdict → strip
  - messages[2] (assistant ground truth) → strip
  - real_cwe → strip (would distinguish TP CWE-match from FP scaffold)

Preserves what the labeler needs:
  - snippet (messages[1] user content)
  - language, file_path, line_range, project_id, claimed_cwe
  - tool name, vulnerability_name, commit_hash

A side mapping `hand_label_case_id_map.json` lets the post-labeling
comparison script realign blind labels to ground truth.

Usage:
    python scripts/build_blind_handlabel.py \\
        --input data/exam/hand_label_cases.json \\
        --output data/exam/hand_label_blind.json \\
        --map-output data/exam/hand_label_case_id_map.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def make_blind_id(orig_id: str) -> str:
    """Stable hash-based id; reveals nothing about verdict."""
    h = hashlib.sha1(orig_id.encode("utf-8")).hexdigest()[:8]
    return f"hl_{h}"


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--input", default="data/exam/hand_label_cases.json")
    p.add_argument("--output", default="data/exam/hand_label_blind.json")
    p.add_argument("--map-output", default="data/exam/hand_label_case_id_map.json")
    args = p.parse_args()

    src = json.loads(Path(args.input).read_text(encoding="utf-8"))
    print(f"loaded {len(src)} cases from {args.input}")

    blind = []
    mapping = {}
    for case in src:
        md = case["metadata"]
        orig_id = md["case_id"]
        blind_id = make_blind_id(orig_id)
        mapping[blind_id] = {
            "original_case_id": orig_id,
            "ground_truth_verdict": md["verdict"],
            "ground_truth_real_cwe": md.get("real_cwe"),
        }

        snippet_msg = case["messages"][1]
        blind.append({
            "blind_id": blind_id,
            "snippet_prompt": snippet_msg["content"],
            "project_id": md["project_id"],
            "claimed_cwe": md["claimed_cwe"],
            "language": md["language"],
            "file_path": md["file_path"],
            "line_range": md["line_range"],
            "tool": md["tool"],
            "vulnerability_name": md.get("vulnerability_name", ""),
            "commit_hash": md.get("commit_hash", ""),
        })

    Path(args.output).write_text(
        json.dumps(blind, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    Path(args.map_output).write_text(
        json.dumps(mapping, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"wrote {args.output} ({len(blind)} blind cases)")
    print(f"wrote {args.map_output} (ground-truth map)")
    print()
    print("Pass 1 instructions: read ONLY", args.output)
    print("DO NOT read", args.map_output, "until both passes are complete")


if __name__ == "__main__":
    main()
