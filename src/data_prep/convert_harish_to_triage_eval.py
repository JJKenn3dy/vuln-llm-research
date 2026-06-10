"""Convert Har1sh-k/sast-bench cases into our triage eval format.

The Har1sh-k benchmark has 85 hand-crafted cases (17 synthetic + 68 real-world).
Each case.json describes regions of code labelled as 'vulnerable' or implied safe,
with an `acceptedKinds` field naming the vulnerability class (ssrf, xss, sqli, ...).

We map each region into one triage example:
  - `vulnerable` region -> TRUE_POSITIVE under the matching CWE
  - region only in `mustNotFlagRegionIds` -> FALSE_POSITIVE (the tool should not flag this)

This is a small (~100-200 examples) extra OOD probe. Project-level split is
trivial since each case is a different project.

Example:

    python -m src.data_prep.convert_harish_to_triage_eval \\
        --harish-root /workspace/data/external/sast-bench \\
        --output data/eval/triage_harish_eval.json
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from src.utils.prompts import TRIAGE_SYSTEM, TRIAGE_USER_TEMPLATE


# Map the Har1sh-k 'canonicalKind' / 'acceptedKinds' tokens to CWE identifiers.
# Source: OWASP Top 10 mapping and CWE common patterns.
KIND_TO_CWE = {
    "ssrf": "CWE-918",
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "path_traversal": "CWE-22",
    "command_injection": "CWE-78",
    "code_injection": "CWE-94",
    "rce": "CWE-94",
    "deserialization": "CWE-502",
    "xxe": "CWE-611",
    "open_redirect": "CWE-601",
    "csrf": "CWE-352",
    "improper_auth": "CWE-287",
    "improper_authn": "CWE-287",
    "improper_authz": "CWE-285",
    "broken_access_control": "CWE-284",
    "secrets_exposure": "CWE-200",
    "info_disclosure": "CWE-200",
    "weak_crypto": "CWE-327",
    "weak_random": "CWE-338",
    "file_upload": "CWE-434",
    "log_injection": "CWE-117",
    "prototype_pollution": "CWE-1321",
    "template_injection": "CWE-94",
    "buffer_overflow": "CWE-787",
    "integer_overflow": "CWE-190",
}


def find_case_jsons(root: Path) -> list[Path]:
    return sorted(root.rglob("case.json"))


def read_code_region(repo_root: Path, region: dict) -> str | None:
    """Read the code from a region. Returns None if file can't be located."""
    rel_path = region.get("path")
    if not rel_path:
        return None
    file_path = repo_root / rel_path
    if not file_path.exists():
        return None
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return None
    start = max(0, region["startLine"] - 1)
    end = min(len(lines), region["endLine"])
    return "\n".join(lines[start:end])


def kind_to_cwe(kind: str) -> str:
    return KIND_TO_CWE.get(kind.lower(), f"CWE-other:{kind}")


def build_example(
    case: dict,
    code: str,
    claimed_cwe: str,
    verdict: str,
    region_id: str,
) -> dict:
    case_id = case["id"]
    language = case.get("language", "unknown")

    user = TRIAGE_USER_TEMPLATE.format(
        tool="semgrep",
        cwe=claimed_cwe,
        severity="MEDIUM",
        file_path=f"<{case_id}>",
        line_range="see snippet",
        code=code,
    )

    if verdict == "TRUE_POSITIVE":
        reasoning = (
            f"The flagged code does contain a {claimed_cwe} vulnerability. "
            f"{case.get('description', '').strip()}"
        )
        real_cwe = claimed_cwe
        suggested_fix = "See the upstream advisory or fix commit referenced in the case."
    else:
        reasoning = (
            f"This region is labelled in the benchmark as a non-vulnerability "
            f"under the claimed {claimed_cwe} class."
        )
        real_cwe = "N/A"
        suggested_fix = "N/A"

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
            "case_id": case_id,
            "region_id": region_id,
            "language": language,
            "claimed_cwe": claimed_cwe,
            "verdict": verdict,
            "kind": case.get("canonicalKind"),
            "real_world": "real_world" in case.get("caseType", ""),
            "project_id": case_id,  # each case is its own project
        },
    }


def convert_case(case_path: Path) -> list[dict]:
    case = json.loads(case_path.read_text(encoding="utf-8"))
    repo_root = (case_path.parent / case["files"]["root"]).resolve()

    must_detect = set(case.get("expectedOutcome", {}).get("mustDetectRegionIds", []))
    must_not_flag = set(case.get("expectedOutcome", {}).get("mustNotFlagRegionIds", []))

    examples: list[dict] = []
    for region in case.get("regions", []):
        region_id = region["id"]
        code = read_code_region(repo_root, region)
        if code is None:
            continue

        accepted_kinds = region.get("acceptedKinds") or [case.get("canonicalKind")]
        if not accepted_kinds or not accepted_kinds[0]:
            continue
        claimed_cwe = kind_to_cwe(accepted_kinds[0])

        if region_id in must_detect or region.get("label") == "vulnerable":
            verdict = "TRUE_POSITIVE"
        elif region_id in must_not_flag or region.get("label") in ("safe", "capability"):
            verdict = "FALSE_POSITIVE"
        else:
            continue  # ambiguous region, skip

        examples.append(build_example(case, code, claimed_cwe, verdict, region_id))
    return examples


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Convert Har1sh-k sast-bench cases to triage eval format")
    p.add_argument("--harish-root", required=True,
                   help="Path to cloned sast-bench repo")
    p.add_argument("--output", required=True,
                   help="Output JSON path")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    root = Path(args.harish_root)
    case_paths = find_case_jsons(root / "cases") if (root / "cases").exists() else find_case_jsons(root)

    all_examples: list[dict] = []
    for cp in case_paths:
        all_examples.extend(convert_case(cp))

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(all_examples, f, ensure_ascii=False, indent=2)

    verdicts = Counter(e["metadata"]["verdict"] for e in all_examples)
    langs = Counter(e["metadata"]["language"] for e in all_examples)
    rw = sum(1 for e in all_examples if e["metadata"]["real_world"])
    print(f"Wrote {len(all_examples)} triage examples to {args.output}")
    print(f"  verdicts: TP={verdicts.get('TRUE_POSITIVE', 0)} FP={verdicts.get('FALSE_POSITIVE', 0)}")
    print(f"  real-world={rw}, synthetic={len(all_examples) - rw}")
    print(f"  languages: {dict(langs.most_common())}")
    print(f"  source cases: {len(case_paths)}")


if __name__ == "__main__":
    main()
