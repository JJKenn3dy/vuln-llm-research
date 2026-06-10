"""Convert SastBench v0.1 findings (Rival Security, 2026-06) into our triage
chat-format so we can run v8.2 inference via run_triage_eval.py.

SastBench dataset gives us metadata (repo + commit + file + line range + claimed
CWE), but NOT the actual code — their agents clone the git repo at inference
time. For our single-call model we fetch the function body via the raw GitHub
URL: https://raw.githubusercontent.com/{owner}/{repo}/{commit}/{path}.

Two modes:
- joint: keep only findings whose CWE ∈ our 12 web CWEs and language ∈ our 7
  web languages. Fair eval of v8.2's specialisation (~808 cases).
- full: keep all 2737 findings. Out-of-distribution test, harder.

Usage:
    python -m src.data_prep.convert_sastbench_to_triage \\
        --input /workspace/data/sastbench/sastbench.json \\
        --output data/eval/sastbench_v01_joint.json \\
        --mode joint --max-cases 100

Concurrency: aiohttp with a small pool (20). GitHub raw is unauthenticated for
public repos; rate is generous (~60 req/min/IP without auth, more authenticated).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import re
from collections import Counter
from pathlib import Path

import aiohttp

from src.utils.prompts import TRIAGE_SYSTEM, TRIAGE_USER_TEMPLATE


WEB_CWES = {
    "CWE-79", "CWE-89", "CWE-22", "CWE-78", "CWE-94", "CWE-352",
    "CWE-434", "CWE-502", "CWE-611", "CWE-798", "CWE-918", "CWE-787",
}
WEB_LANGS = {"PHP", "Python", "JavaScript", "TypeScript", "Java", "Ruby", "Go"}


def github_raw_url(repo_url: str, commit: str, path: str) -> str | None:
    """Convert https://github.com/owner/repo into raw.githubusercontent.com URL."""
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$", repo_url)
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{commit}/{path}"


def slice_lines(text: str, line_start: int, line_end: int, pad: int = 5) -> str:
    """Return text[line_start-pad : line_end+pad] with original 1-indexed line numbers."""
    lines = text.splitlines()
    s = max(1, line_start - pad)
    e = min(len(lines), line_end + pad)
    return "\n".join(lines[s - 1:e])


async def fetch_one(session: aiohttp.ClientSession, finding: dict, sem: asyncio.Semaphore) -> dict | None:
    async with sem:
        meta = finding.get("metadata", {})
        ta = finding.get("to_analyzer", {})
        locations = ta.get("locations") or []
        if not locations:
            return None
        loc = locations[0]
        path = loc.get("file")
        line_start = loc.get("line_start") or 1
        line_end = loc.get("line_end") or line_start
        commit = finding.get("commit_hash")
        repo_url = finding.get("repo_url")
        url = github_raw_url(repo_url, commit, path) if (repo_url and commit and path) else None
        if not url:
            return None
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return None
                text = await resp.text(errors="replace")
        except Exception:
            return None
        code = slice_lines(text, int(line_start), int(line_end), pad=8)
        if not code.strip():
            return None
        return {
            "finding_id": finding.get("finding_id"),
            "repo_url": repo_url,
            "commit_hash": commit,
            "ground_truth": finding.get("ground_truth"),
            "metadata": meta,
            "locations": loc,
            "vulnerability_type": ta.get("vulnerability_type"),
            "vulnerability_name": ta.get("vulnerability_name"),
            "description": str(ta.get("description") or ""),
            "code": code,
            "languages": meta.get("languages") or [],
            "file_path": path,
            "line_range": f"{line_start}-{line_end}",
        }


def build_triage_example(rec: dict) -> dict:
    cwe = rec["metadata"].get("cwe_id", "CWE-?")
    langs = rec.get("languages", [])
    lang = langs[0] if langs else "unknown"
    verdict = ("TRUE_POSITIVE" if rec["ground_truth"] == "true_positive"
               else "FALSE_POSITIVE")
    user = TRIAGE_USER_TEMPLATE.format(
        tool="semgrep",
        cwe=cwe,
        severity="MEDIUM",
        file_path=rec["file_path"],
        line_range=rec["line_range"],
        code=rec["code"][:4000],
    )
    placeholder_reasoning = (
        f"Ground truth from SastBench: {verdict}. "
        f"Claimed: {cwe} ({rec.get('vulnerability_name', '')[:80]})."
    )
    assistant = (
        f"Verdict: {verdict}\n"
        f"Confidence: HIGH\n"
        f"Reasoning: {placeholder_reasoning}\n"
        f"RealCWE: {cwe if verdict == 'TRUE_POSITIVE' else 'N/A'}\n"
        f"SuggestedFix: see SastBench reference\n"
    )
    return {
        "messages": [
            {"role": "system", "content": TRIAGE_SYSTEM},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ],
        "metadata": {
            "case_id": rec["finding_id"],
            "project_id": rec["repo_url"],
            "claimed_cwe": cwe,
            "real_cwe": cwe if verdict == "TRUE_POSITIVE" else "N/A",
            "verdict": verdict,
            "language": lang.lower() if lang else "unknown",
            "tool": "semgrep",
            "file_path": rec["file_path"],
            "line_range": rec["line_range"],
            "source": "sastbench_v01",
            "vulnerability_name": rec.get("vulnerability_name"),
        },
    }


def filter_findings(findings: list[dict], mode: str) -> list[dict]:
    if mode == "full":
        return findings
    kept = []
    for f in findings:
        cwe = f.get("metadata", {}).get("cwe_id")
        langs = f.get("metadata", {}).get("languages") or []
        if cwe not in WEB_CWES:
            continue
        if not any(l in WEB_LANGS for l in langs):
            continue
        kept.append(f)
    return kept


async def fetch_all(findings: list[dict], concurrency: int, hf_token: str | None) -> list[dict]:
    headers = {"User-Agent": "vuln-llm-research-sastbench-fetcher/1.0"}
    if hf_token:
        headers["Authorization"] = f"token {hf_token}"
    sem = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession(headers=headers) as session:
        results = []
        n = len(findings)
        done = 0
        async def wrapped(f):
            nonlocal done
            r = await fetch_one(session, f, sem)
            done += 1
            if done % 50 == 0:
                print(f"  fetched {done}/{n}", flush=True)
            return r
        for chunk_start in range(0, n, 200):
            chunk = findings[chunk_start:chunk_start + 200]
            chunk_results = await asyncio.gather(*[wrapped(f) for f in chunk])
            results.extend([r for r in chunk_results if r])
    return results


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Convert SastBench v0.1 to our triage format")
    p.add_argument("--input", required=True, help="Path to sastbench.json")
    p.add_argument("--output", required=True)
    p.add_argument("--mode", choices=["joint", "full"], default="joint")
    p.add_argument("--max-cases", type=int, default=None)
    p.add_argument("--concurrency", type=int, default=20)
    p.add_argument("--gh-token", default=None,
                   help="GitHub PAT for higher raw rate limit; leave empty for unauthenticated")
    p.add_argument("--shuffle-seed", type=int, default=42)
    return p.parse_args()


def main() -> None:
    args = parse_args()
    data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    print(f"Loaded {len(data)} findings")

    kept = filter_findings(data, args.mode)
    print(f"After {args.mode} filter: {len(kept)}")

    import random
    random.Random(args.shuffle_seed).shuffle(kept)
    if args.max_cases:
        kept = kept[:args.max_cases]
        print(f"Capped to {len(kept)}")

    fetched = asyncio.run(fetch_all(kept, args.concurrency, args.gh_token))
    print(f"Fetched code for {len(fetched)} / {len(kept)} cases")

    examples = [build_triage_example(r) for r in fetched]
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(examples, ensure_ascii=False, indent=2), encoding="utf-8")

    verdicts = Counter(e["metadata"]["verdict"] for e in examples)
    cwes = Counter(e["metadata"]["claimed_cwe"] for e in examples)
    langs = Counter(e["metadata"]["language"] for e in examples)
    print(f"Wrote {len(examples)} -> {args.output}")
    print(f"  TP={verdicts.get('TRUE_POSITIVE', 0)} FP={verdicts.get('FALSE_POSITIVE', 0)}")
    print(f"  top CWE: {cwes.most_common(8)}")
    print(f"  langs: {dict(langs.most_common(8))}")


if __name__ == "__main__":
    main()
