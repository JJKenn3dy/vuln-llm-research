"""Mechanical evidence packet extractor — per EVIDENCE_PACKET_PROTOCOL.md.

Fetches each case's file from GitHub raw at the case's commit_hash and applies
the protocol:
  1. Enclosing function body (regex-based detection, language-aware)
  2. File-level imports
  3. Sanitizer-keyword lines (whole file)
  4. Callers — NOT implemented (requires repo clone). Documented.

Output enriches the scaffold with evidence_packet + protocol_compliance.

This is the (b) arm context source for sufficiency_probe.py when human
hand-labeling is replaced by model-proxy. Honest packet reproduction by a
deterministic extractor — no oracle bias.

Usage:
    python scripts/extract_evidence_packets.py \\
        --cases data/exam/hand_label_cases.json \\
        --output data/exam/hand_label_evidence_extracted.json \\
        --concurrency 10
"""
from __future__ import annotations

import argparse
import asyncio
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

import aiohttp


# Per-language function-start regexes
FN_START_RE: dict[str, re.Pattern] = {
    "php": re.compile(r"^\s*(?:public|private|protected|static|abstract|final)?\s*(?:public|private|protected|static|abstract|final)?\s*function\s+\w+", re.M),
    "python": re.compile(r"^\s*(?:async\s+)?def\s+\w+|^\s*class\s+\w+", re.M),
    "javascript": re.compile(
        r"^\s*(?:export\s+)?(?:async\s+)?function\s+\w+|"
        r"^\s*(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>)|"
        r"^\s*\w+\s*:\s*(?:async\s+)?function|"
        r"^\s*\w+\s*\([^)]*\)\s*\{",
        re.M,
    ),
    "typescript": re.compile(
        r"^\s*(?:export\s+)?(?:async\s+)?function\s+\w+|"
        r"^\s*(?:export\s+)?(?:const|let|var)\s+\w+\s*[:=][^;]*?(?:function|\([^)]*\)\s*(?::\s*\w+)?\s*=>)|"
        r"^\s*(?:public|private|protected)?\s*(?:static\s+)?(?:async\s+)?\w+\s*\([^)]*\)\s*[:{]",
        re.M,
    ),
    "java": re.compile(r"^\s*(?:public|private|protected|static|final|abstract|synchronized)\s+(?:[\w<>\[\]\?,\s]+\s+)+\w+\s*\([^)]*\)", re.M),
    "go": re.compile(r"^\s*func\s+(?:\([^)]+\)\s+)?\w+", re.M),
    "ruby": re.compile(r"^\s*def\s+\w+|^\s*class\s+\w+", re.M),
}


EXTENSION_TO_LANG = {
    ".php": "php", ".phtml": "php", ".php5": "php",
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby", ".erb": "ruby",
}


def detect_language(file_path: str, metadata_lang: str | None) -> str:
    """File extension trumps SastBench metadata.language (which is unreliable)."""
    if file_path:
        for ext, lang in EXTENSION_TO_LANG.items():
            if file_path.lower().endswith(ext):
                return lang
    return (metadata_lang or "unknown").lower()

IMPORT_RE: dict[str, re.Pattern] = {
    "php": re.compile(r"^\s*(?:use|require|require_once|include|include_once|namespace)\s+", re.M),
    "python": re.compile(r"^\s*(?:import|from)\s+", re.M),
    "javascript": re.compile(r"^\s*(?:import|const\s+\{[^}]+\}\s*=\s*require|const\s+\w+\s*=\s*require|require\s*\()", re.M),
    "typescript": re.compile(r"^\s*(?:import|const\s+\w+\s*=\s*require)", re.M),
    "java": re.compile(r"^\s*(?:package|import)\s+", re.M),
    "go": re.compile(r"^\s*(?:package|import)\s+|^\s*[\"\w/]+\s*\"[\w/.-]+\"", re.M),
    "ruby": re.compile(r"^\s*(?:require|require_relative|include|extend)\s+", re.M),
}

SANITIZER_KEYWORDS = re.compile(
    r"\b(?:sanitize|sanitiz|escape|validate|valid|clean|encode|prepare|parametr|"
    r"htmlspecial|strip|filter|whitelist|allowlist|denylist|blacklist|"
    r"is_safe|safe_|escape_|secure_|trusted)",
    re.I,
)


def github_raw_url(repo_url: str | None, commit: str | None, file_path: str | None) -> str | None:
    if not (repo_url and commit and file_path):
        return None
    m = re.match(r"https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$", repo_url)
    if not m:
        return None
    return f"https://raw.githubusercontent.com/{m.group(1)}/{m.group(2)}/{commit}/{file_path}"


def find_enclosing_function(lines: list[str], line_start_1based: int,
                              language: str) -> tuple[int, int] | None:
    """Heuristic: return (fn_start_0based, fn_end_0based_exclusive) or None.

    fn_start = greatest function-start line ≤ line_start
    fn_end = next function-start, or fn_start + 200, or EOF.
    """
    fn_re = FN_START_RE.get(language)
    if not fn_re:
        return None
    text = "\n".join(lines)
    starts: list[int] = []
    for m in fn_re.finditer(text):
        starts.append(text[: m.start()].count("\n"))  # 0-based line
    if not starts:
        return None
    before = [s for s in starts if s + 1 <= line_start_1based]
    if not before:
        return None
    fn_start = max(before)
    after = [s for s in starts if s > fn_start]
    fn_end_raw = after[0] if after else len(lines)
    fn_end = min(fn_end_raw, fn_start + 200)
    return fn_start, fn_end


def build_packet(case: dict, file_content: str | None) -> tuple[str, dict]:
    md = case["metadata"]
    file_path = md.get("file_path", "?")
    lang = detect_language(file_path, md.get("language"))
    line_range = md.get("line_range", "?")
    try:
        line_start = int(str(line_range).split("-")[0])
    except (ValueError, IndexError):
        line_start = 1

    stats = {
        "language": lang,
        "file_path": file_path,
        "line_range": line_range,
        "fetch_ok": file_content is not None,
        "function_extracted": False,
        "imports_count": 0,
        "sanitizer_lines_count": 0,
        "fallback_to_window": False,
    }

    if file_content is None:
        # Compliance=false: cannot reproduce without raw file
        return (
            f"=== FETCH FAILED for {file_path} ===\n"
            f"Could not retrieve file from GitHub raw at the case's commit. "
            f"Evidence packet cannot be constructed.\n",
            stats,
        )

    lines = file_content.splitlines()

    # 1. Enclosing function
    fn_bounds = find_enclosing_function(lines, line_start, lang)
    if fn_bounds:
        fn_s, fn_e = fn_bounds
        fn_body = "\n".join(lines[fn_s:fn_e])
        stats["function_extracted"] = True
        function_section = (
            f"=== ENCLOSING FUNCTION (lines {fn_s+1}-{fn_e} of {file_path}, language: {lang}) ===\n"
            + fn_body[:3000]
            + ("\n[truncated]" if len(fn_body) > 3000 else "")
        )
    else:
        # Fallback: ±50 lines window around line_start
        w_s = max(0, line_start - 50)
        w_e = min(len(lines), line_start + 50)
        function_section = (
            f"=== CONTEXT WINDOW (function detection failed, lines {w_s+1}-{w_e} of {file_path}) ===\n"
            + "\n".join(lines[w_s:w_e])[:3000]
        )
        stats["fallback_to_window"] = True

    # 2. Imports
    import_re = IMPORT_RE.get(lang)
    imports: list[str] = []
    if import_re:
        # Top of file (first 200 lines) — most imports cluster there
        for l in lines[:200]:
            if import_re.match(l):
                imports.append(l.rstrip())
    stats["imports_count"] = len(imports)
    imports_section = (
        f"=== FILE IMPORTS ({len(imports)} found, top 30) ===\n"
        + "\n".join(imports[:30])
        + ("\n[truncated]" if len(imports) > 30 else "")
    )

    # 3. Sanitizer-keyword lines from whole file
    sanitizer_lines: list[str] = []
    for i, l in enumerate(lines):
        if SANITIZER_KEYWORDS.search(l):
            sanitizer_lines.append(f"L{i+1}: {l.strip()[:200]}")
    stats["sanitizer_lines_count"] = len(sanitizer_lines)
    sanitizer_section = (
        f"=== SANITIZER-KEYWORD LINES IN FILE ({len(sanitizer_lines)} matches, top 30) ===\n"
        + "\n".join(sanitizer_lines[:30])
        + ("\n[truncated]" if len(sanitizer_lines) > 30 else "")
    )

    # 4. Callers — NOT implemented
    callers_section = (
        "=== CALLERS ===\n"
        "(NOT extracted — requires repo clone. Documented limitation of v0 extractor.)\n"
    )

    packet = "\n\n".join([function_section, imports_section, sanitizer_section, callers_section])
    return packet, stats


async def fetch_file(session: aiohttp.ClientSession, url: str,
                       sem: asyncio.Semaphore) -> str | None:
    async with sem:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as r:
                if r.status != 200:
                    return None
                return await r.text(errors="replace")
        except Exception:
            return None


async def process_all(cases: list[dict], concurrency: int,
                       gh_token: str | None) -> list[dict]:
    headers = {"User-Agent": "vuln-llm-research-evidence-extractor/0.1"}
    if gh_token:
        headers["Authorization"] = f"token {gh_token}"
    sem = asyncio.Semaphore(concurrency)
    out: list[dict] = []
    async with aiohttp.ClientSession(headers=headers) as session:
        async def one(case):
            md = case["metadata"]
            url = github_raw_url(
                md.get("project_id"),
                md.get("commit_hash"),
                md.get("file_path"),
            )
            content = await fetch_file(session, url, sem) if url else None
            packet, stats = build_packet(case, content)
            return {
                "case_id": str(md["case_id"]),
                "github_raw_url": url,
                "evidence_packet": packet,
                # Compliance = followed the protocol mechanically. Imports/sanitizers
                # being zero is informative, not a violation — small files may genuinely
                # have neither. Strict criterion: file fetched + function bound found
                # via language-aware regex (no fallback-window).
                "evidence_packet_protocol_compliance": bool(
                    stats["fetch_ok"] and stats["function_extracted"]
                ),
                "stats": stats,
            }
        results = await asyncio.gather(*[one(c) for c in cases])
        out.extend(results)
    return out


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--cases", required=True, help="cases JSON with metadata incl. commit_hash")
    p.add_argument("--output", required=True)
    p.add_argument("--concurrency", type=int, default=10)
    p.add_argument("--gh-token", default=None, help="optional GitHub PAT for raw rate")
    p.add_argument("--limit", type=int, default=None, help="smoke testing")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    cases = json.loads(Path(args.cases).read_text(encoding="utf-8"))
    if args.limit:
        cases = cases[:args.limit]
    print(f"Cases: {len(cases)}")

    results = asyncio.run(process_all(cases, args.concurrency, args.gh_token))

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")

    n_compliant = sum(1 for r in results if r["evidence_packet_protocol_compliance"])
    n_fetched = sum(1 for r in results if r["stats"]["fetch_ok"])
    n_fn = sum(1 for r in results if r["stats"]["function_extracted"])
    n_fallback = sum(1 for r in results if r["stats"]["fallback_to_window"])
    langs = Counter(r["stats"]["language"] for r in results)
    print(f"  fetched: {n_fetched}/{len(results)}")
    print(f"  function extracted: {n_fn}/{len(results)}")
    print(f"  fallback to window: {n_fallback}/{len(results)}")
    print(f"  protocol_compliance=true: {n_compliant}/{len(results)}")
    print(f"  language distribution: {dict(langs)}")
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
