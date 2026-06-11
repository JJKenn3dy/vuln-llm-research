"""SARIF-in, SARIF-out triage orchestrator.

Two modes:

  filter (default):
    1. load SARIF, iterate findings
    2. for each finding, resolve code snippet (inline first, repo_root fallback)
    3. build TriageRequest, call backend.infer()
    4. parse Verdict from response
    5. attach verdict + reasoning to the result's property bag
    6. partial JSONL dump every dump_every findings (feedback_intermediate_results_always.md)
    7. emit SARIF: keep all by default, drop FALSE_POSITIVE when --drop-fp

  ranker (no model verdict, no filtering):
    1-2. same as filter
    3. call backend.score_p_tp() to get first-token TRUE/FALSE probability
    4. attach p_tp to property bag, do NOT collapse to verdict label
    5. output SARIF sorted by p_tp descending
       (rationale: reviewer rule for DR=46% adapter — sort, don't hide)
"""
from __future__ import annotations

import copy
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Iterator

from .backends import TriageBackend, TriageRequest
from .code_extractor import (
    DEFAULT_CONTEXT_LINES,
    DEFAULT_MAX_CHARS,
    Snippet,
    resolve_snippet,
)
from .sarif_parser import Finding, iter_findings, load_sarif
from .verdict import FALSE_POSITIVE, PARSE_FAIL, TRUE_POSITIVE, Verdict, parse


PROPERTY_BAG_KEY = "vuln_llm_triage"

MODE_FILTER = "filter"
MODE_RANKER = "ranker"


def triage_sarif(
    *,
    sarif_path: str | Path,
    output_path: str | Path,
    backend: TriageBackend,
    mode: str = MODE_FILTER,
    repo_root: str | Path | None = None,
    drop_fp: bool = False,
    context_lines: int = DEFAULT_CONTEXT_LINES,
    max_snippet_chars: int = DEFAULT_MAX_CHARS,
    partial_path: str | Path | None = None,
    dump_every: int = 10,
    progress_log: str | Path | None = None,
) -> dict:
    """Run triage end-to-end. Returns a summary dict.

    mode='filter': model emits a verdict, output is filtered SARIF.
    mode='ranker': model emits p_tp, output is SARIF sorted by p_tp desc.

    partial_path defaults to <output_path>.partial.jsonl.
    """
    if mode not in (MODE_FILTER, MODE_RANKER):
        raise ValueError(f"unknown mode: {mode!r}")
    if mode == MODE_RANKER:
        return _triage_ranker(
            sarif_path=sarif_path,
            output_path=output_path,
            backend=backend,
            repo_root=repo_root,
            context_lines=context_lines,
            max_snippet_chars=max_snippet_chars,
            partial_path=partial_path,
            dump_every=dump_every,
            progress_log=progress_log,
        )
    doc = load_sarif(sarif_path)
    findings = list(iter_findings(doc))
    n = len(findings)

    partial_path = Path(partial_path) if partial_path else Path(str(output_path) + ".partial.jsonl")
    partial_path.parent.mkdir(parents=True, exist_ok=True)
    if partial_path.exists():
        partial_path.unlink()
    partial_fp = open(partial_path, "w", encoding="utf-8")

    log_fp = None
    if progress_log:
        Path(progress_log).parent.mkdir(parents=True, exist_ok=True)
        log_fp = open(progress_log, "w", encoding="utf-8")

    def _log(line: str) -> None:
        stamped = f"[{datetime.now().strftime('%H:%M:%S')}] {line}"
        print(stamped, flush=True)
        if log_fp:
            log_fp.write(stamped + "\n")
            log_fp.flush()

    _log(f"loaded {n} findings from {sarif_path}")

    verdicts: list[tuple[Finding, Verdict | None, str]] = []
    counts = {TRUE_POSITIVE: 0, FALSE_POSITIVE: 0, PARSE_FAIL: 0, "skipped": 0}

    for i, finding in enumerate(findings):
        try:
            snippet = resolve_snippet(
                inline=finding.snippet,
                repo_root=repo_root,
                file_path=finding.file_path,
                line_start=finding.line_start,
                line_end=finding.line_end,
                context_lines=context_lines,
                max_chars=max_snippet_chars,
            )
        except FileNotFoundError as e:
            counts["skipped"] += 1
            verdicts.append((finding, None, f"skip: {e}"))
            _emit_partial(partial_fp, i, finding, None, f"skip: {e}", counts, n)
            _log(f"[{i+1}/{n}] skip {finding.finding_id}: {e}")
            continue

        req = _build_request(finding, snippet)
        try:
            raw = backend.infer(req)
        except Exception as e:
            counts["skipped"] += 1
            verdicts.append((finding, None, f"backend error: {e}"))
            _emit_partial(partial_fp, i, finding, None, str(e), counts, n)
            _log(f"[{i+1}/{n}] backend error {finding.finding_id}: {e}")
            continue

        v = parse(raw)
        verdicts.append((finding, v, ""))
        counts[v.verdict if v.verdict in counts else PARSE_FAIL] = (
            counts.get(v.verdict, 0) + 1
        )

        _emit_partial(partial_fp, i, finding, v, "", counts, n)
        if (i + 1) % dump_every == 0 or (i + 1) == n:
            partial_fp.flush()
            _log(
                f"[{i+1}/{n}] TP={counts[TRUE_POSITIVE]} FP={counts[FALSE_POSITIVE]} "
                f"PARSE_FAIL={counts[PARSE_FAIL]} skip={counts['skipped']}"
            )

    partial_fp.close()

    filtered_doc = _build_filtered_doc(doc, verdicts, drop_fp=drop_fp)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(filtered_doc, f, ensure_ascii=False, indent=2)

    summary = {
        "input": str(sarif_path),
        "output": str(output_path),
        "n_findings": n,
        "counts": counts,
        "drop_fp": drop_fp,
        "n_emitted": _count_emitted(filtered_doc),
    }
    backend.close()
    _log(f"done: {summary}")
    if log_fp:
        log_fp.close()
    return summary


def _build_request(finding: Finding, snippet: Snippet) -> TriageRequest:
    line_range = (
        f"{snippet.effective_start}-{snippet.effective_end}"
        if snippet.effective_end != snippet.effective_start
        else str(snippet.effective_start)
    )
    return TriageRequest(
        finding_id=finding.finding_id,
        tool=finding.tool,
        claimed_cwe=finding.claimed_cwe or "unknown",
        severity=finding.severity,
        file_path=finding.file_path,
        line_range=line_range,
        code=snippet.text,
    )


def _emit_partial(
    fp,
    idx: int,
    finding: Finding,
    verdict: Verdict | None,
    error: str,
    counts: dict,
    total: int,
) -> None:
    record = {
        "i": idx,
        "total": total,
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "claimed_cwe": finding.claimed_cwe,
        "verdict": verdict.verdict if verdict else None,
        "confidence": verdict.confidence if verdict else None,
        "error": error,
        "counts_so_far": {**counts},
    }
    fp.write(json.dumps(record, ensure_ascii=False) + "\n")


def _build_filtered_doc(
    doc: dict,
    verdicts: list[tuple[Finding, Verdict | None, str]],
    *,
    drop_fp: bool,
) -> dict:
    out = copy.deepcopy(doc)
    by_run_idx: dict[int, list[tuple[int, Verdict | None, str]]] = {}
    for finding, verdict, error in verdicts:
        by_run_idx.setdefault(finding.run_index, []).append(
            (finding.raw_result_index, verdict, error)
        )

    for run_idx, run in enumerate(out.get("runs", [])):
        annotations = {
            ridx: (v, err)
            for ridx, v, err in by_run_idx.get(run_idx, [])
        }
        new_results = []
        for idx, result in enumerate(run.get("results", [])):
            v, err = annotations.get(idx, (None, ""))
            if v is None:
                if not drop_fp:
                    annotated = copy.deepcopy(result)
                    annotated.setdefault("properties", {})[PROPERTY_BAG_KEY] = {
                        "verdict": None,
                        "error": err or "no_verdict",
                    }
                    new_results.append(annotated)
                continue
            if drop_fp and v.verdict == FALSE_POSITIVE:
                continue
            annotated = copy.deepcopy(result)
            annotated.setdefault("properties", {})[PROPERTY_BAG_KEY] = {
                "verdict": v.verdict,
                "confidence": v.confidence,
                "reasoning": v.reasoning,
                "real_cwe": v.real_cwe,
                "suggested_fix": v.suggested_fix,
            }
            new_results.append(annotated)
        run["results"] = new_results
    return out


def _count_emitted(doc: dict) -> int:
    return sum(len(run.get("results", []) or []) for run in doc.get("runs", []))


def iter_partial_records(path: str | Path) -> Iterator[dict]:
    """Read the partial JSONL log back for monitoring or recovery."""
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def _triage_ranker(
    *,
    sarif_path: str | Path,
    output_path: str | Path,
    backend: TriageBackend,
    repo_root: str | Path | None,
    context_lines: int,
    max_snippet_chars: int,
    partial_path: str | Path | None,
    dump_every: int,
    progress_log: str | Path | None,
) -> dict:
    """p_tp ranking mode. Reviewer rule: real logprobs, not verdict mapping.

    Produces a SARIF where every result is annotated with vuln_llm_triage.p_tp
    and the results are sorted by p_tp descending. Nothing is dropped — the
    operator sees all findings, just in priority order.
    """
    doc = load_sarif(sarif_path)
    findings = list(iter_findings(doc))
    n = len(findings)

    partial_path = Path(partial_path) if partial_path else Path(str(output_path) + ".partial.jsonl")
    partial_path.parent.mkdir(parents=True, exist_ok=True)
    if partial_path.exists():
        partial_path.unlink()
    partial_fp = open(partial_path, "w", encoding="utf-8")

    log_fp = None
    if progress_log:
        Path(progress_log).parent.mkdir(parents=True, exist_ok=True)
        log_fp = open(progress_log, "w", encoding="utf-8")

    def _log(line: str) -> None:
        stamped = f"[{datetime.now().strftime('%H:%M:%S')}] {line}"
        print(stamped, flush=True)
        if log_fp:
            log_fp.write(stamped + "\n")
            log_fp.flush()

    _log(f"loaded {n} findings from {sarif_path} (ranker mode)")

    scored: list[tuple[Finding, float | None, str]] = []
    n_scored = 0
    n_skipped = 0

    for i, finding in enumerate(findings):
        try:
            snippet = resolve_snippet(
                inline=finding.snippet,
                repo_root=repo_root,
                file_path=finding.file_path,
                line_start=finding.line_start,
                line_end=finding.line_end,
                context_lines=context_lines,
                max_chars=max_snippet_chars,
            )
        except FileNotFoundError as e:
            n_skipped += 1
            scored.append((finding, None, f"skip: {e}"))
            _emit_ranker_partial(partial_fp, i, finding, None, f"skip: {e}", n)
            _log(f"[{i+1}/{n}] skip {finding.finding_id}: {e}")
            continue

        req = _build_request(finding, snippet)
        try:
            p_tp = backend.score_p_tp(req)
        except Exception as e:
            n_skipped += 1
            scored.append((finding, None, f"backend error: {e}"))
            _emit_ranker_partial(partial_fp, i, finding, None, str(e), n)
            _log(f"[{i+1}/{n}] backend error {finding.finding_id}: {e}")
            continue

        if p_tp is None:
            n_skipped += 1
            scored.append((finding, None, "backend returned None"))
            _emit_ranker_partial(partial_fp, i, finding, None, "no_score", n)
        else:
            scored.append((finding, p_tp, ""))
            n_scored += 1
            _emit_ranker_partial(partial_fp, i, finding, p_tp, "", n)

        if (i + 1) % dump_every == 0 or (i + 1) == n:
            partial_fp.flush()
            _log(f"[{i+1}/{n}] scored={n_scored} skipped={n_skipped}")

    partial_fp.close()

    ranked_doc = _build_ranker_doc(doc, scored)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(ranked_doc, f, ensure_ascii=False, indent=2)

    summary = {
        "input": str(sarif_path),
        "output": str(output_path),
        "mode": MODE_RANKER,
        "n_findings": n,
        "n_scored": n_scored,
        "n_skipped": n_skipped,
        "n_emitted": _count_emitted(ranked_doc),
    }
    backend.close()
    _log(f"done: {summary}")
    if log_fp:
        log_fp.close()
    return summary


def _emit_ranker_partial(
    fp,
    idx: int,
    finding: Finding,
    p_tp: float | None,
    error: str,
    total: int,
) -> None:
    record = {
        "i": idx,
        "total": total,
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "claimed_cwe": finding.claimed_cwe,
        "p_tp": p_tp,
        "error": error,
    }
    fp.write(json.dumps(record, ensure_ascii=False) + "\n")


def _build_ranker_doc(
    doc: dict,
    scored: list[tuple[Finding, float | None, str]],
) -> dict:
    """Sort results by p_tp desc within each run, annotate property bag.

    Findings that failed scoring drop to the bottom of the run with p_tp=null
    and an error string so the operator can still see them.
    """
    out = copy.deepcopy(doc)
    by_run: dict[int, list[tuple[float, int, Finding, float | None, str]]] = {}
    sort_idx = 0
    for finding, p_tp, error in scored:
        order = p_tp if p_tp is not None else -1.0
        by_run.setdefault(finding.run_index, []).append(
            (order, sort_idx, finding, p_tp, error)
        )
        sort_idx += 1

    for run_idx, run in enumerate(out.get("runs", [])):
        entries = by_run.get(run_idx, [])
        entries.sort(key=lambda x: (-x[0], x[1]))
        original_results = run.get("results", []) or []
        new_results = []
        for order, _, finding, p_tp, error in entries:
            raw_idx = finding.raw_result_index
            if raw_idx < 0 or raw_idx >= len(original_results):
                continue
            annotated = copy.deepcopy(original_results[raw_idx])
            bag = annotated.setdefault("properties", {})
            bag[PROPERTY_BAG_KEY] = {
                "p_tp": p_tp,
                "error": error or None,
            }
            new_results.append(annotated)
        run["results"] = new_results
    return out
