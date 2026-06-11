"""SARIF v2.1 loader for SAST triage.

Extracts the fields the triage model needs (file path, line range, claimed
CWE, severity, tool name, snippet) from a SARIF document. Tolerant of
Semgrep, CodeQL, and Snyk Code variants.

CWE extraction order of precedence:
  1. result.properties.cwe / .cwe_id (Semgrep)
  2. result.taxa[].name when toolComponent name == "CWE" (CodeQL)
  3. result.properties.tags filtered by CWE-NNN
  4. rule.properties.tags filtered by CWE-NNN
  5. rule.relationships[].target.id with CWE prefix
  6. None if nothing matches
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

CWE_RE = re.compile(r"CWE-\d{1,5}", re.IGNORECASE)


@dataclass
class Finding:
    """One SARIF result reduced to triage-relevant fields."""

    finding_id: str
    rule_id: str
    tool: str
    claimed_cwe: str | None
    severity: str
    file_path: str
    line_start: int
    line_end: int
    snippet: str | None
    message: str
    raw_result: dict[str, Any] = field(default_factory=dict)
    raw_result_index: int = -1
    run_index: int = 0


def load_sarif(path: str | Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    version = doc.get("version", "")
    if not version.startswith("2."):
        raise ValueError(f"unsupported SARIF version: {version!r}, expected 2.x")
    return doc


def iter_findings(doc: dict[str, Any]) -> Iterator[Finding]:
    """Yield Finding for each result across all runs in the SARIF doc."""
    for run_idx, run in enumerate(doc.get("runs", [])):
        tool_name = _tool_name(run)
        rules_by_id = _index_rules(run)
        for result_idx, result in enumerate(run.get("results", [])):
            yield _build_finding(
                result=result,
                result_idx=result_idx,
                run_idx=run_idx,
                tool=tool_name,
                rules_by_id=rules_by_id,
            )


def _tool_name(run: dict[str, Any]) -> str:
    driver = run.get("tool", {}).get("driver", {})
    return driver.get("name", "unknown").lower()


def _index_rules(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    driver = run.get("tool", {}).get("driver", {})
    rules = driver.get("rules", []) or []
    out: dict[str, dict[str, Any]] = {}
    for rule in rules:
        rid = rule.get("id")
        if rid:
            out[rid] = rule
    return out


def _build_finding(
    *,
    result: dict[str, Any],
    result_idx: int,
    run_idx: int,
    tool: str,
    rules_by_id: dict[str, dict[str, Any]],
) -> Finding:
    rule_id = result.get("ruleId") or _rule_id_by_index(result, rules_by_id)
    rule = rules_by_id.get(rule_id or "", {})

    cwe = _extract_cwe(result, rule)
    severity = _extract_severity(result, rule)
    file_path, line_start, line_end, snippet = _extract_location(result)
    message = _extract_message(result, rule)
    finding_id = (
        result.get("guid")
        or result.get("correlationGuid")
        or f"{tool}:{rule_id}:{file_path}:{line_start}-{line_end}:{result_idx}"
    )

    return Finding(
        finding_id=finding_id,
        rule_id=rule_id or "",
        tool=tool,
        claimed_cwe=cwe,
        severity=severity,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        snippet=snippet,
        message=message,
        raw_result=result,
        raw_result_index=result_idx,
        run_index=run_idx,
    )


def _rule_id_by_index(
    result: dict[str, Any],
    rules_by_id: dict[str, dict[str, Any]],
) -> str | None:
    idx = result.get("ruleIndex")
    if idx is None:
        return None
    rules = list(rules_by_id.values())
    if 0 <= idx < len(rules):
        return rules[idx].get("id")
    return None


def _extract_cwe(result: dict[str, Any], rule: dict[str, Any]) -> str | None:
    props = result.get("properties", {}) or {}
    for key in ("cwe", "cwe_id", "cweId"):
        v = props.get(key)
        if isinstance(v, str):
            m = CWE_RE.search(v)
            if m:
                return _normalize_cwe(m.group(0))
        if isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    m = CWE_RE.search(item)
                    if m:
                        return _normalize_cwe(m.group(0))

    for taxon in result.get("taxa", []) or []:
        name = taxon.get("name", "")
        m = CWE_RE.search(name)
        if m:
            return _normalize_cwe(m.group(0))

    for tag in (props.get("tags") or []):
        m = CWE_RE.search(str(tag))
        if m:
            return _normalize_cwe(m.group(0))

    rule_props = rule.get("properties", {}) or {}
    for tag in (rule_props.get("tags") or []):
        m = CWE_RE.search(str(tag))
        if m:
            return _normalize_cwe(m.group(0))

    for rel in rule.get("relationships", []) or []:
        target = (rel.get("target") or {}).get("id", "")
        m = CWE_RE.search(str(target))
        if m:
            return _normalize_cwe(m.group(0))

    return None


def _normalize_cwe(raw: str) -> str:
    digits = re.sub(r"\D", "", raw)
    return f"CWE-{int(digits)}" if digits else raw.upper()


def _extract_severity(result: dict[str, Any], rule: dict[str, Any]) -> str:
    level = result.get("level")
    if level:
        return _level_to_severity(level)

    props = result.get("properties", {}) or {}
    raw = props.get("security-severity")
    if raw is not None:
        try:
            return _score_to_severity(float(raw))
        except (TypeError, ValueError):
            pass

    rule_props = rule.get("properties", {}) or {}
    raw = rule_props.get("security-severity")
    if raw is not None:
        try:
            return _score_to_severity(float(raw))
        except (TypeError, ValueError):
            pass

    default_level = rule.get("defaultConfiguration", {}).get("level")
    if default_level:
        return _level_to_severity(default_level)

    return "UNKNOWN"


def _level_to_severity(level: str) -> str:
    return {
        "error": "HIGH",
        "warning": "MEDIUM",
        "note": "LOW",
        "none": "INFO",
    }.get(level.lower(), level.upper())


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _extract_location(
    result: dict[str, Any],
) -> tuple[str, int, int, str | None]:
    locations = result.get("locations") or []
    if not locations:
        return "", 0, 0, None

    physical = (locations[0].get("physicalLocation") or {})
    artifact = physical.get("artifactLocation") or {}
    file_path = artifact.get("uri", "")

    region = physical.get("region") or {}
    start = int(region.get("startLine", 0) or 0)
    end = int(region.get("endLine", start) or start)

    snippet = None
    snippet_obj = region.get("snippet") or {}
    if "text" in snippet_obj:
        snippet = snippet_obj["text"]
    else:
        ctx = physical.get("contextRegion") or {}
        ctx_snippet = ctx.get("snippet") or {}
        if "text" in ctx_snippet:
            snippet = ctx_snippet["text"]

    return file_path, start, end, snippet


def _extract_message(result: dict[str, Any], rule: dict[str, Any]) -> str:
    msg = result.get("message", {})
    if isinstance(msg, dict):
        text = msg.get("text") or msg.get("markdown") or ""
    else:
        text = str(msg)
    if text:
        return text
    rule_msg = rule.get("shortDescription", {}) or {}
    return rule_msg.get("text", "")
