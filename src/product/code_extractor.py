"""Resolve a SARIF finding's code snippet.

Source order:
  1. snippet inlined in the SARIF region.snippet.text (Semgrep, CodeQL)
  2. on-disk read from repo_root / file_path with the SARIF line range

Adds a context window (default 5 lines before/after) so the model sees
imports and enclosing scope hints. Trims the result to max_chars from the
center of the finding outward so we never blow past the model's context.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

DEFAULT_CONTEXT_LINES = 5
DEFAULT_MAX_CHARS = 6000


@dataclass
class Snippet:
    text: str
    effective_start: int
    effective_end: int
    truncated: bool
    source: str


def resolve_snippet(
    *,
    inline: str | None,
    repo_root: str | Path | None,
    file_path: str,
    line_start: int,
    line_end: int,
    context_lines: int = DEFAULT_CONTEXT_LINES,
    max_chars: int = DEFAULT_MAX_CHARS,
) -> Snippet:
    if inline and inline.strip():
        text, truncated = _clip(inline, max_chars)
        return Snippet(
            text=text,
            effective_start=line_start,
            effective_end=line_end,
            truncated=truncated,
            source="sarif_inline",
        )

    if repo_root is None:
        raise FileNotFoundError(
            "no inline snippet and no repo_root provided; cannot resolve code"
        )

    abs_path = Path(repo_root) / file_path
    if not abs_path.is_file():
        raise FileNotFoundError(f"file not found in repo: {abs_path}")

    with open(abs_path, encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    total = len(lines)
    start = max(1, line_start - context_lines)
    end = min(total, max(line_end, line_start) + context_lines)
    selected = lines[start - 1 : end]
    raw = "".join(selected)
    text, truncated = _clip(raw, max_chars)

    return Snippet(
        text=text,
        effective_start=start,
        effective_end=end,
        truncated=truncated,
        source="disk_read",
    )


def _clip(text: str, max_chars: int) -> tuple[str, bool]:
    if len(text) <= max_chars:
        return text, False
    half = max_chars // 2
    head = text[:half]
    tail = text[-half:]
    return f"{head}\n\n... [truncated {len(text) - max_chars} chars] ...\n\n{tail}", True
