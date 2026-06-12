"""Render a ranked SARIF + optional filter outputs into an HTML triage report.

The HTML is self-contained (no external CSS/JS), ready to print to PDF via
browser. Designed as a cold-outreach attachment: top-K findings with code,
p_tp, and (if available) per-finding reasoning + suggested fix.

Usage:
  python -m src.product.report \\
      --ranker-sarif data/practical/results_v2/nodegoat_ranker.sarif \\
      --repo-name "OWASP NodeGoat" \\
      --top-k 15 \\
      --out report.html

Optional reasoning from a filter-mode outputs JSON (run_triage_eval format):
  ... --filter-outputs runs/v8_3_1_filter_outputs.json
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import get_lexer_by_name, guess_lexer_for_filename
from pygments.util import ClassNotFound


PROPERTY_BAG_KEY = "vuln_llm_triage"

LANG_BY_EXT = {
    ".php": "php",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".py": "python",
    ".java": "java",
    ".rb": "ruby",
    ".go": "go",
    ".cs": "csharp",
    ".html": "html",
    ".css": "css",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".sh": "bash",
    ".cjs": "javascript",
    ".mjs": "javascript",
    ".sql": "sql",
}


def _detect_lexer(file_path: str, code: str):
    ext = "." + file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
    lang = LANG_BY_EXT.get(ext)
    if lang:
        try:
            return get_lexer_by_name(lang, stripall=False)
        except ClassNotFound:
            pass
    try:
        return guess_lexer_for_filename(file_path, code)
    except ClassNotFound:
        return get_lexer_by_name("text")


def highlight_code(file_path: str, code: str, line_start: int = 1) -> str:
    """Pygments highlight with line numbers anchored at line_start."""
    lexer = _detect_lexer(file_path, code)
    formatter = HtmlFormatter(
        linenos="inline",
        linenostart=max(1, line_start),
        cssclass="src",
        nobackground=True,
    )
    return highlight(code, lexer, formatter)


def extract_findings(sarif: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract finding rows ready for template. Reads p_tp from property bag.

    Each result expected to have properties.vuln_llm_triage.p_tp from the
    ranker mode in src.product.triage_filter.
    """
    rows = []
    for run_idx, run in enumerate(sarif.get("runs", [])):
        tool = (run.get("tool", {}) or {}).get("driver", {}).get("name", "unknown")
        rules = {r.get("id"): r for r in (run.get("tool", {}).get("driver", {}).get("rules") or [])}
        for res in run.get("results", []) or []:
            bag = (res.get("properties") or {}).get(PROPERTY_BAG_KEY) or {}
            p_tp = bag.get("p_tp")
            rule_id = res.get("ruleId") or ""
            rule = rules.get(rule_id, {})
            loc = ((res.get("locations") or [{}])[0].get("physicalLocation") or {})
            artifact = (loc.get("artifactLocation") or {}).get("uri", "")
            region = loc.get("region") or {}
            line_start = int(region.get("startLine", 0) or 0)
            line_end = int(region.get("endLine", line_start) or line_start)
            snippet = (region.get("snippet") or {}).get("text", "") or ""
            if not snippet:
                ctx = (loc.get("contextRegion") or {}).get("snippet") or {}
                snippet = ctx.get("text", "") or ""
            msg = (res.get("message") or {}).get("text") or ""
            cwe = _extract_cwe(res, rule)
            rows.append({
                "tool": tool,
                "rule_id": rule_id,
                "rule_short": rule_id.split(".")[-1] if "." in rule_id else rule_id,
                "claimed_cwe": cwe,
                "file_path": artifact,
                "line_start": line_start,
                "line_end": line_end,
                "snippet": snippet,
                "message": msg,
                "p_tp": p_tp,
                "p_tp_pct": f"{p_tp*100:.1f}%" if isinstance(p_tp, (int, float)) else "n/a",
                "p_tp_band": _band(p_tp),
                "finding_key": f"{run_idx}:{res.get('ruleId')}:{artifact}:{line_start}",
            })
    return rows


def _band(p_tp: float | None) -> str:
    if p_tp is None:
        return "unknown"
    if p_tp >= 0.6:
        return "high"
    if p_tp >= 0.5:
        return "medium"
    return "low"


def _extract_cwe(res: dict[str, Any], rule: dict[str, Any]) -> str | None:
    import re
    cwe_re = re.compile(r"CWE-\d+", re.IGNORECASE)
    props = res.get("properties") or {}
    for key in ("cwe", "cwe_id"):
        v = props.get(key)
        if isinstance(v, str):
            m = cwe_re.search(v)
            if m: return m.group(0).upper()
    for t in (props.get("tags") or []):
        m = cwe_re.search(str(t))
        if m: return m.group(0).upper()
    rule_props = rule.get("properties") or {}
    for t in (rule_props.get("tags") or []):
        m = cwe_re.search(str(t))
        if m: return m.group(0).upper()
    return None


def attach_reasoning(rows: list[dict], filter_outputs_path: str | None) -> None:
    """Attach reasoning + verdict + confidence from a filter-mode run.

    Currently filter outputs use case_id (case_0..case_N) without back-link
    to SARIF; we just take by index if counts match. Skip if mismatch.
    """
    if not filter_outputs_path:
        return
    try:
        outs = json.loads(Path(filter_outputs_path).read_text(encoding="utf-8"))
    except Exception:
        return
    if len(outs) != len(rows):
        return
    for row, o in zip(rows, outs):
        row["verdict"] = o.get("predicted_verdict")
        row["confidence"] = o.get("predicted_confidence")
        row["reasoning"] = _parse_reasoning(o.get("model_response") or "")
        row["suggested_fix"] = _parse_suggested_fix(o.get("model_response") or "")


def _parse_reasoning(resp: str) -> str:
    import re
    m = re.search(r"Reasoning:\s*(.+?)(?=\n[A-Z][A-Za-z]+:|\Z)", resp, re.DOTALL)
    return (m.group(1).strip() if m else "").strip()


def _parse_suggested_fix(resp: str) -> str:
    import re
    m = re.search(r"SuggestedFix:\s*(.+?)(?=\n[A-Z][A-Za-z]+:|\Z)", resp, re.DOTALL)
    fix = (m.group(1).strip() if m else "").strip()
    if fix.lower() in ("n/a", "na", ""):
        return ""
    return fix


HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{ repo_name }} — SAST Triage Report</title>
<style>
  :root {
    --bg: #ffffff;
    --fg: #1a1a1a;
    --muted: #6b7280;
    --border: #e5e7eb;
    --high: #b91c1c;
    --high-bg: #fee2e2;
    --medium: #b45309;
    --medium-bg: #fef3c7;
    --low: #1e7c5a;
    --low-bg: #d1fae5;
    --unknown: #6b7280;
    --unknown-bg: #f3f4f6;
    --link: #1d4ed8;
  }
  * { box-sizing: border-box; }
  html, body { background: var(--bg); color: var(--fg); }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    line-height: 1.5;
    max-width: 900px;
    margin: 0 auto;
    padding: 32px 24px 80px;
    font-size: 14px;
  }
  h1 { font-size: 26px; margin: 0 0 4px; }
  h2 { font-size: 18px; margin: 32px 0 12px; padding-bottom: 6px; border-bottom: 1px solid var(--border); }
  h3 { font-size: 15px; margin: 16px 0 4px; }
  .meta { color: var(--muted); font-size: 13px; margin-bottom: 24px; }
  .summary {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 10px;
    margin: 16px 0 24px;
  }
  .summary .card {
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px 12px;
  }
  .summary .label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; }
  .summary .value { font-size: 20px; font-weight: 600; margin-top: 2px; }

  .finding {
    border: 1px solid var(--border);
    border-radius: 8px;
    margin: 14px 0;
    padding: 14px 16px;
    page-break-inside: avoid;
  }
  .finding-head { display: flex; align-items: baseline; gap: 10px; margin-bottom: 6px; }
  .rank { font-weight: 700; color: var(--muted); font-size: 13px; }
  .file-path { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; flex: 1; word-break: break-all; }
  .priority {
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    padding: 3px 8px;
    border-radius: 4px;
  }
  .priority.high   { color: var(--high);   background: var(--high-bg);   }
  .priority.medium { color: var(--medium); background: var(--medium-bg); }
  .priority.low    { color: var(--low);    background: var(--low-bg);    }
  .priority.unknown { color: var(--unknown); background: var(--unknown-bg); }

  .badges { font-size: 12px; color: var(--muted); margin-bottom: 8px; }
  .badge {
    display: inline-block;
    padding: 1px 6px;
    border: 1px solid var(--border);
    border-radius: 3px;
    margin-right: 4px;
  }
  .msg { font-size: 13px; color: var(--fg); margin: 4px 0 10px; }
  .code-block {
    background: #f9fafb;
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 8px 10px;
    overflow-x: auto;
    font-size: 12px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  .code-block .src { margin: 0; }
  .code-block pre { margin: 0; }
  .reasoning {
    margin-top: 10px;
    padding: 10px 12px;
    background: #f9fafb;
    border-left: 3px solid var(--link);
    border-radius: 0 4px 4px 0;
    font-size: 13px;
  }
  .reasoning .label { font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); margin-bottom: 4px; }
  .suggested-fix {
    margin-top: 8px;
    padding: 10px 12px;
    background: #ecfdf5;
    border-left: 3px solid var(--low);
    border-radius: 0 4px 4px 0;
    font-size: 13px;
  }
  .footer { color: var(--muted); font-size: 12px; margin-top: 36px; padding-top: 16px; border-top: 1px solid var(--border); }
  .footer p { margin: 6px 0; }
  .footer ul { margin: 6px 0; padding-left: 18px; }
  .scope { background: #fffbeb; border: 1px solid #fde68a; padding: 10px 14px; border-radius: 6px; margin: 16px 0; font-size: 13px; }
  .scope b { color: #92400e; }

  {{ pygments_css | safe }}
</style>
</head>
<body>

<h1>SAST Triage Report</h1>
<p class="meta">
  Repository: <b>{{ repo_name }}</b><br>
  Generated: {{ generated_at }}<br>
  Triage model: v8.3.1 (Qwen2.5-Coder-7B + LoRA, fine-tuned on CVEFixes + CrossVul)
</p>

<div class="summary">
  <div class="card"><div class="label">Total findings</div><div class="value">{{ total }}</div></div>
  <div class="card"><div class="label">High priority (p_tp ≥ 0.6)</div><div class="value">{{ counts.high }}</div></div>
  <div class="card"><div class="label">Medium (0.5–0.6)</div><div class="value">{{ counts.medium }}</div></div>
  <div class="card"><div class="label">Low (< 0.5)</div><div class="value">{{ counts.low }}</div></div>
</div>

{% if cwe_summary %}
<h2>CWE distribution (across all findings)</h2>
<p style="font-size: 13px; color: var(--muted);">
  {% for cwe, n in cwe_summary %}<span class="badge">{{ cwe }} ({{ n }})</span>{% endfor %}
</p>
{% endif %}

<h2>Top {{ top_k }} findings by triage priority</h2>
<p class="meta" style="margin-top:-6px;">Sorted by p_tp (model's probability that the finding is a true positive) descending.</p>

{% for f in findings %}
<div class="finding">
  <div class="finding-head">
    <span class="rank">#{{ loop.index }}</span>
    <span class="priority {{ f.p_tp_band }}">{{ f.p_tp_band }}{% if f.p_tp is not none %} · p_tp {{ "%.3f" | format(f.p_tp) }}{% endif %}</span>
    <span class="file-path">{{ f.file_path }}{% if f.line_start %}:{{ f.line_start }}{% if f.line_end and f.line_end != f.line_start %}-{{ f.line_end }}{% endif %}{% endif %}</span>
  </div>
  <div class="badges">
    {% if f.tool %}<span class="badge">tool: {{ f.tool }}</span>{% endif %}
    {% if f.claimed_cwe %}<span class="badge">{{ f.claimed_cwe }}</span>{% endif %}
    {% if f.rule_short %}<span class="badge">{{ f.rule_short }}</span>{% endif %}
    {% if f.verdict %}<span class="badge">verdict: {{ f.verdict }}{% if f.confidence %} ({{ f.confidence }}){% endif %}</span>{% endif %}
  </div>
  {% if f.message %}<div class="msg">{{ f.message }}</div>{% endif %}
  {% if f.code_html %}
  <div class="code-block">{{ f.code_html | safe }}</div>
  {% endif %}
  {% if f.reasoning %}
  <div class="reasoning">
    <div class="label">Reasoning</div>
    {{ f.reasoning }}
  </div>
  {% endif %}
  {% if f.suggested_fix %}
  <div class="suggested-fix">
    <div class="label" style="color: var(--low);">Suggested fix</div>
    {{ f.suggested_fix }}
  </div>
  {% endif %}
</div>
{% endfor %}

<div class="scope">
  <p><b>Triage scope</b> (honest disclosure, per public-benchmark eval on yeswehack + DVWA-paired, 111 cases):</p>
  <ul>
    <li>High detection: SQL injection (CWE-89), XSS (CWE-79), LFI/PathTraversal (CWE-22/98), SSRF (CWE-918), SSTI, Deserialization, eval/CodeInjection, FormatString, CSRF, PrototypePollution.</li>
    <li>Partial: CommandInjection (CWE-78), OpenRedirect (CWE-601), IDOR (CWE-639).</li>
    <li>Out of scope (model does not reliably detect): BusinessLogic, CORS, CachePoisoning, Broken-Access-Control, Weak-ID-Generation, Captcha-Bypass, Upload-Chain, AuthBypass-via-type-juggling, client-side JS validation.</li>
    <li>Snippet-only triage: findings whose mitigation lives outside the visible code window (e.g. validation 100 lines upstream) may be flagged as priority. Manual confirmation of top-5 recommended before acting.</li>
  </ul>
</div>

<div class="footer">
  <p>Methodology: single-call inference per finding, greedy decoding, p_tp from first-token logprobs over TRUE_POSITIVE vs FALSE_POSITIVE. Benchmark numbers (MCC 0.420 on yeswehack+DVWA, MCC 0.177 with paired strict-beat vs single-call Sonnet 4.5 on SastBench-250) measured under cluster-bootstrap CIs. Recall on diverse OSS is partial (DR ~46% on SastBench-250) — positioning is <b>priority ranker</b>, not filter.</p>
  <p>Generated by <a href="https://github.com/JJKenn3dy/vuln-llm-research" style="color: var(--link);">vuln-llm-research</a> · v8.3.1 adapter</p>
</div>

</body>
</html>
"""


def render(
    sarif_path: str,
    repo_name: str,
    top_k: int = 15,
    filter_outputs: str | None = None,
) -> str:
    sarif = json.loads(Path(sarif_path).read_text(encoding="utf-8"))
    rows = extract_findings(sarif)
    attach_reasoning(rows, filter_outputs)

    # Sort by p_tp desc (None at the bottom)
    rows.sort(key=lambda r: (-(r["p_tp"] if r["p_tp"] is not None else -1.0)))
    total = len(rows)

    counts = Counter()
    for r in rows:
        counts[r["p_tp_band"]] += 1

    # CWE distribution (all findings)
    cwe_counter = Counter(r["claimed_cwe"] for r in rows if r["claimed_cwe"])
    cwe_summary = cwe_counter.most_common(15)

    # Top K
    top = rows[:top_k]
    for r in top:
        if r.get("snippet"):
            r["code_html"] = highlight_code(r["file_path"], r["snippet"], r["line_start"] or 1)

    # Pygments CSS once for the whole doc
    pygments_css = HtmlFormatter(cssclass="src", nobackground=True).get_style_defs(".src")

    env = Environment(autoescape=True)
    template = env.from_string(HTML_TEMPLATE)
    return template.render(
        repo_name=repo_name,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
        total=total,
        counts={"high": counts["high"], "medium": counts["medium"], "low": counts["low"], "unknown": counts["unknown"]},
        cwe_summary=cwe_summary,
        top_k=min(top_k, total),
        findings=top,
        pygments_css=pygments_css,
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="src.product.report")
    p.add_argument("--ranker-sarif", required=True, help="output of src.product --mode ranker")
    p.add_argument("--repo-name", required=True, help="display name for the header")
    p.add_argument("--top-k", type=int, default=15)
    p.add_argument("--filter-outputs", default=None, help="optional run_triage_eval outputs.json for reasoning")
    p.add_argument("--out", required=True, help="output HTML path")
    args = p.parse_args(argv)

    html = render(args.ranker_sarif, args.repo_name, args.top_k, args.filter_outputs)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(html, encoding="utf-8")
    print(f"wrote {Path(args.out).resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
