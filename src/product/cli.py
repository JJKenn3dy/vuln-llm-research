"""CLI for SARIF triage.

  python -m src.product \
      --input findings.sarif \
      --output filtered.sarif \
      --backend mock \
      --repo-root /path/to/checkout

Backends:
  mock  — dry run, deterministic verdict by CWE allowlist
  local — HF transformers + LoRA (needs GPU)
  vllm  — OpenAI-compatible HTTP, e.g. vllm serve

Modes:
  filter   model emits Verdict, SARIF can drop FP with --drop-fp (default)
  ranker   model emits first-token p_tp, SARIF sorted by p_tp desc

Flags:
  --mode {filter,ranker}
  --drop-fp           filter mode only: omit FALSE_POSITIVE results
  --context-lines N   context window around the SARIF region (default 5)
  --max-chars N       hard cap on snippet chars sent to the model (default 6000)
"""
from __future__ import annotations

import argparse
import sys

from .backends.mock import MockBackend
from .triage_filter import MODE_FILTER, MODE_RANKER, triage_sarif


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="src.product",
        description="Filter SAST SARIF findings through the vuln-llm triage model.",
    )
    p.add_argument("--input", required=True, help="input SARIF v2.1 file")
    p.add_argument("--output", required=True, help="output SARIF file (with verdicts)")
    p.add_argument(
        "--backend",
        choices=["mock", "local", "vllm"],
        required=True,
    )
    p.add_argument(
        "--mode",
        choices=[MODE_FILTER, MODE_RANKER],
        default=MODE_FILTER,
        help="filter (drop or label) or ranker (sort by p_tp, show all)",
    )
    p.add_argument("--repo-root", default=None, help="checkout path for snippet resolution")
    p.add_argument("--drop-fp", action="store_true", help="filter mode: omit false positives")
    p.add_argument("--context-lines", type=int, default=5)
    p.add_argument("--max-chars", type=int, default=6000)
    p.add_argument("--max-new-tokens", type=int, default=400)
    p.add_argument("--progress-log", default=None, help="optional file for live progress")

    # local
    p.add_argument("--base-model", default="Qwen/Qwen2.5-Coder-7B-Instruct")
    p.add_argument("--adapter-dir", default=None)

    # vllm
    p.add_argument("--vllm-url", default="http://localhost:8000/v1")
    p.add_argument("--vllm-model", default="v8_3_1")
    p.add_argument("--vllm-api-key", default="EMPTY")

    # mock
    p.add_argument(
        "--mock-true-cwes",
        default="",
        help="comma-separated CWEs the mock backend should call TRUE_POSITIVE",
    )

    return p.parse_args(argv)


def build_backend(args: argparse.Namespace):
    if args.backend == "mock":
        true_cwes = {c.strip() for c in args.mock_true_cwes.split(",") if c.strip()}
        return MockBackend(true_cwes=true_cwes)
    if args.backend == "local":
        from .backends.local import LocalBackend

        return LocalBackend(
            base_model=args.base_model,
            adapter_dir=args.adapter_dir,
            max_new_tokens=args.max_new_tokens,
        )
    if args.backend == "vllm":
        from .backends.vllm import VLLMBackend

        return VLLMBackend(
            base_url=args.vllm_url,
            model=args.vllm_model,
            api_key=args.vllm_api_key,
            max_new_tokens=args.max_new_tokens,
        )
    raise ValueError(f"unknown backend: {args.backend}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    backend = build_backend(args)
    summary = triage_sarif(
        sarif_path=args.input,
        output_path=args.output,
        backend=backend,
        mode=args.mode,
        repo_root=args.repo_root,
        drop_fp=args.drop_fp,
        context_lines=args.context_lines,
        max_snippet_chars=args.max_chars,
        progress_log=args.progress_log,
    )
    print(f"emitted {summary['n_emitted']} / {summary['n_findings']} results ({args.mode} mode)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
