"""SAST triage product surface.

CLI and HTTP entrypoints that consume SARIF findings, send each finding
through a triage model (local LoRA / vLLM / mock), and emit a filtered
SARIF with verdict, confidence, and reasoning attached to each result's
property bag.
"""
