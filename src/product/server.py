"""FastAPI surface around triage_sarif.

  uvicorn src.product.server:build_app --factory --port 8080

POST /triage_sarif
    multipart/form-data:
      sarif: SARIF file
      repo_root: optional path string
      drop_fp: bool (default false)
    returns: filtered SARIF JSON

POST /triage_finding
    JSON: { tool, claimed_cwe, severity, file_path, line_range, code }
    returns: parsed verdict
"""
import json
import os
import tempfile
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

from .backends import TriageBackend, TriageRequest
from .triage_filter import triage_sarif
from .verdict import parse


def build_app(backend: Optional[TriageBackend] = None):

    if backend is None:
        backend = _build_default_backend()

    app = FastAPI(title="vuln-llm triage", version="0.1.0")

    class FindingIn(BaseModel):
        tool: str
        claimed_cwe: str
        severity: str = "UNKNOWN"
        file_path: str
        line_range: str
        code: str

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/triage_finding")
    def triage_finding(body: FindingIn):
        req = TriageRequest(
            finding_id=f"{body.tool}:{body.file_path}:{body.line_range}",
            tool=body.tool,
            claimed_cwe=body.claimed_cwe,
            severity=body.severity,
            file_path=body.file_path,
            line_range=body.line_range,
            code=body.code,
        )
        raw = backend.infer(req)
        v = parse(raw)
        return {
            "verdict": v.verdict,
            "confidence": v.confidence,
            "reasoning": v.reasoning,
            "real_cwe": v.real_cwe,
            "suggested_fix": v.suggested_fix,
            "raw_response": v.raw_response,
        }

    @app.post("/triage_sarif")
    async def triage_sarif_endpoint(
        sarif: UploadFile = File(...),
        repo_root: Optional[str] = Form(None),
        drop_fp: bool = Form(False),
    ):
        try:
            body = await sarif.read()
        except Exception as e:
            raise HTTPException(400, f"failed to read upload: {e}")

        with tempfile.TemporaryDirectory() as tmp:
            in_path = Path(tmp) / "in.sarif"
            out_path = Path(tmp) / "out.sarif"
            in_path.write_bytes(body)
            try:
                triage_sarif(
                    sarif_path=in_path,
                    output_path=out_path,
                    backend=backend,
                    repo_root=repo_root,
                    drop_fp=drop_fp,
                )
            except ValueError as e:
                raise HTTPException(400, str(e))
            return json.loads(out_path.read_text(encoding="utf-8"))

    return app


def _build_default_backend() -> TriageBackend:
    """Pick the backend from env vars so this stays usable in different deploys."""
    kind = os.environ.get("TRIAGE_BACKEND", "mock").lower()
    if kind == "mock":
        from .backends.mock import MockBackend

        cwes = {c.strip() for c in os.environ.get("MOCK_TRUE_CWES", "").split(",") if c.strip()}
        return MockBackend(true_cwes=cwes)
    if kind == "local":
        from .backends.local import LocalBackend

        return LocalBackend(
            base_model=os.environ.get("BASE_MODEL", "Qwen/Qwen2.5-Coder-7B-Instruct"),
            adapter_dir=os.environ.get("ADAPTER_DIR"),
        )
    if kind == "vllm":
        from .backends.vllm import VLLMBackend

        return VLLMBackend(
            base_url=os.environ.get("VLLM_URL", "http://localhost:8000/v1"),
            model=os.environ.get("VLLM_MODEL", "v8_3_1"),
            api_key=os.environ.get("VLLM_API_KEY", "EMPTY"),
        )
    raise ValueError(f"unknown TRIAGE_BACKEND={kind!r}")
