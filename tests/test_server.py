import json
from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from src.product.backends.mock import MockBackend
from src.product.server import build_app


@pytest.fixture
def client():
    app = build_app(backend=MockBackend(true_cwes={"CWE-78"}))
    return TestClient(app)


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_triage_finding(client):
    r = client.post(
        "/triage_finding",
        json={
            "tool": "semgrep",
            "claimed_cwe": "CWE-78",
            "severity": "HIGH",
            "file_path": "cmd.go",
            "line_range": "1-5",
            "code": "exec.Command(userInput)",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "TRUE_POSITIVE"
    assert body["real_cwe"] == "CWE-78"


def test_triage_sarif_endpoint(client, tmp_path):
    doc = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Semgrep", "rules": []}},
                "results": [
                    {
                        "ruleId": "r1",
                        "level": "error",
                        "message": {"text": "x"},
                        "properties": {"cwe": "CWE-78"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "a.go"},
                                    "region": {
                                        "startLine": 1,
                                        "endLine": 1,
                                        "snippet": {"text": "exec(x)"},
                                    },
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    sarif_path = tmp_path / "in.sarif"
    sarif_path.write_text(json.dumps(doc), encoding="utf-8")

    with open(sarif_path, "rb") as f:
        r = client.post(
            "/triage_sarif",
            files={"sarif": ("in.sarif", f, "application/json")},
            data={"drop_fp": "false"},
        )
    assert r.status_code == 200
    out = r.json()
    results = out["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["properties"]["vuln_llm_triage"]["verdict"] == "TRUE_POSITIVE"
