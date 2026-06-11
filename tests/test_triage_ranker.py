import json
from pathlib import Path

from src.product.backends.mock import MockBackend
from src.product.triage_filter import (
    MODE_RANKER,
    PROPERTY_BAG_KEY,
    iter_partial_records,
    triage_sarif,
)


def _three_finding_sarif(tmp_path: Path) -> Path:
    doc = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Semgrep", "rules": []}},
                "results": [
                    {
                        "ruleId": "low-risk-rule",
                        "level": "warning",
                        "message": {"text": "low"},
                        "properties": {"cwe": "CWE-200"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "low.go"},
                                    "region": {
                                        "startLine": 1,
                                        "endLine": 1,
                                        "snippet": {"text": "log.Println(x)"},
                                    },
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "high-risk-rule",
                        "level": "error",
                        "message": {"text": "high"},
                        "properties": {"cwe": "CWE-78"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "high.go"},
                                    "region": {
                                        "startLine": 1,
                                        "endLine": 1,
                                        "snippet": {"text": "exec.Command(userInput)"},
                                    },
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "medium-rule",
                        "level": "warning",
                        "message": {"text": "med"},
                        "properties": {"cwe": "CWE-377"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "med.py"},
                                    "region": {
                                        "startLine": 5,
                                        "endLine": 5,
                                        "snippet": {"text": "os.tempnam()"},
                                    },
                                }
                            }
                        ],
                    },
                ],
            }
        ],
    }
    path = tmp_path / "in.sarif"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def test_ranker_sorts_by_p_tp_descending(tmp_path):
    sarif = _three_finding_sarif(tmp_path)
    out = tmp_path / "ranked.sarif"
    backend = MockBackend(true_cwes={"CWE-78"})

    summary = triage_sarif(
        sarif_path=sarif,
        output_path=out,
        backend=backend,
        mode=MODE_RANKER,
    )
    assert summary["mode"] == "ranker"
    assert summary["n_scored"] == 3
    assert summary["n_skipped"] == 0
    assert summary["n_emitted"] == 3

    doc = json.loads(out.read_text(encoding="utf-8"))
    results = doc["runs"][0]["results"]
    assert results[0]["ruleId"] == "high-risk-rule"  # CWE-78 highest p_tp
    p_tps = [r["properties"][PROPERTY_BAG_KEY]["p_tp"] for r in results]
    assert p_tps == sorted(p_tps, reverse=True)
    assert all(0.0 <= p <= 1.0 for p in p_tps)


def test_ranker_does_not_drop_low_scores(tmp_path):
    sarif = _three_finding_sarif(tmp_path)
    out = tmp_path / "ranked.sarif"
    summary = triage_sarif(
        sarif_path=sarif,
        output_path=out,
        backend=MockBackend(true_cwes={"CWE-78"}),
        mode=MODE_RANKER,
    )
    assert summary["n_emitted"] == 3


def test_ranker_partial_log_has_p_tp(tmp_path):
    sarif = _three_finding_sarif(tmp_path)
    out = tmp_path / "ranked.sarif"
    triage_sarif(
        sarif_path=sarif,
        output_path=out,
        backend=MockBackend(true_cwes={"CWE-78"}),
        mode=MODE_RANKER,
    )
    records = list(iter_partial_records(str(out) + ".partial.jsonl"))
    assert len(records) == 3
    assert all("p_tp" in r for r in records)
    assert all(r.get("verdict") is None for r in records)
