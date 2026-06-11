import json
from pathlib import Path

from src.product.backends.mock import MockBackend
from src.product.triage_filter import (
    PROPERTY_BAG_KEY,
    iter_partial_records,
    triage_sarif,
)


def _sarif(tmp_path: Path) -> Path:
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Semgrep",
                        "rules": [
                            {
                                "id": "tp-rule",
                                "properties": {"tags": ["CWE-78"], "security-severity": "8.0"},
                            },
                            {
                                "id": "fp-rule",
                                "properties": {"tags": ["CWE-200"], "security-severity": "3.0"},
                            },
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "tp-rule",
                        "level": "error",
                        "message": {"text": "exec sink"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "a.go"},
                                    "region": {
                                        "startLine": 1,
                                        "endLine": 1,
                                        "snippet": {"text": "exec.Command(input)"},
                                    },
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "fp-rule",
                        "level": "warning",
                        "message": {"text": "info leak"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "b.go"},
                                    "region": {
                                        "startLine": 5,
                                        "endLine": 5,
                                        "snippet": {"text": "log.Println(secret)"},
                                    },
                                }
                            }
                        ],
                    },
                ],
            }
        ],
    }
    path = tmp_path / "input.sarif"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def test_triage_keeps_all_and_annotates_property_bag(tmp_path):
    sarif = _sarif(tmp_path)
    out = tmp_path / "filtered.sarif"
    backend = MockBackend(true_cwes={"CWE-78"})

    summary = triage_sarif(
        sarif_path=sarif,
        output_path=out,
        backend=backend,
        drop_fp=False,
        dump_every=1,
    )
    assert summary["counts"]["TRUE_POSITIVE"] == 1
    assert summary["counts"]["FALSE_POSITIVE"] == 1
    assert summary["n_emitted"] == 2

    data = json.loads(out.read_text(encoding="utf-8"))
    results = data["runs"][0]["results"]
    assert results[0]["properties"][PROPERTY_BAG_KEY]["verdict"] == "TRUE_POSITIVE"
    assert results[1]["properties"][PROPERTY_BAG_KEY]["verdict"] == "FALSE_POSITIVE"


def test_drop_fp_strips_false_positives(tmp_path):
    sarif = _sarif(tmp_path)
    out = tmp_path / "filtered.sarif"
    summary = triage_sarif(
        sarif_path=sarif,
        output_path=out,
        backend=MockBackend(true_cwes={"CWE-78"}),
        drop_fp=True,
    )
    assert summary["n_emitted"] == 1
    data = json.loads(out.read_text(encoding="utf-8"))
    results = data["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "tp-rule"


def test_partial_log_written_per_finding(tmp_path):
    sarif = _sarif(tmp_path)
    out = tmp_path / "filtered.sarif"
    triage_sarif(
        sarif_path=sarif,
        output_path=out,
        backend=MockBackend(true_cwes={"CWE-78"}),
    )
    records = list(iter_partial_records(str(out) + ".partial.jsonl"))
    assert len(records) == 2
    assert records[0]["verdict"] == "TRUE_POSITIVE"
    assert records[1]["verdict"] == "FALSE_POSITIVE"
    assert records[1]["counts_so_far"]["FALSE_POSITIVE"] == 1
