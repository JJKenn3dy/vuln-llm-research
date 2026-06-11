import json

from src.product.sarif_parser import iter_findings, load_sarif


def _semgrep_doc(tmp_path, snippet_text=None):
    region = {"startLine": 12, "endLine": 14}
    if snippet_text is not None:
        region["snippet"] = {"text": snippet_text}
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
                                "id": "go.lang.security.audit.dangerous-exec-cmd",
                                "shortDescription": {"text": "Detected exec without sanitization"},
                                "properties": {
                                    "tags": ["CWE-78", "security"],
                                    "security-severity": "8.1",
                                },
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "go.lang.security.audit.dangerous-exec-cmd",
                        "message": {"text": "exec call with untrusted input"},
                        "level": "error",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "cmd/main.go"},
                                    "region": region,
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    path = tmp_path / "semgrep.sarif"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def _codeql_doc(tmp_path):
    doc = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [
                            {
                                "id": "py/sql-injection",
                                "shortDescription": {"text": "SQL query built from user-controlled sources"},
                                "defaultConfiguration": {"level": "error"},
                                "relationships": [
                                    {"target": {"id": "external/cwe/cwe-089"}}
                                ],
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleIndex": 0,
                        "message": {"text": "User input flows into SQL"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app/db.py"},
                                    "region": {"startLine": 42, "endLine": 42},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    path = tmp_path / "codeql.sarif"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def test_load_rejects_legacy_version(tmp_path):
    path = tmp_path / "old.sarif"
    path.write_text(json.dumps({"version": "1.0"}), encoding="utf-8")
    try:
        load_sarif(path)
    except ValueError as e:
        assert "unsupported SARIF version" in str(e)
    else:
        raise AssertionError("expected ValueError")


def test_semgrep_finding_minimal_fields(tmp_path):
    path = _semgrep_doc(tmp_path, snippet_text="exec.Command(userInput)")
    doc = load_sarif(path)
    findings = list(iter_findings(doc))
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "semgrep"
    assert f.rule_id == "go.lang.security.audit.dangerous-exec-cmd"
    assert f.claimed_cwe == "CWE-78"
    assert f.severity == "HIGH"
    assert f.file_path == "cmd/main.go"
    assert f.line_start == 12 and f.line_end == 14
    assert f.snippet == "exec.Command(userInput)"


def test_severity_falls_back_to_level(tmp_path):
    path = _codeql_doc(tmp_path)
    findings = list(iter_findings(load_sarif(path)))
    assert findings[0].severity == "HIGH"


def test_codeql_cwe_via_relationships(tmp_path):
    path = _codeql_doc(tmp_path)
    findings = list(iter_findings(load_sarif(path)))
    assert findings[0].claimed_cwe == "CWE-89"


def test_finding_id_is_stable_without_guid(tmp_path):
    path = _semgrep_doc(tmp_path, snippet_text="x")
    findings_a = list(iter_findings(load_sarif(path)))
    findings_b = list(iter_findings(load_sarif(path)))
    assert findings_a[0].finding_id == findings_b[0].finding_id


def test_no_snippet_returns_none(tmp_path):
    path = _semgrep_doc(tmp_path, snippet_text=None)
    findings = list(iter_findings(load_sarif(path)))
    assert findings[0].snippet is None
