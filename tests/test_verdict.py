from src.product.verdict import (
    FALSE_POSITIVE,
    PARSE_FAIL,
    TRUE_POSITIVE,
    parse,
)


def test_parse_full_response():
    response = (
        "Verdict: TRUE_POSITIVE\n"
        "Confidence: HIGH\n"
        "Reasoning: User input flows unsanitized into exec call.\n"
        "RealCWE: CWE-78\n"
        "SuggestedFix: Replace exec with parameterized call.\n"
    )
    v = parse(response)
    assert v.verdict == TRUE_POSITIVE
    assert v.confidence == "HIGH"
    assert "exec call" in v.reasoning
    assert v.real_cwe == "CWE-78"
    assert "parameterized" in v.suggested_fix


def test_parse_accepts_tp_shorthand():
    v = parse("Verdict: TP\nConfidence: LOW")
    assert v.verdict == TRUE_POSITIVE
    assert v.confidence == "LOW"


def test_parse_accepts_fp_shorthand():
    v = parse("Verdict: FP")
    assert v.verdict == FALSE_POSITIVE


def test_parse_missing_verdict():
    v = parse("Some unrelated chatter without any structured fields.")
    assert v.verdict == PARSE_FAIL
    assert v.confidence == ""
