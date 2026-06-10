"""Eyeball post_fix and misclass FP examples from the teacher smoke."""
import json
import re

d = json.load(open("/workspace/runs/smoke_teacher/triage_train.json"))
for fp_type in ("post_fix", "misclassified_cwe"):
    print(f"\n========== FP_SOURCE = {fp_type} ==========")
    examples = [e for e in d if e["metadata"].get("fp_source") == fp_type]
    if not examples:
        print("  none in this split")
        continue
    for e in examples[:1]:
        md = e["metadata"]
        cwe = md.get("claimed_cwe")
        real = md.get("real_cwe")
        lang = md.get("language")
        case = md.get("case_id")
        print(f"case_id={case} claimed_cwe={cwe} real_cwe={real} lang={lang}")
        m = re.search(r"Code:\s*\n(.*?)$", e["messages"][1]["content"], re.DOTALL)
        if m:
            c = m.group(1).strip()
            print(f"CODE ({len(c)} chars, first 400):")
            print(c[:400])
        print("\nASSISTANT:")
        print(e["messages"][2]["content"])
