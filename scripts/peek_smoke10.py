"""Read smoke10 outputs and characterise each case + model decision."""
import json
import re

raw_cases = json.load(open("/workspace/runs/v8_2_eval/smoke10.json"))
outputs = json.load(open("/workspace/runs/v8_2_eval/smoke10_outputs.json"))

case_by_idx = {i: c for i, c in enumerate(raw_cases)}

print(f"{'idx':3s} {'CVE':25s} {'CWE':9s} {'lang':10s} {'true':16s} {'pred':16s} {'ok':3s} {'fp_src':18s} {'code_len':9s}")
print("-" * 130)
wrong = []
for i, o in enumerate(outputs):
    c = case_by_idx[i]
    md = c["metadata"]
    true = md["verdict"]
    pred = o["predicted_verdict"]
    user = c["messages"][1]["content"]
    m = re.search(r"Code:\s*\n(.*?)$", user, re.DOTALL)
    code = m.group(1).strip() if m else ""
    fp_src = md.get("fp_source", "-")
    ok = "✓" if true == pred else "✗"
    print(f"{i:<3d} {md.get('case_id', '')[:25]:25s} {md.get('claimed_cwe', ''):9s} "
          f"{md.get('language', '')[:10]:10s} {true:16s} {pred:16s} {ok:3s} {fp_src:18s} {len(code):>9d}")
    if true != pred:
        wrong.append((i, c, o))

print()
print("=" * 60)
print(f"Wrong cases: {len(wrong)}")
for i, c, o in wrong:
    md = c["metadata"]
    user = c["messages"][1]["content"]
    m = re.search(r"Code:\s*\n(.*?)$", user, re.DOTALL)
    code = m.group(1).strip() if m else ""
    print(f"\n--- WRONG #{i}: {md.get('case_id')} | claimed={md.get('claimed_cwe')} | true={md['verdict']} | pred={o['predicted_verdict']} ---")
    print(f"Code ({len(code)} ch):")
    print(code[:600])
    print()
    print("Model said:")
    print(o["model_response"][:800])
