"""Print a slice of hand_label_blind.json in compact form for fast labeling."""
import json
import sys
from pathlib import Path

START = int(sys.argv[1])
END = int(sys.argv[2])  # exclusive

P = Path("f:/vuln-llm-research/data/exam/sastbench250_handlabel/hand_label_blind.json")
data = json.loads(P.read_text(encoding="utf-8"))

for i in range(START, min(END, len(data))):
    case = data[i]
    prompt = case["snippet_prompt"]
    # Strip prompt boilerplate to get just code
    after_code = prompt.find("Code:\n")
    after_output = prompt.find("\nOutput exactly")
    code = prompt[after_code + 6:after_output] if after_code >= 0 and after_output >= 0 else prompt
    print(f"=== idx={i} blind_id={case['blind_id']} | CWE={case['claimed_cwe']} | {case['language']} | {case['file_path']} ({case['line_range']}) ===")
    print(code)
    print()
