"""Eyeball-compare top candidates from teacher_ab_v3.json."""
import json
r = json.load(open("/workspace/runs/teacher_ab_v3.json"))
picks = ["openrouter_opus48", "openrouter_haiku45", "openai_gpt54_mini"]
for i in (0, 4, 8):
    s = r["samples"][i]
    print(f"\n=== sample {i}: {s['cve_id']} {s['cwe']} ===")
    print("CODE (first 200 ch):")
    print(s["code_excerpt"][:200])
    for k in picks:
        ans = s["answers"].get(k, "")
        print(f"\n[{k}] ({len(ans)} ch):")
        print(ans)
