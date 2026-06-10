"""Inspect raw hitoshura25/cvefixes HF dataset to confirm pre/post pairs are present."""
from datasets import load_dataset
from collections import Counter

ds = load_dataset("hitoshura25/cvefixes", split="train")
print("Total rows:", len(ds))
print("Columns:", ds.column_names)
print()

row = ds[0]
print("=== row 0 (first 200 ch per field) ===")
for k, v in row.items():
    s = str(v)
    suffix = " ..." if len(s) > 200 else ""
    print(f"  {k} ({type(v).__name__}): {s[:200]}{suffix}")
print()

WEB_CWES = {"CWE-79", "CWE-89", "CWE-22", "CWE-78", "CWE-94", "CWE-352",
            "CWE-434", "CWE-502", "CWE-611", "CWE-798", "CWE-918", "CWE-787"}

if "cwe_id" in ds.column_names:
    cwes = Counter(ds["cwe_id"])
    print("Top 20 CWEs (all):")
    for c, n in cwes.most_common(20):
        marker = " <-- web" if c in WEB_CWES else ""
        print(f"  {c}: {n}{marker}")
    web_total = sum(n for c, n in cwes.items() if c in WEB_CWES)
    print(f"  TOTAL web-CWE rows: {web_total} / {len(ds)}")
    print()

if "language" in ds.column_names:
    langs = Counter(ds["language"])
    print("Top 10 langs:", langs.most_common(10))
else:
    print("No 'language' col")
print()

pre_post_cols = [c for c in ds.column_names if "vuln" in c.lower() or "fix" in c.lower() or "before" in c.lower() or "after" in c.lower()]
print("Columns suggestive of pre/post pair:", pre_post_cols)

if "cve_id" in ds.column_names:
    cves = Counter(ds["cve_id"])
    print(f"Unique CVEs: {len(cves)}")
    print(f"  rows per CVE > 1: {sum(1 for n in cves.values() if n > 1)}")
    print(f"  rows per CVE == 1: {sum(1 for n in cves.values() if n == 1)}")
