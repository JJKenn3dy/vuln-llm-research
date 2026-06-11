"""Build eval JSON from yeswehack/vulnerable-code-snippets + DVWA paired levels.

Output schema matches src/utils/prompts triage format.

yeswehack: vulnerable-only side. Each top-level CWE dir has subdirs with vsnippet/
containing main vulnerable file. Mapping dir -> CWE done manually below.

DVWA: paired low/medium/high/impossible per module. Ground truth:
  low      -> true_positive (no defense)
  medium   -> true_positive (weak defense, usually bypassable)
  high     -> true_positive (better defense, often bypassable by pattern)
  impossible -> false_positive (proper defense)

Output: data/eval/ywh_dvwa_eval.json — list of {case_id, source, claimed_cwe,
    code, language, file_path, truth, defense_level (DVWA only), ...}
"""
import json
import os
import re
import sys
from pathlib import Path

YWH_ROOT = Path("f:/tmp/practical_apps/ywh_snippets")
DVWA_ROOT = Path("f:/tmp/practical_apps/DVWA")
OUT = Path("f:/vuln-llm-research/data/eval/ywh_dvwa_eval.json")

YWH_CWE_MAP = {
    "SQLi": "CWE-89",
    "XSS": "CWE-79",
    "CommandInjection": "CWE-78",
    "CodeInjection": "CWE-94",
    "LFI": "CWE-98",
    "PathTraversal": "CWE-22",
    "SSRF": "CWE-918",
    "Deserialization": "CWE-502",
    "SSTI": "CWE-1336",
    "OpenRedirect": "CWE-601",
    "IDOR": "CWE-639",
    "FileUpload": "CWE-434",
    "CSRF": "CWE-352",
    "PrototypePollution": "CWE-1321",
    "CORS": "CWE-942",
    "BrokenAuth": "CWE-287",
    "FormatInjection": "CWE-134",
    "DoS": "CWE-1333",
    "CachePoisoning": "CWE-444",
    "BusinessLogic": "CWE-840",
    "BufferOverflow": "CWE-119",
}

EXT_LANG = {
    ".php": "php",
    ".js": "javascript",
    ".ts": "typescript",
    ".py": "python",
    ".java": "java",
    ".rb": "ruby",
    ".go": "go",
}

DVWA_CWE_MAP = {
    "sqli": "CWE-89",
    "sqli_blind": "CWE-89",
    "xss_r": "CWE-79",
    "xss_s": "CWE-79",
    "xss_d": "CWE-79",
    "exec": "CWE-78",
    "csrf": "CWE-352",
    "fi": "CWE-98",
    "upload": "CWE-434",
    "open_redirect": "CWE-601",
    "brute": "CWE-307",
    "captcha": "CWE-804",
    "weak_id": "CWE-330",
    "authbypass": "CWE-287",
    "bac": "CWE-639",
    "javascript": "CWE-602",
}


def pick_main_ywh_file(subdir: Path) -> Path | None:
    """Pick the main vulnerable file in a yeswehack subdir/vsnippet/."""
    vsnippet = subdir / "vsnippet"
    if not vsnippet.is_dir():
        return None
    cands = []
    for f in vsnippet.iterdir():
        if not f.is_file():
            continue
        if f.suffix not in EXT_LANG:
            continue
        if "ignore" in f.parts:
            continue
        # Prefer files with numeric prefix or that match the dir name
        score = 0
        if re.match(r"^\d+", f.name):
            score += 10
        if subdir.name.lower().replace("-", "_") in f.name.lower().replace("-", "_"):
            score += 5
        cands.append((score, f))
    cands.sort(key=lambda x: -x[0])
    return cands[0][1] if cands else None


def collect_ywh() -> list[dict]:
    cases = []
    for cat_dir in YWH_ROOT.iterdir():
        if not cat_dir.is_dir() or cat_dir.name not in YWH_CWE_MAP:
            continue
        cwe = YWH_CWE_MAP[cat_dir.name]
        for sub in sorted(cat_dir.iterdir()):
            if not sub.is_dir():
                continue
            f = pick_main_ywh_file(sub)
            if f is None:
                continue
            try:
                code = f.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            if len(code) > 8000:
                code = code[:8000] + "\n// ... [truncated]"
            cases.append({
                "case_id": f"ywh:{cat_dir.name}:{sub.name}",
                "source": "yeswehack/vulnerable-code-snippets",
                "category": cat_dir.name,
                "claimed_cwe": cwe,
                "code": code,
                "language": EXT_LANG[f.suffix],
                "file_path": str(f.relative_to(YWH_ROOT)).replace("\\", "/"),
                "tool": "manual",
                "severity": "HIGH",
                "truth": "TRUE_POSITIVE",
                "defense_level": "vulnerable",
            })
    return cases


def collect_dvwa() -> list[dict]:
    cases = []
    vuln_root = DVWA_ROOT / "vulnerabilities"
    for module_dir in sorted(vuln_root.iterdir()):
        if not module_dir.is_dir():
            continue
        mod = module_dir.name
        if mod not in DVWA_CWE_MAP:
            continue
        cwe = DVWA_CWE_MAP[mod]
        src = module_dir / "source"
        if not src.is_dir():
            continue
        for level in ("low", "medium", "high", "impossible"):
            f = src / f"{level}.php"
            if not f.is_file():
                continue
            try:
                code = f.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            if len(code) > 8000:
                code = code[:8000] + "\n// ... [truncated]"
            truth = "FALSE_POSITIVE" if level == "impossible" else "TRUE_POSITIVE"
            cases.append({
                "case_id": f"dvwa:{mod}:{level}",
                "source": "OWASP/DVWA",
                "category": mod,
                "claimed_cwe": cwe,
                "code": code,
                "language": "php",
                "file_path": str(f.relative_to(DVWA_ROOT)).replace("\\", "/"),
                "tool": "manual",
                "severity": "HIGH",
                "truth": truth,
                "defense_level": level,
            })
    return cases


def main():
    ywh = collect_ywh()
    dvwa = collect_dvwa()
    print(f"yeswehack cases: {len(ywh)}")
    print(f"  by CWE: {sorted({(c['claimed_cwe'], c['category']) for c in ywh})}")
    print(f"DVWA cases: {len(dvwa)}")
    print(f"  by module: { {m: sum(1 for c in dvwa if c['category']==m) for m in sorted({c['category'] for c in dvwa})} }")
    print(f"  by truth: { {t: sum(1 for c in dvwa if c['truth']==t) for t in ['TRUE_POSITIVE','FALSE_POSITIVE']} }")
    all_cases = ywh + dvwa
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(all_cases, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {len(all_cases)} cases to {OUT}")


if __name__ == "__main__":
    main()
