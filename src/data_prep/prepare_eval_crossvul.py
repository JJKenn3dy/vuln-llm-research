"""
Подготовка стандартизированного eval-сета на CrossVul для нашей v5b модели.

Цель: получить fair-comparison с published numbers (LLMxCPG-D и др.) на
публичном бенчмарке. Это наш аналог "SOTA на стандартном тесте".

Шаги:
1. Скачать hitoshura25/crossvul (9313 before/after пар, 158 CWE, 21 язык)
2. Отфильтровать web-языки (PHP, JS, Python, Java, Ruby, TS, Go)
3. Anti-leakage: убрать пересечения с нашим train_data_v5b_train.json по
   hash кода (sha1 первых 256 символов).
4. Сэмплировать сбалансированно: 200 vuln + 200 safe (вычитая anti-leakage).
   Если будет меньше — берём что есть.
5. Сконвертировать в формат eval_v5_inputs.json (тот же chat-template).

Output: eval_crossvul_inputs.json
"""
import hashlib
import json
import os
import random
import sys
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Без прокси, иначе HF не отдаст
for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
    os.environ.pop(k, None)
for line in open(".env", encoding="utf-8"):
    if "=" in line:
        k, v = line.strip().split("=", 1); os.environ.setdefault(k, v)

from datasets import load_dataset

WEB_LANGUAGES = {"php", "javascript", "js", "typescript", "ts", "python", "py",
                 "java", "ruby", "go"}

SYSTEM_PROMPT = ("You are a secure code analysis assistant. Decide whether the "
                 "given code contains a security vulnerability. If a "
                 "vulnerability is present, output a structured security "
                 "report. If the code is safe, state that no vulnerability "
                 "was detected. Output only plain text, no markdown.")

USER_TEMPLATE = """Analyze the following code for security vulnerabilities.

If vulnerable, output exactly these 4 fields in this exact order:
Type:
Cause:
VerificationSteps:
Fix:

If safe, output exactly:
Verdict: No vulnerability detected.
Reason: <one short sentence why>

Language/Context:
{language}

Code:
{code}"""

CODE_HEAD_LEN = 256
MAX_CODE_LEN = 8000  # обрезать слишком длинные — модель всё равно не съест


def code_hash(code: str) -> str:
    """sha1 первых N символов нормализованного кода."""
    if not code:
        return ""
    norm = code.strip()[:CODE_HEAD_LEN]
    return hashlib.sha1(norm.encode("utf-8", errors="replace")).hexdigest()[:12]


def load_train_hashes(path: Path) -> set[str]:
    """Все hash'ы кода из train_v5b — уязвимый и фиксированный."""
    hashes = set()
    if not path.exists():
        print(f"[warn] {path} not found, anti-leakage will be skipped")
        return hashes
    data = json.load(open(path, encoding="utf-8"))
    for ex in data:
        md = ex.get("metadata", {})
        for k in ("vuln_code_hash", "fixed_code_hash"):
            h = md.get(k)
            if h:
                hashes.add(h)
        # Также вычислим по содержимому user message — раскопаем код
        for m in ex.get("messages", []):
            if m.get("role") == "user":
                content = m.get("content", "")
                if "Code:" in content:
                    code = content.split("Code:", 1)[1].strip()
                    hashes.add(code_hash(code))
    return hashes


def make_example(code: str, language: str, label: str, cwe_id: str,
                 file_pair_id: str, src_idx: int):
    """Один пример в формате нашего eval_v5_inputs.json."""
    code_clipped = code[:MAX_CODE_LEN]
    user_msg = USER_TEMPLATE.format(
        language=(language or "Generic").capitalize(),
        code=code_clipped,
    )
    if label == "vulnerable":
        # Заглушка для assistant — модель её не видит, но keepим формат
        assistant_msg = (f"Type: {cwe_id}\nCause: N/A\n"
                         "VerificationSteps: N/A\nFix: N/A")
    else:
        assistant_msg = "Verdict: No vulnerability detected.\nReason: N/A"
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
            {"role": "assistant", "content": assistant_msg},
        ],
        "metadata": {
            "label": label,
            "cve_id": "",
            "cwe_id": cwe_id,
            "repo": "",
            "file_path": "",
            "vuln_code_hash": code_hash(code) if label == "vulnerable" else "",
            "fixed_code_hash": code_hash(code) if label == "safe" else "",
            "split_group": "",
            "source": "crossvul",
            "file_pair_id": file_pair_id,
            "src_idx": src_idx,
            "language": language,
        },
    }


def main():
    random.seed(42)

    print("Loading hitoshura25/crossvul...")
    ds = load_dataset("hitoshura25/crossvul", token=os.environ["HF_TOKEN"])["train"]
    print(f"  total pairs: {len(ds)}")

    # 1. Фильтр web-языков
    web_pairs = [ex for ex in ds if (ex.get("language") or "").lower() in WEB_LANGUAGES]
    print(f"  web-language pairs (PHP/JS/TS/Python/Java/Ruby/Go): {len(web_pairs)}")
    lang_dist = Counter(ex["language"].lower() for ex in web_pairs)
    print("  language distribution:")
    for lang, cnt in lang_dist.most_common():
        print(f"    {lang}: {cnt}")

    # 2. Anti-leakage с train_v5b
    train_path = Path("train_data_v5b_train.json")
    train_hashes = load_train_hashes(train_path)
    print(f"  train_v5b hashes loaded: {len(train_hashes)}")

    leaked = 0
    clean_pairs = []
    for ex in web_pairs:
        v_h = code_hash(ex["vulnerable_code"])
        f_h = code_hash(ex["fixed_code"])
        if v_h in train_hashes or f_h in train_hashes:
            leaked += 1
            continue
        clean_pairs.append(ex)
    print(f"  removed leaked pairs: {leaked}")
    print(f"  clean pairs after anti-leakage: {len(clean_pairs)}")

    # 3. Сэмплируем сбалансированно (200/200)
    target_per_class = 200
    random.shuffle(clean_pairs)
    selected = clean_pairs[: target_per_class]
    print(f"  selected pairs (yielding 2x examples): {len(selected)}")

    # 4. Конвертируем в (vuln + safe) пары
    eval_examples = []
    for src_idx, ex in enumerate(selected):
        cwe = ex.get("cwe_id") or ""
        lang = ex.get("language") or ""
        fpid = ex.get("file_pair_id") or ""
        # уязвимый
        eval_examples.append(make_example(
            ex["vulnerable_code"], lang, "vulnerable", cwe, fpid, src_idx,
        ))
        # безопасный (fixed)
        eval_examples.append(make_example(
            ex["fixed_code"], lang, "safe", cwe, fpid, src_idx,
        ))
    random.shuffle(eval_examples)

    print(f"  total eval examples: {len(eval_examples)} "
          f"({sum(1 for e in eval_examples if e['metadata']['label']=='vulnerable')} vuln "
          f"+ {sum(1 for e in eval_examples if e['metadata']['label']=='safe')} safe)")

    out_path = Path("eval_crossvul_inputs.json")
    out_path.write_text(json.dumps(eval_examples, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    print(f"\nSAVED: {out_path}")

    # quick CWE distribution
    cwe_dist = Counter(e["metadata"]["cwe_id"] for e in eval_examples
                       if e["metadata"]["label"] == "vulnerable")
    print(f"\nCWE coverage in vuln subset (top 15 of {len(cwe_dist)}):")
    for cwe, cnt in cwe_dist.most_common(15):
        print(f"  {cwe}: {cnt}")


if __name__ == "__main__":
    main()
