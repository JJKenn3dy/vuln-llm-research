"""
prepare_train_v6.py — domain-augmented train для v6.

Берём CrossVul (hitoshura25/crossvul, 9313 пар), фильтруем web-языки,
anti-leakage с eval-100 и crossvul-eval-400, сэмплируем 400 пар по топ-15 CWE,
через DeepSeek (OpenRouter) генерируем Cause/Verifications/Fix для vuln
и Reason для safe. Получаем 800 примеров. Объединяем с train_v5b → ~2200 пар.

Output:
    train_data_v6_train.json
    train_data_v6_val.json
    deepseek_cache_v6.jsonl

Использование:
    python prepare_train_v6.py --smoke   # 5 пар, проверка пайплайна
    python prepare_train_v6.py --full    # полные 400 пар
"""
import argparse
import hashlib
import json
import os
import random
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Без прокси, иначе HF не отдаст
for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
    os.environ.pop(k, None)
for line in open(".env", encoding="utf-8"):
    if "=" in line:
        k, v = line.strip().split("=", 1); os.environ.setdefault(k, v)

import httpx
from openai import OpenAI
from datasets import load_dataset

# --- config ---

WEB_LANGUAGES = {"php", "javascript", "js", "typescript", "ts", "python", "py",
                 "java", "ruby", "go"}

# Топ-CWE из CrossVul: пересечение нашего train (11 CWE) + 4 ходовых в CrossVul
TARGET_CWE = [
    "CWE-79",   # XSS — у нас есть, но в CrossVul огромный объём
    "CWE-89",   # SQL injection — у нас есть
    "CWE-22",   # Path traversal — у нас есть
    "CWE-352",  # CSRF — у нас есть
    "CWE-94",   # Code injection — у нас есть
    "CWE-78",   # OS command injection — у нас есть
    "CWE-918",  # SSRF — у нас есть
    "CWE-434",  # File upload — у нас есть
    "CWE-502",  # Insecure deserialization — у нас есть
    "CWE-611",  # XXE — у нас есть
    "CWE-787",  # Buffer overflow — у нас есть
    # новые из CrossVul (не было в нашем train, расширяем coverage):
    "CWE-200",  # Information exposure
    "CWE-732",  # Incorrect permission
    "CWE-264",  # Permissions/access control
    "CWE-310",  # Cryptographic issues
]

# Прямой DeepSeek API — в 5x дешевле OpenRouter и frontier-quality
DEEPSEEK_API_KEY = "sk-7efbdd7335884862ae2801a44c4c5950"
DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEEPSEEK_MODEL = "deepseek-chat"

CACHE_PATH = Path("deepseek_cache_v6.jsonl")
CODE_HEAD_LEN = 256
MAX_CODE_LEN = 4000  # для DeepSeek input — чем меньше, тем дешевле
CONCURRENCY = 6

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

# --- DeepSeek prompts (взяты из v5 prepare) ---

CAUSE_SYSTEM = ("You are an application security expert. Write a code-grounded Cause "
                "explanation. Use ONLY facts visible in the provided code. Reference exact "
                "function, variable, sink, source, or missing check. Do NOT mention product "
                "names, library names, version numbers, affected components, or any external "
                "CVE-only facts. Plain text, 1-2 sentences, max 300 chars.")
CAUSE_USER = """Vulnerability class (CWE): {cwe_id}

Vulnerable code:
{code}

Write a Cause that:
- references the exact variable/function/parameter visible in the code
- names the vulnerable sink and untrusted source if applicable
- describes the missing check or unsafe operation in code terms
- avoids any product name, version, or external context not in code"""

VERIF_SYSTEM = ("You are an application security expert. Write precise, code-specific "
                "verification steps for the given vulnerability. Reference the exact "
                "function, variable, or parameter you see in the code. Do NOT write "
                "generic advice. Plain text only, no markdown, no bullet symbols.")
VERIF_USER = """Vulnerability type: {cwe_id}

Vulnerable code snippet:
{code}

Write 2-3 verification steps specific to THIS code above.
Each step must reference the exact variable/function/parameter visible in the code.
Provide a concrete payload or test action.
Describe what to observe as proof of exploitation."""

FIX_SYSTEM = ("You are an application security expert. Write a single concrete Fix "
              "recommendation for the given vulnerability. Reference exact functions, "
              "variables or parameters visible in the code. No HTML, no markdown, no "
              "version strings, no URLs. Plain text, 1-3 sentences, max 400 chars.")
FIX_USER = """Vulnerability type: {cwe_id}

Vulnerable code:
{vuln_code}

Reference fixed code (hint only, do NOT copy verbatim):
{fixed_code}

Write a Fix that names the exact variable/function and describes the API
or technique to use. Avoid vague phrases like "validate input"."""

REASON_SYSTEM = ("You are a code-review assistant. The given code is a post-fix snippet. "
                 "Describe the visible mitigation pattern (parameterized query, escape, "
                 "validation, allowlist, etc.) referencing the exact API/variable/check in "
                 "the code. Do NOT mention any vulnerability class name (CWE-XX, 'XSS', "
                 "'SQL injection', 'CSRF', etc.). Do NOT claim the code is safe in general. "
                 "No markdown, max 200 chars.")
REASON_USER = """Internal context (do NOT mention in output): code was patched against {cwe_id}.

Code snippet (post-fix):
{code}

Output exactly one line describing the visible mitigation, in this style:
- "The query uses parameterized execution via cursor.execute(sql, (user_id,))."
- "The path is canonicalized via os.path.realpath() and checked against an allowlist."
- "The output is escaped via html.escape(name) before being rendered."
- "The XML parser disables external entity resolution."
"""


# --- helpers ---

def code_hash(code: str) -> str:
    if not code: return ""
    return hashlib.sha1(code.strip()[:CODE_HEAD_LEN].encode("utf-8", errors="replace")).hexdigest()[:12]


def load_existing_hashes(*paths) -> set:
    hashes = set()
    for p in paths:
        p = Path(p)
        if not p.exists(): continue
        data = json.load(open(p, encoding="utf-8"))
        for ex in data:
            md = ex.get("metadata", {})
            for k in ("vuln_code_hash", "fixed_code_hash"):
                h = md.get(k)
                if h: hashes.add(h)
            for m in ex.get("messages", []):
                if m.get("role") == "user":
                    c = m.get("content", "")
                    if "Code:" in c:
                        hashes.add(code_hash(c.split("Code:", 1)[1]))
    return hashes


def make_client():
    http_client = httpx.Client(trust_env=False, timeout=90)
    return OpenAI(
        base_url=DEEPSEEK_BASE_URL,
        api_key=DEEPSEEK_API_KEY,
        timeout=90,
        http_client=http_client,
    )


def load_cache():
    """Resume cache: file_pair_id+field -> content."""
    cache = {}
    if CACHE_PATH.exists():
        for line in CACHE_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line: continue
            try:
                rec = json.loads(line)
                cache[(rec["pair_id"], rec["field"])] = rec["content"]
            except Exception:
                pass
    return cache


def append_cache(pair_id, field, content):
    with CACHE_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"pair_id": pair_id, "field": field, "content": content},
                           ensure_ascii=False) + "\n")


def call_deepseek(client, system_msg, user_msg, max_tokens=300, retries=3):
    last_err = None
    for attempt in range(retries):
        try:
            resp = client.chat.completions.create(
                model=DEEPSEEK_MODEL,
                messages=[{"role": "system", "content": system_msg},
                          {"role": "user", "content": user_msg}],
                max_tokens=max_tokens, temperature=0.2,
            )
            return (resp.choices[0].message.content or "").strip()
        except Exception as e:
            last_err = e
            time.sleep(2 ** attempt)
    raise RuntimeError(f"DeepSeek failed: {last_err}")


def gen_vuln_content(client, pair_id, cwe_id, vuln_code, fixed_code, cache):
    """Сгенерировать Cause/Verifications/Fix для vuln-примера."""
    out = {}
    if (pair_id, "cause") in cache:
        out["cause"] = cache[(pair_id, "cause")]
    else:
        out["cause"] = call_deepseek(client, CAUSE_SYSTEM,
                                      CAUSE_USER.format(cwe_id=cwe_id, code=vuln_code[:MAX_CODE_LEN]),
                                      max_tokens=200)
        append_cache(pair_id, "cause", out["cause"])

    if (pair_id, "verif") in cache:
        out["verif"] = cache[(pair_id, "verif")]
    else:
        out["verif"] = call_deepseek(client, VERIF_SYSTEM,
                                      VERIF_USER.format(cwe_id=cwe_id, code=vuln_code[:MAX_CODE_LEN]),
                                      max_tokens=300)
        append_cache(pair_id, "verif", out["verif"])

    if (pair_id, "fix") in cache:
        out["fix"] = cache[(pair_id, "fix")]
    else:
        out["fix"] = call_deepseek(client, FIX_SYSTEM,
                                    FIX_USER.format(cwe_id=cwe_id,
                                                    vuln_code=vuln_code[:MAX_CODE_LEN // 2],
                                                    fixed_code=fixed_code[:MAX_CODE_LEN // 2]),
                                    max_tokens=300)
        append_cache(pair_id, "fix", out["fix"])
    return out


def gen_safe_reason(client, pair_id, cwe_id, fixed_code, cache):
    if (pair_id, "reason") in cache:
        return cache[(pair_id, "reason")]
    out = call_deepseek(client, REASON_SYSTEM,
                         REASON_USER.format(cwe_id=cwe_id, code=fixed_code[:MAX_CODE_LEN]),
                         max_tokens=120)
    append_cache(pair_id, "reason", out)
    return out


def make_train_example(code, language, label, cwe_id, content, file_pair_id):
    """Один пример в формате v5b train (system + user + assistant)."""
    user_msg = USER_TEMPLATE.format(
        language=(language or "Generic").capitalize(),
        code=code[:MAX_CODE_LEN],
    )
    if label == "vulnerable":
        assistant = (f"Type: {cwe_id}\n"
                     f"Cause: {content['cause']}\n"
                     f"VerificationSteps: {content['verif']}\n"
                     f"Fix: {content['fix']}")
    else:
        assistant = f"Verdict: No vulnerability detected.\nReason: {content}"
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
            {"role": "assistant", "content": assistant},
        ],
        "metadata": {
            "label": label,
            "cve_id": "",
            "cwe_id": cwe_id,
            "repo": "",
            "file_path": "",
            "vuln_code_hash": code_hash(code) if label == "vulnerable" else "",
            "fixed_code_hash": code_hash(code) if label == "safe" else "",
            "split_group": "v6_crossvul",
            "source": "crossvul",
            "file_pair_id": file_pair_id,
            "language": language,
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--smoke", action="store_true", help="5 пар для проверки пайплайна")
    ap.add_argument("--full", action="store_true", help="full 400 пар (~$1.0)")
    ap.add_argument("--n-pairs", type=int, default=400, help="сколько пар взять (default 400)")
    args = ap.parse_args()

    target = 5 if args.smoke else (args.n_pairs if args.full else 400)
    random.seed(42)

    print(f"=== prepare_train_v6.py ({target} pairs target) ===")
    print("Loading hitoshura25/crossvul...")
    ds = load_dataset("hitoshura25/crossvul", token=os.environ["HF_TOKEN"])["train"]
    print(f"  total: {len(ds)}")

    # Web filter
    web = [ex for ex in ds if (ex.get("language") or "").lower() in WEB_LANGUAGES]
    print(f"  web-languages: {len(web)}")

    # CWE filter
    web_cwe = [ex for ex in web if ex.get("cwe_id") in TARGET_CWE]
    print(f"  in target CWE-set ({len(TARGET_CWE)} CWE): {len(web_cwe)}")

    # Anti-leakage
    print("  anti-leakage check...")
    excluded_hashes = load_existing_hashes(
        "eval_v5_inputs.json",
        "eval_crossvul_inputs.json",
        "train_data_v5b_train.json",
        "train_data_v5b_val.json",
    )
    print(f"    excluded hashes: {len(excluded_hashes)}")
    leaked = 0
    clean = []
    for ex in web_cwe:
        if code_hash(ex["vulnerable_code"]) in excluded_hashes or \
           code_hash(ex["fixed_code"]) in excluded_hashes:
            leaked += 1
        else:
            clean.append(ex)
    print(f"    removed leaked: {leaked}, remaining: {len(clean)}")

    # Балансировка по CWE: cap ≤ ceil(target / num_cwe) на CWE-класс
    cap_per_cwe = max(1, target * 3 // len(TARGET_CWE))  # запас, потом обрежем
    by_cwe = {}
    for ex in clean:
        by_cwe.setdefault(ex["cwe_id"], []).append(ex)

    sampled = []
    for cwe in TARGET_CWE:
        pool = by_cwe.get(cwe, [])
        random.shuffle(pool)
        take = pool[:cap_per_cwe]
        sampled.extend(take)
        print(f"    {cwe}: {len(pool)} avail, take {len(take)}")

    random.shuffle(sampled)
    sampled = sampled[:target]
    print(f"  final selected: {len(sampled)} pairs")

    # DeepSeek генерация
    print(f"\n=== DeepSeek generation via OpenRouter ({DEEPSEEK_MODEL}) ===")
    client = make_client()
    cache = load_cache()
    print(f"  cache loaded: {len(cache)} entries")

    examples = []
    cum_cost = 0.0
    PIN, POUT = 0.27, 1.10  # USD per 1M tokens

    def process(pair):
        try:
            pid = pair.get("file_pair_id") or f"crossvul_{id(pair)}"
            cwe = pair["cwe_id"]
            lang = pair.get("language") or ""
            v_code = pair["vulnerable_code"]
            f_code = pair["fixed_code"]
            # Vuln content
            v_content = gen_vuln_content(client, pid, cwe, v_code, f_code, cache)
            v_ex = make_train_example(v_code, lang, "vulnerable", cwe, v_content, pid)
            # Safe content
            s_reason = gen_safe_reason(client, pid, cwe, f_code, cache)
            s_ex = make_train_example(f_code, lang, "safe", cwe, s_reason, pid)
            return v_ex, s_ex, None
        except Exception as e:
            return None, None, str(e)

    started = time.time()
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as ex_pool:
        futures = [ex_pool.submit(process, p) for p in sampled]
        done = 0
        for fut in as_completed(futures):
            v_ex, s_ex, err = fut.result()
            done += 1
            if err:
                print(f"  [{done}/{len(sampled)}] ERR: {err[:80]}")
                continue
            examples.append(v_ex)
            examples.append(s_ex)
            elapsed = time.time() - started
            rate = done / elapsed if elapsed else 0
            eta = (len(sampled) - done) / rate if rate else 0
            if done % 10 == 0 or done == len(sampled):
                print(f"  [{done}/{len(sampled)}]  elapsed={elapsed:.0f}s ETA={eta:.0f}s")

    print(f"\n  generated examples: {len(examples)}")

    # Объединить с v5b train + val
    print("\n=== Merging with train_v5b ===")
    v5b_train = json.load(open("train_data_v5b_train.json", encoding="utf-8"))
    v5b_val = json.load(open("train_data_v5b_val.json", encoding="utf-8"))
    print(f"  v5b train: {len(v5b_train)}, val: {len(v5b_val)}")

    # Split CrossVul examples 90/10 train/val
    random.shuffle(examples)
    n_val = max(1, len(examples) // 10)
    cv_val = examples[:n_val]
    cv_train = examples[n_val:]

    final_train = v5b_train + cv_train
    final_val = v5b_val + cv_val
    random.shuffle(final_train)
    random.shuffle(final_val)
    print(f"  v6 train: {len(final_train)} (={len(v5b_train)}+{len(cv_train)})")
    print(f"  v6 val:   {len(final_val)} (={len(v5b_val)}+{len(cv_val)})")

    json.dump(final_train, open("train_data_v6_train.json", "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)
    json.dump(final_val, open("train_data_v6_val.json", "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)
    print("\nSAVED: train_data_v6_train.json, train_data_v6_val.json")

    # Final stats
    cwe_dist = Counter(e["metadata"]["cwe_id"] for e in final_train
                       if e["metadata"]["label"] == "vulnerable")
    print("\nCWE distribution in v6 train (vuln only):")
    for c, n in cwe_dist.most_common():
        print(f"  {c}: {n}")


if __name__ == "__main__":
    main()
