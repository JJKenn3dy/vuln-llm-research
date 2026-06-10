"""
prepare_train_v7lite.py — v7-lite (single-teacher DeepSeek scaling).

Идея: расширить v6 train ещё ~1800 уникальными CrossVul-парами через
DeepSeek-V3, без overlay/refinement (это будет v7-full, если v7-lite
покажет рост).

Anti-leakage от:
    eval_v5_inputs.json            (in-domain TEST)
    eval_crossvul_inputs.json      (OOD VAL CrossVul-300 + OOD TEST CrossVul-100)
    train_data_v5b_train.json/val  (предыдущий train)
    train_data_v6_train.json/val   (текущий train — критично!)

Output:
    train_data_v7lite_train.json
    train_data_v7lite_val.json
    deepseek_cache_v7lite.jsonl

Использование:
    python prepare_train_v7lite.py --smoke           # 5 пар, проверка пайплайна
    python prepare_train_v7lite.py --full            # 1800 новых пар (~$0.85)
    python prepare_train_v7lite.py --full --n-pairs 1200   # вручную меньше
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

for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
    os.environ.pop(k, None)
for line in open(".env", encoding="utf-8"):
    if "=" in line:
        k, v = line.strip().split("=", 1); os.environ.setdefault(k, v)

import httpx
from openai import OpenAI
from datasets import load_dataset

# --- config (идентично v6 для сопоставимости) ---

WEB_LANGUAGES = {"php", "javascript", "js", "typescript", "ts", "python", "py",
                 "java", "ruby", "go"}

TARGET_CWE = [
    "CWE-79", "CWE-89", "CWE-22", "CWE-352", "CWE-94",
    "CWE-78", "CWE-918", "CWE-434", "CWE-502", "CWE-611", "CWE-787",
    "CWE-200", "CWE-732", "CWE-264", "CWE-310",
]

# Whitelist NEW CWE классов после eyeball-проверки smoke-each-new (10:30 МСК).
# DeepSeek на этих классах генерит code-grounded и семантически корректные ответы.
NEW_CWE_WHITELIST = [
    "CWE-20",   # Improper Input Validation
    "CWE-74",   # Injection (general)
    "CWE-77",   # Command Injection
    "CWE-284",  # Improper Access Control
    "CWE-287",  # Improper Authentication
    "CWE-347",  # Improper Crypto Signature Verification
    "CWE-400",  # Uncontrolled Resource Consumption (DoS)
    "CWE-862",  # Missing Authorization
]
# BLACKLIST после eyeball: DeepSeek путает классы или генерит мусор.
# CWE-269 → описывает SQL injection (CWE-89)
# CWE-601 → не понимает URL redirect, описывает setup.py
# CWE-684 → описывает baseline bug, не security
# CWE-863 → путает с path traversal (CWE-22)

DEEPSEEK_API_KEY = "sk-7efbdd7335884862ae2801a44c4c5950"
DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEEPSEEK_MODEL = "deepseek-chat"

CACHE_PATH = Path("deepseek_cache_v7lite.jsonl")
CODE_HEAD_LEN = 256
MAX_CODE_LEN = 4000
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
        if not p.exists():
            print(f"  [warn] {p} not found, skipping anti-leakage source")
            continue
        data = json.load(open(p, encoding="utf-8"))
        n_added = 0
        for ex in data:
            md = ex.get("metadata", {})
            for k in ("vuln_code_hash", "fixed_code_hash"):
                h = md.get(k)
                if h:
                    if h not in hashes: n_added += 1
                    hashes.add(h)
            for m in ex.get("messages", []):
                if m.get("role") == "user":
                    c = m.get("content", "")
                    if "Code:" in c:
                        h = code_hash(c.split("Code:", 1)[1])
                        if h:
                            if h not in hashes: n_added += 1
                            hashes.add(h)
        print(f"  + {p.name}: {n_added} new hashes")
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
            "split_group": "v7lite_crossvul",
            "source": "crossvul",
            "file_pair_id": file_pair_id,
            "language": language,
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--smoke", action="store_true", help="5 пар, проверка пайплайна")
    ap.add_argument("--full", action="store_true", help="full run")
    ap.add_argument("--n-pairs", type=int, default=0, help="hard cap сверху (0 = без ограничения)")
    ap.add_argument("--cap-known", type=int, default=80, help="макс пар на CWE из TARGET-15 (известные)")
    ap.add_argument("--cap-new", type=int, default=200, help="макс пар на каждый НОВЫЙ CWE")
    ap.add_argument("--min-pairs", type=int, default=20, help="мин пар на CWE для включения (отрезаем шум)")
    ap.add_argument("--smoke-mix", action="store_true", help="smoke 5 пар: 2 KNOWN + 3 NEW (для проверки качества DeepSeek)")
    ap.add_argument("--smoke-each-new", action="store_true", help="smoke по 1 паре на каждый NEW CWE (eyeball quality)")
    ap.add_argument("--dry-run", action="store_true", help="посчитать пул без вызовов DeepSeek")
    args = ap.parse_args()

    target = 5 if args.smoke else args.n_pairs  # 0 = no hard cap
    random.seed(43)  # отличный seed от v6 (там был 42), чтобы получить другую выборку

    print(f"=== prepare_train_v7lite.py (target={target} new pairs, seed=43) ===")
    print("Loading hitoshura25/crossvul...")
    ds = load_dataset("hitoshura25/crossvul", token=os.environ["HF_TOKEN"])["train"]
    print(f"  total: {len(ds)}")

    web = [ex for ex in ds if (ex.get("language") or "").lower() in WEB_LANGUAGES]
    print(f"  web-languages: {len(web)}")

    # Для v7-lite: НЕ фильтруем по TARGET_CWE — берём все web-пары,
    # но cap_per_cwe применяется отдельно для known/new CWE (см. ниже).
    web_cwe = web
    print(f"  no CWE filter: {len(web_cwe)} (will apply differential cap by known/new)")

    print("\n  anti-leakage check (расширенный — включая v6 train):")
    excluded_hashes = load_existing_hashes(
        "eval_v5_inputs.json",
        "eval_crossvul_inputs.json",
        "train_data_v5b_train.json",
        "train_data_v5b_val.json",
        "train_data_v6_train.json",
        "train_data_v6_val.json",
    )
    print(f"  total excluded hashes: {len(excluded_hashes)}")

    leaked = 0
    clean = []
    for ex in web_cwe:
        if code_hash(ex["vulnerable_code"]) in excluded_hashes or \
           code_hash(ex["fixed_code"]) in excluded_hashes:
            leaked += 1
        else:
            clean.append(ex)
    print(f"  removed leaked: {leaked}, remaining clean: {len(clean)}")

    # Differential cap: known CWE (already in v6) — мало, новые — много.
    # Цель: не пересытить модель XSS, дать максимум данных по новым классам.
    KNOWN_CWE = set(TARGET_CWE)  # 15 классов которые v6 уже видела
    cap_known = args.cap_known
    cap_new = args.cap_new
    min_pairs = args.min_pairs

    by_cwe = {}
    skipped_no_cwe = 0
    for ex in clean:
        cwe = ex.get("cwe_id")
        if not cwe or cwe.strip().upper() in ("UNKNOWN", "NVD-CWE-NOINFO", "NVD-CWE-OTHER"):
            skipped_no_cwe += 1
            continue
        by_cwe.setdefault(cwe, []).append(ex)
    if skipped_no_cwe:
        print(f"  skipped pairs without valid CWE: {skipped_no_cwe}")

    sampled = []
    print(f"\n  differential sampling: cap_known={cap_known} cap_new={cap_new} min_pairs={min_pairs}")
    print(f"\n  KNOWN CWE (already in v6 train, low cap):")
    skipped_known = 0
    for cwe in sorted(by_cwe.keys()):
        if cwe not in KNOWN_CWE:
            continue
        pool = by_cwe[cwe]
        if len(pool) < min_pairs:
            print(f"    {cwe}: avail={len(pool):4d}  SKIPPED (<{min_pairs})")
            skipped_known += 1
            continue
        random.shuffle(pool)
        take = pool[:cap_known]
        sampled.extend(take)
        print(f"    {cwe}: avail={len(pool):4d}  take={len(take)}")

    print(f"\n  NEW CWE WHITELIST (8 classes after eyeball quality-check):")
    whitelist = set(NEW_CWE_WHITELIST)
    skipped_new_min = 0
    skipped_new_bl = 0
    for cwe in sorted(by_cwe.keys()):
        if cwe in KNOWN_CWE:
            continue
        if cwe not in whitelist:
            skipped_new_bl += 1
            continue
        pool = by_cwe[cwe]
        if len(pool) < min_pairs:
            print(f"    {cwe}: avail={len(pool):4d}  SKIPPED (<{min_pairs})")
            skipped_new_min += 1
            continue
        random.shuffle(pool)
        take = pool[:cap_new]
        sampled.extend(take)
        print(f"    {cwe}: avail={len(pool):4d}  take={len(take)}")
    print(f"  (skipped {skipped_new_bl} NEW CWE not in whitelist; {skipped_new_min} below min-pairs)")

    if args.smoke_mix:
        # 2 KNOWN + 3 NEW для smoke-test — выбираем CWE с большим пулом
        random.shuffle(sampled)
        known_picks = [ex for ex in sampled if ex.get("cwe_id") in KNOWN_CWE][:2]
        new_picks = [ex for ex in sampled if ex.get("cwe_id") not in KNOWN_CWE][:3]
        sampled = known_picks + new_picks
        random.shuffle(sampled)
        print(f"\n  SMOKE-MIX: {len(sampled)} pairs ({len(known_picks)} KNOWN + {len(new_picks)} NEW)")

    if args.smoke_each_new:
        # По 1 паре на каждый NEW CWE — для eyeball quality по всему spectrum
        new_cwes_in_pool = sorted({ex["cwe_id"] for ex in sampled if ex["cwe_id"] not in KNOWN_CWE})
        picks = []
        for cwe in new_cwes_in_pool:
            for ex in sampled:
                if ex["cwe_id"] == cwe:
                    picks.append(ex)
                    break
        sampled = picks
        print(f"\n  SMOKE-EACH-NEW: {len(sampled)} pairs (1 per NEW CWE: {new_cwes_in_pool})")

    random.shuffle(sampled)
    if target > 0:
        sampled = sampled[:target]
    print(f"\n  final selected: {len(sampled)} pairs")

    if args.dry_run:
        print("\n[DRY RUN] стоп: DeepSeek вызовы не выполняются.")
        return

    print(f"\n=== DeepSeek generation ({DEEPSEEK_MODEL}) ===")
    client = make_client()
    cache = load_cache()
    print(f"  cache loaded: {len(cache)} entries")

    examples = []

    def process(pair):
        try:
            pid = pair.get("file_pair_id") or f"crossvul_{id(pair)}"
            cwe = pair["cwe_id"]
            lang = pair.get("language") or ""
            v_code = pair["vulnerable_code"]
            f_code = pair["fixed_code"]
            v_content = gen_vuln_content(client, pid, cwe, v_code, f_code, cache)
            v_ex = make_train_example(v_code, lang, "vulnerable", cwe, v_content, pid)
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
            if done % 25 == 0 or done == len(sampled):
                print(f"  [{done}/{len(sampled)}]  elapsed={elapsed:.0f}s  ETA={eta:.0f}s  rate={rate:.2f}/s")

    print(f"\n  generated examples: {len(examples)}  ({len(examples)//2} unique pairs)")

    if args.smoke_mix or args.smoke_each_new:
        # Smoke output для eyeball-проверки — НЕ мерджим с train_v6
        out_path = Path("smoke_v7lite_outputs.json")
        out_path.write_text(json.dumps(examples, ensure_ascii=False, indent=2),
                             encoding="utf-8")
        print(f"\n=== SMOKE OUTPUT ({len(examples)} examples) ===")
        for ex in examples:
            md = ex["metadata"]
            label = md["label"]
            cwe = md["cwe_id"]
            content = ex["messages"][2]["content"]
            preview = content[:300].replace("\n", " | ")
            print(f"\n[{label.upper()}] {cwe} (lang={md['language']})")
            print(f"  {preview}{'...' if len(content) > 300 else ''}")
        print(f"\nSAVED: {out_path}")
        print("\nReview these by eye and decide: OK to run full prepare? Re-run без --smoke-mix.")
        return

    # Объединить с v6 train+val
    print("\n=== Merging with train_v6 ===")
    v6_train = json.load(open("train_data_v6_train.json", encoding="utf-8"))
    v6_val = json.load(open("train_data_v6_val.json", encoding="utf-8"))
    print(f"  v6 train: {len(v6_train)}, val: {len(v6_val)}")

    random.shuffle(examples)
    n_val = max(1, len(examples) // 10)
    cv_val = examples[:n_val]
    cv_train = examples[n_val:]

    final_train = v6_train + cv_train
    final_val = v6_val + cv_val
    random.shuffle(final_train)
    random.shuffle(final_val)
    print(f"  v7lite train: {len(final_train)} (={len(v6_train)}+{len(cv_train)})")
    print(f"  v7lite val:   {len(final_val)} (={len(v6_val)}+{len(cv_val)})")

    json.dump(final_train, open("train_data_v7lite_train.json", "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)
    json.dump(final_val, open("train_data_v7lite_val.json", "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)
    print("\nSAVED: train_data_v7lite_train.json, train_data_v7lite_val.json")

    cwe_dist = Counter(e["metadata"]["cwe_id"] for e in final_train
                       if e["metadata"]["label"] == "vulnerable")
    print("\nCWE distribution in v7lite train (vuln only):")
    for c, n in cwe_dist.most_common():
        print(f"  {c}: {n}")

    label_dist = Counter(e["metadata"]["label"] for e in final_train)
    print(f"\nLabel balance in train: {dict(label_dist)}")
    src_dist = Counter(e["metadata"].get("source", "cvefixes") for e in final_train)
    print(f"Source split in train: {dict(src_dist)}")


if __name__ == "__main__":
    main()
