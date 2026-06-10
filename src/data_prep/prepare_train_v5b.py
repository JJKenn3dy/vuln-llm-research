"""
prepare_train_v5.py — детектор + интерпретатор уязвимостей.

ЭТАП 1 (текущий): SKELETON БЕЗ DEEPSEEK.
- Cause / VerificationSteps / Fix / Reason заполняются placeholder'ами "PLACEHOLDER_*"
- Цель: проверить что выборка, окна кода, дедуп, стратификация работают
- Запускается на маленьком mini-датасете (24 примера: ~14 поз + ~10 нег)

После прохождения skeleton-тестов будут добавлены DeepSeek-вызовы (этап 4).

Использование:
    python prepare_train_v5.py --mini      # mini-prepare для skeleton-теста
    python prepare_train_v5.py --full      # полный прогон (после этапа 4)
"""
import argparse
import ast
import difflib
import hashlib
import json
import random
import re
from collections import Counter

random.seed(42)

# datasets импортируем лениво — только если --source hf
def load_dataset(*args, **kwargs):
    from datasets import load_dataset as _ld
    return _ld(*args, **kwargs)

# --- Конфигурация ---

WEB_CWE = [
    "CWE-79", "CWE-89", "CWE-22", "CWE-352",
    "CWE-434", "CWE-285", "CWE-306", "CWE-502",
    "CWE-918", "CWE-611", "CWE-94", "CWE-78",
    "CWE-787", "CWE-798",
]

# Caps для full-режима (positive): доли × TRAIN_SIZE_POS=1200
FULL_POSITIVE_CAPS = {
    "CWE-79":  300, "CWE-89":  144, "CWE-787": 132, "CWE-94":  132,
    "CWE-22":  120, "CWE-352":  84, "CWE-918":  72, "CWE-434":  60,
    "CWE-78":   60, "CWE-502":  36, "CWE-611":  24, "CWE-798":  24,
    "CWE-285":   6, "CWE-306":   6,
}
FULL_POSITIVE_TOTAL = sum(FULL_POSITIVE_CAPS.values())  # 1200
FULL_NEGATIVE_TOTAL = 800

# v5b: balanced 50/50 (sum=800), пропорционально v5-распределению.
# Цель — устранить дисбаланс train 72/28 → 50/50 для снижения FAR.
V5B_POSITIVE_CAPS = {
    "CWE-79":  200, "CWE-89":   96, "CWE-787":  88, "CWE-94":   88,
    "CWE-22":   80, "CWE-352":  56, "CWE-918":  48, "CWE-434":  40,
    "CWE-78":   40, "CWE-502":  24, "CWE-611":  16, "CWE-798":  16,
    "CWE-285":   4, "CWE-306":   4,
}
V5B_POSITIVE_TOTAL = sum(V5B_POSITIVE_CAPS.values())  # 800
V5B_NEGATIVE_TOTAL = 800

# Caps для mini-режима (skeleton-тест): пропорционально, но мелко
MINI_POSITIVE_CAPS = {c: max(1, FULL_POSITIVE_CAPS[c] // 100) for c in FULL_POSITIVE_CAPS}
MINI_POSITIVE_TOTAL = sum(MINI_POSITIVE_CAPS.values())  # ~14
MINI_NEGATIVE_TOTAL = 10

# --- Промпты обучения ---

SYSTEM_PROMPT_V5 = (
    "You are a secure code analysis assistant. Decide whether the given code "
    "contains a security vulnerability. If a vulnerability is present, output "
    "a structured security report. If the code is safe, state that no "
    "vulnerability was detected. Output only plain text, no markdown."
)

USER_TEMPLATE_V5 = """Analyze the following code for security vulnerabilities.

If vulnerable, output exactly these 4 fields in this exact order:
Type:
Cause:
VerificationSteps:
Fix:

If safe, output exactly:
Verdict: No vulnerability detected.
Reason: <one short sentence why>

Language/Context:
{language_hint}

Code:
{code_snippet}"""

# --- Cause-fallback (на случай отбраковки DeepSeek) ---

CAUSE_FALLBACKS = {
    "CWE-79":  "The code appears to render or return user-controlled data without an escaping step visible in the snippet.",
    "CWE-89":  "The code appears to build or execute a query without parameterization visible in the snippet.",
    "CWE-22":  "The code appears to use a path value without canonicalization or an allowlist check visible in the snippet.",
    "CWE-78":  "The code appears to pass input into a command execution sink without safe argument handling visible in the snippet.",
    "CWE-352": "The code appears to perform a state-changing action without an anti-CSRF token check visible in the snippet.",
    "CWE-918": "The code appears to issue an outbound request to a user-controlled URL without a target allowlist visible in the snippet.",
    "CWE-434": "The code appears to accept an uploaded file without a content-type or extension allowlist visible in the snippet.",
    "CWE-787": "The code appears to write to a buffer without a bounds check visible in the snippet.",
    "CWE-94":  "The code appears to evaluate or import dynamic input without a safe sandbox visible in the snippet.",
    "CWE-502": "The code appears to deserialize untrusted input without a type/class allowlist visible in the snippet.",
    "CWE-611": "The code appears to parse XML without disabling external entity resolution visible in the snippet.",
    "CWE-798": "The code appears to embed a credential literal in source rather than reading it from a secret store.",
    "DEFAULT": "The code performs a security-sensitive operation without an explicit safety check visible in the snippet.",
}

# --- Утилиты ---

def clean_text(val):
    """Из v3: распаковка строкового списка в чистый текст."""
    if isinstance(val, str) and val.strip().startswith("["):
        try:
            val = ast.literal_eval(val)
        except Exception:
            pass
    if isinstance(val, list):
        for item in val:
            if isinstance(item, dict) and item.get("lang") == "en":
                return item.get("value", "").strip()
        return str(val[0]).strip() if val else ""
    return str(val).strip() if val else ""


def normalize_code(code):
    """Нормализация для дедупа: strip + collapse пустых строк."""
    if not code:
        return ""
    return "\n".join(line.strip() for line in code.splitlines() if line.strip())


def code_hash(code):
    return hashlib.md5(normalize_code(code).encode()).hexdigest()[:12]


def dedup_key(ex):
    """5-компонентный ключ дедупликации."""
    return (
        ex.get("cve_id") or "",
        ex.get("repo") or ex.get("project") or "",
        ex.get("file_path") or ex.get("filename") or "",
        code_hash(ex.get("vulnerable_code") or ""),
        code_hash(ex.get("fixed_code") or ""),
    )


def get_cwe_id(ex):
    """Извлечь канонический CWE-ID, например 'CWE-79'."""
    cwe = (ex.get("cwe_id") or "").strip()
    if not cwe:
        return ""
    m = re.search(r"CWE-\d+", cwe)
    return m.group(0) if m else cwe


def load_eval_exclusion(path):
    """
    Загружает eval JSON и возвращает (cve_ids, hash_pairs) для anti-leakage.
    Двухуровневая защита: cve_id — главный фильтр (нечувствителен к форматированию
    кода), hash_pairs (vh, fh) — страховка для записей без cve_id или с
    суррогатом 'local-...'.
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    cve_ids = set()
    hash_pairs = set()
    for entry in data:
        m = entry.get("metadata", {})
        cid = (m.get("cve_id") or "").strip()
        vh = (m.get("vuln_code_hash") or "").strip()
        fh = (m.get("fixed_code_hash") or "").strip()
        if cid and not cid.startswith("local-"):
            cve_ids.add(cid)
        if vh and fh:
            hash_pairs.add((vh, fh))
    return cve_ids, hash_pairs


def matches_eval(ex, cve_ids, hash_pairs):
    """True если пример пересекается с eval по cve_id или (vh, fh)."""
    cid = (ex.get("cve_id") or "").strip()
    if cid and cid in cve_ids:
        return True
    vh = code_hash(ex.get("vulnerable_code") or "")
    fh = code_hash(ex.get("fixed_code") or "")
    if vh and fh and (vh, fh) in hash_pairs:
        return True
    return False


def parse_v4_local(path="f:/diplom/train_data_v4.json"):
    """
    Парсит train_data_v4.json и возвращает список dict'ов в формате CVEfixes:
    {cve_id, cwe_id, cwe_name, cve_description, vulnerable_code, fixed_code}.
    User-сообщение в v4 имеет структурированный формат с этими полями.
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    parsed = []
    for entry in data:
        user = entry["messages"][1]["content"]

        def grab(label, until=None):
            if until:
                pat = rf"{label}:\s*\n(.+?)\n(?:{until}:|\Z)"
            else:
                pat = rf"{label}:\s*\n(.+?)(?:\n[A-Z][a-zA-Z ]+:|\Z)"
            m = re.search(pat, user, re.DOTALL)
            return m.group(1).strip() if m else ""

        cve_desc = grab("CVE Description", "CWE ID")
        cwe_id   = grab("CWE ID", "CWE Name").strip()
        cwe_name = grab("CWE Name", "CWE Description").strip()
        vuln_code = grab("Vulnerable Code", "Fixed Code")
        fixed_code = grab("Fixed Code")

        # cve_id — извлечём из cve_description если есть
        m = re.search(r"CVE-\d{4}-\d+", cve_desc)
        cve_id = m.group(0) if m else f"local-{hashlib.md5(vuln_code.encode()).hexdigest()[:8]}"

        if vuln_code and fixed_code and cwe_id:
            parsed.append({
                "cve_id": cve_id,
                "cwe_id": cwe_id,
                "cwe_name": cwe_name,
                "cve_description": cve_desc,
                "vulnerable_code": vuln_code,
                "fixed_code": fixed_code,
                "repo": "",
                "file_path": "",
            })
    return parsed


def is_valid(ex, allow_non_web=False):
    has_fields = all([
        ex.get("cve_description"),
        ex.get("cwe_name"),
        ex.get("vulnerable_code"),
        ex.get("fixed_code"),
    ])
    if not has_fields:
        return False
    if allow_non_web:
        return True
    cwe = ex.get("cwe_id", "") or ""
    return any(c in cwe for c in WEB_CWE)


def language_hint(code, file_path=None):
    """
    Только по расширению/синтаксису. БЕЗ CWE — это была бы утечка метки.
    """
    if file_path:
        ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
        ext_map = {
            "c": "C", "h": "C", "cpp": "C++", "cc": "C++", "hpp": "C++", "cxx": "C++",
            "py": "Python", "php": "PHP", "js": "JavaScript", "ts": "TypeScript",
            "jsx": "JavaScript", "tsx": "TypeScript",
            "java": "Java", "rb": "Ruby", "go": "Go", "rs": "Rust",
            "html": "HTML", "vue": "JavaScript",
        }
        if ext in ext_map:
            return ext_map[ext]
    code = code or ""
    if "<?php" in code:
        return "PHP"
    if re.search(r"^\s*(def|import|from)\s", code, re.MULTILINE) and ":" in code:
        return "Python"
    if "#include" in code:
        return "C/C++"
    if re.search(r"\bfunction\s+\w+\s*\(", code) or "=>" in code or "var " in code:
        return "JavaScript"
    if re.search(r"\bpublic\s+(static\s+)?(class|void)", code):
        return "Java"
    if re.search(r"^\s*(package|import)\s+\w+", code, re.MULTILINE) and "func " in code:
        return "Go"
    return "Generic"


def select_code_window(vulnerable_code, fixed_code, target="vuln", max_chars=2000):
    """
    Возвращает окно вокруг изменённых строк diff.
    target='vuln'  → окно из vulnerable_code вокруг удалённых строк (для позитивов)
    target='fixed' → окно из fixed_code вокруг добавленных строк (для негативов)
    """
    vuln_lines = (vulnerable_code or "").splitlines()
    fixed_lines = (fixed_code or "").splitlines()
    diff = list(difflib.unified_diff(vuln_lines, fixed_lines, lineterm="", n=0))

    if target == "vuln":
        source_lines = vuln_lines
        marker = "-"
        hunk_re = re.compile(r"^@@ -(\d+)")
    elif target == "fixed":
        source_lines = fixed_lines
        marker = "+"
        hunk_re = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)")
    else:
        raise ValueError(f"target must be 'vuln' or 'fixed', got {target!r}")

    changed = []
    cur = 0
    for line in diff:
        m = hunk_re.match(line)
        if m:
            cur = int(m.group(1)) - 1
            continue
        if line.startswith(marker) and not line.startswith(marker * 3):
            changed.append(cur)
            cur += 1
        elif line.startswith(" "):
            cur += 1

    if not changed or not source_lines:
        return ("\n".join(source_lines))[:max_chars]

    center = changed[len(changed) // 2]
    half = 30
    lo = max(0, center - half)
    hi = min(len(source_lines), center + half)
    window = "\n".join(source_lines[lo:hi])
    return window[:max_chars] if len(window) > max_chars else window


def stratified_sample(examples, caps):
    """Стратифицированная выборка по CWE с ограничением caps[cwe]."""
    bucket = {c: [] for c in caps}
    pool = list(examples)
    random.shuffle(pool)
    used_keys = set()
    for ex in pool:
        cwe = get_cwe_id(ex)
        if cwe not in caps:
            continue
        key = dedup_key(ex)
        if key in used_keys:
            continue
        if len(bucket[cwe]) >= caps[cwe]:
            continue
        bucket[cwe].append(ex)
        used_keys.add(key)
    selected = [ex for v in bucket.values() for ex in v]
    return selected, used_keys


# --- Постфильтры ---

VERSION_RE = re.compile(r"\d+\.\d+\.\d+")
URL_RE = re.compile(r"https?://")
CVE_RE = re.compile(r"CVE-\d{4}-\d+")
HTML_TAG_RE = re.compile(r"<[a-zA-Z/]")
MARKDOWN_RE = re.compile(r"```|\*\*")

BAD_REASON_PATTERNS = [
    re.compile(r"\bCWE-\d+\b"),
    re.compile(r"\bCVE-\d{4}-\d+\b"),
    re.compile(r"\bXSS\b"),
    re.compile(r"\bCSRF\b"),
    re.compile(r"\bXXE\b"),
    re.compile(r"\bSSRF\b"),
    re.compile(r"\bSQL\s+injection\b", re.IGNORECASE),
    re.compile(r"\bcommand\s+injection\b", re.IGNORECASE),
    re.compile(r"\bcode\s+injection\b", re.IGNORECASE),
    re.compile(r"\bpath\s+traversal\b", re.IGNORECASE),
    re.compile(r"\bbuffer\s+overflow\b", re.IGNORECASE),
    re.compile(r"\bdeserialization\s+vulnerability\b", re.IGNORECASE),
]


def cause_is_clean(text):
    if not text:
        return False
    if HTML_TAG_RE.search(text):
        return False
    if VERSION_RE.search(text):
        return False
    if URL_RE.search(text):
        return False
    if CVE_RE.search(text):
        return False
    if MARKDOWN_RE.search(text):
        return False
    return True


def fix_is_clean(text):
    if not text:
        return False
    if HTML_TAG_RE.search(text):
        return False
    if VERSION_RE.search(text):
        return False
    if URL_RE.search(text):
        return False
    if CVE_RE.search(text):
        return False
    if MARKDOWN_RE.search(text):
        return False
    return True


def reason_is_clean(text):
    """Reason применяет ТОЛЬКО к содержимому Reason-поля, НЕ ко всему assistant."""
    if not text:
        return False
    for p in BAD_REASON_PATTERNS:
        if p.search(text):
            return False
    if MARKDOWN_RE.search(text):
        return False
    return True


# --- Сборка entry ---

SAFE_VERDICT_LINE = "Verdict: No vulnerability detected."


def build_positive_entry(ex, cause, verif_steps, fix_text):
    code_window = select_code_window(
        ex.get("vulnerable_code"),
        ex.get("fixed_code"),
        target="vuln",
    )
    user_msg = USER_TEMPLATE_V5.format(
        language_hint=language_hint(code_window, ex.get("file_path")),
        code_snippet=code_window,
    )
    cwe_id = get_cwe_id(ex)
    cwe_name = ex.get("cwe_name") or "Unknown vulnerability"
    type_line = f"{cwe_id} - {cwe_name}" if cwe_id else cwe_name
    answer = (
        f"Type: {type_line}\n"
        f"Cause: {cause}\n"
        f"VerificationSteps: {verif_steps}\n"
        f"Fix: {fix_text}"
    )
    return {
        "messages": [
            {"role": "system",    "content": SYSTEM_PROMPT_V5},
            {"role": "user",      "content": user_msg},
            {"role": "assistant", "content": answer},
        ],
        "metadata": {
            "label": "vulnerable",
            "cve_id": ex.get("cve_id") or "",
            "cwe_id": cwe_id,
            "repo": ex.get("repo") or ex.get("project") or "",
            "file_path": ex.get("file_path") or ex.get("filename") or "",
            "vuln_code_hash": code_hash(ex.get("vulnerable_code") or ""),
            "fixed_code_hash": code_hash(ex.get("fixed_code") or ""),
            "split_group": "",  # заполняется при split
        },
    }


def build_negative_entry(ex, reason):
    code_window = select_code_window(
        ex.get("vulnerable_code"),
        ex.get("fixed_code"),
        target="fixed",
    )
    user_msg = USER_TEMPLATE_V5.format(
        language_hint=language_hint(code_window, ex.get("file_path")),
        code_snippet=code_window,
    )
    answer = f"{SAFE_VERDICT_LINE}\nReason: {reason}"
    return {
        "messages": [
            {"role": "system",    "content": SYSTEM_PROMPT_V5},
            {"role": "user",      "content": user_msg},
            {"role": "assistant", "content": answer},
        ],
        "metadata": {
            "label": "safe",
            "cve_id": ex.get("cve_id") or "",
            "cwe_id": get_cwe_id(ex),  # для аналитики, в input не попадает
            "repo": ex.get("repo") or ex.get("project") or "",
            "file_path": ex.get("file_path") or ex.get("filename") or "",
            "vuln_code_hash": code_hash(ex.get("vulnerable_code") or ""),
            "fixed_code_hash": code_hash(ex.get("fixed_code") or ""),
            "split_group": "",
        },
    }


def cleanup_outliers(entries):
    out = []
    for e in entries:
        a = e["messages"][2]["content"]
        if len(a) > 5000:
            continue
        out.append(e)
    return out


# --- DeepSeek-заглушки (этап 1, --mini) ---

def placeholder_cause(ex):
    cwe = get_cwe_id(ex)
    return f"PLACEHOLDER_CAUSE for {cwe}"


def placeholder_verif(ex):
    return "PLACEHOLDER_VERIFICATION_STEPS"


def placeholder_fix(ex):
    return "PLACEHOLDER_FIX"


def placeholder_reason(ex):
    return "PLACEHOLDER_REASON: visible mitigation pattern"


# --- DeepSeek API + JSONL resume cache (этапы 2-4) ---

DEEPSEEK_API_KEY = "sk-7efbdd7335884862ae2801a44c4c5950"
DEEPSEEK_BASE_URL = "https://api.deepseek.com"
# "deepseek-chat" → alias на v4-flash в NON-thinking режиме (что нам нужно).
# Прямой "deepseek-v4-flash" по умолчанию thinking — он тратит весь max_tokens на reasoning
# и возвращает пустые ответы (finish_reason=length).
# Alias deprecation 2026-07-24, к тому моменту нужно мигрировать на явный non-thinking endpoint.
DEEPSEEK_MODEL = "deepseek-chat"

CACHE_PATH = "f:/diplom/deepseek_cache_v5.jsonl"

import threading
_cache_lock = threading.Lock()


def get_client():
    """
    OpenAI клиент с явным httpx — обходит ALL_PROXY=socks5h (httpx его не понимает),
    использует HTTPS_PROXY/HTTP_PROXY если они есть, иначе напрямую.
    """
    import os as _os
    from openai import OpenAI
    import httpx
    https_proxy = _os.environ.get("HTTPS_PROXY") or _os.environ.get("HTTP_PROXY")
    if https_proxy and not https_proxy.startswith("socks"):
        http_client = httpx.Client(proxies=https_proxy, trust_env=False, timeout=120.0)
    else:
        http_client = httpx.Client(trust_env=False, timeout=120.0)
    return OpenAI(api_key=DEEPSEEK_API_KEY, base_url=DEEPSEEK_BASE_URL, http_client=http_client)


def cache_id(ex, field):
    """Уникальный ID для resume cache. Включает code-hash чтобы разные сниппеты не сливались."""
    vh = code_hash(ex.get("vulnerable_code") or "")
    fh = code_hash(ex.get("fixed_code") or "")
    return f"{ex.get('cve_id', 'NA')}:{vh}:{fh}:{field}"


def load_cache(path=CACHE_PATH):
    cache = {}
    if not __import__("os").path.exists(path):
        return cache
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                cache[rec["id"]] = rec
            except Exception:
                continue
    return cache


def append_cache(rec, path=CACHE_PATH):
    """Thread-safe append для concurrent генерации."""
    line = json.dumps(rec, ensure_ascii=False) + "\n"
    with _cache_lock:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()


# --- Промпты DeepSeek ---

CAUSE_SYSTEM = (
    "You are an application security expert. Write a code-grounded Cause "
    "explanation. Use ONLY facts visible in the provided code. Reference exact "
    "function, variable, sink, source, or missing check. Do NOT mention product "
    "names, library names, version numbers, affected components, or any external "
    "CVE-only facts. Plain text, 1-2 sentences, max 300 chars."
)

CAUSE_USER_TEMPLATE = """Vulnerability class (CWE): {cwe_id} — {cwe_name}

Vulnerable code:
{code_window}

Write a Cause that:
- references the exact variable/function/parameter visible in the code
- names the vulnerable sink and untrusted source if applicable
- describes the missing check or unsafe operation in code terms
- avoids any product name, version, or external context not in code"""


VERIF_SYSTEM = (
    "You are an application security expert. Write precise, code-specific "
    "verification steps for the given vulnerability. Reference the exact "
    "function, variable, or parameter you see in the code. Do NOT write "
    "generic advice. Plain text only, no markdown, no bullet symbols."
)

VERIF_USER_TEMPLATE = """Vulnerability type: {cwe_id} — {cwe_name}

Vulnerable code snippet:
{code_window}

Write 2-3 verification steps specific to THIS code above.
Each step must reference the exact variable/function/parameter visible in the code.
Provide a concrete payload or test action.
Describe what to observe as proof of exploitation."""


FIX_SYSTEM = (
    "You are an application security expert. Write a single concrete Fix "
    "recommendation for the given vulnerability. Reference exact functions, "
    "variables or parameters visible in the code. No HTML, no markdown, no "
    "version strings, no URLs. Plain text, 1-3 sentences, max 400 chars."
)

FIX_USER_TEMPLATE = """Vulnerability type: {cwe_id} — {cwe_name}

Vulnerable code:
{vuln_window}

Reference fixed code (hint only, do NOT copy verbatim):
{fixed_window}

Write a Fix that names the exact variable/function and describes the API
or technique to use. Avoid vague phrases like "validate input"."""


REASON_SYSTEM = (
    "You are a code-review assistant. The given code is a post-fix snippet. "
    "Describe the visible mitigation pattern (parameterized query, escape, "
    "validation, allowlist, etc.) referencing the exact API/variable/check in "
    "the code. Do NOT mention any vulnerability class name (CWE-XX, 'XSS', "
    "'SQL injection', 'CSRF', etc.). Do NOT claim the code is safe in general. "
    "No markdown, max 200 chars."
)

REASON_USER_TEMPLATE = """Internal context (do NOT mention in output): code was patched against {cwe_id} — {cwe_name}.

Code snippet (post-fix):
{code_window}

Output exactly one line describing the visible mitigation, in this style:
- "The query uses parameterized execution via cursor.execute(sql, (user_id,))."
- "The path is canonicalized via os.path.realpath() and checked against an allowlist."
- "The output is escaped via html.escape(name) before being rendered."
- "The XML parser disables external entity resolution."
"""


# --- Generator core: retry + cache + fallback ---

def _call_deepseek(client, system_msg, user_msg, max_tokens, temperature=0.2, retries=2):
    last_err = None
    for attempt in range(retries + 1):
        try:
            resp = client.chat.completions.create(
                model=DEEPSEEK_MODEL,
                messages=[
                    {"role": "system", "content": system_msg},
                    {"role": "user",   "content": user_msg},
                ],
                max_tokens=max_tokens,
                temperature=temperature,
            )
            choice = resp.choices[0]
            text = choice.message.content or ""
            text = text.strip()
            # Возвращаем кортеж (text, finish_reason) — каллер сам решит как обработать пустоту
            return text, getattr(choice, "finish_reason", None)
        except Exception as e:
            last_err = e
            time.sleep(1.0 * (attempt + 1))
    raise last_err


def get_or_generate(cache, ex, field, builder, filter_fn, fallback_fn, client,
                    max_tokens, system_msg=None):
    """
    cache: dict id->record (loaded from JSONL)
    ex: dataset example
    field: 'cause' | 'verif' | 'fix' | 'reason'
    builder: ex -> user_msg (or returns None to skip)
    filter_fn: text -> bool (postfilter; True = pass)
    fallback_fn: ex -> str (used on filter fail / API fail)
    """
    cid = cache_id(ex, field)
    if cid in cache and cache[cid].get("status") == "ok":
        return cache[cid]["text"]

    user_msg = builder(ex)
    if user_msg is None:
        text = fallback_fn(ex)
        rec = {"id": cid, "status": "skipped", "field": field, "text": text}
        append_cache(rec)
        cache[cid] = rec
        return text

    raw_response = None
    finish_reason = None
    error_msg = None
    try:
        raw_response, finish_reason = _call_deepseek(client, system_msg, user_msg, max_tokens=max_tokens)
        if not raw_response:
            text = fallback_fn(ex)
            status = "empty"
        elif filter_fn(raw_response):
            text = raw_response
            status = "ok"
        else:
            text = fallback_fn(ex)
            status = "filtered"
    except Exception as e:
        error_msg = str(e)
        text = fallback_fn(ex)
        status = "failed"

    rec = {"id": cid, "status": status, "field": field, "text": text,
           "raw": raw_response, "finish_reason": finish_reason, "error": error_msg,
           "cwe_id": get_cwe_id(ex), "cve_id": ex.get("cve_id", "")}
    append_cache(rec)
    cache[cid] = rec
    return text


# --- Builders + fallbacks per-field ---

def build_cause_user(ex):
    code_window = select_code_window(
        ex.get("vulnerable_code"), ex.get("fixed_code"), target="vuln"
    )
    if not code_window.strip():
        return None
    return CAUSE_USER_TEMPLATE.format(
        cwe_id=get_cwe_id(ex) or "Unknown",
        cwe_name=ex.get("cwe_name") or "",
        code_window=code_window,
    )


def cause_fallback(ex):
    cwe = get_cwe_id(ex)
    return CAUSE_FALLBACKS.get(cwe, CAUSE_FALLBACKS["DEFAULT"])


def build_verif_user(ex):
    code_window = select_code_window(
        ex.get("vulnerable_code"), ex.get("fixed_code"), target="vuln"
    )
    if not code_window.strip():
        return None
    return VERIF_USER_TEMPLATE.format(
        cwe_id=get_cwe_id(ex) or "Unknown",
        cwe_name=ex.get("cwe_name") or "",
        code_window=code_window,
    )


def verif_filter(text):
    if not text:
        return False
    if MARKDOWN_RE.search(text):
        return False
    if VERSION_RE.search(text):
        return False
    # HTML в VerificationSteps РАЗРЕШЁН (XSS payload <script>...</script>)
    return True


def verif_fallback(ex):
    cwe = get_cwe_id(ex) or "Unknown"
    return f"Review the code for {cwe} patterns and test with appropriate security payloads targeting the visible sinks."


def build_fix_user(ex):
    vuln_window = select_code_window(
        ex.get("vulnerable_code"), ex.get("fixed_code"), target="vuln"
    )
    fixed_window = select_code_window(
        ex.get("vulnerable_code"), ex.get("fixed_code"), target="fixed"
    )
    if not vuln_window.strip():
        return None
    return FIX_USER_TEMPLATE.format(
        cwe_id=get_cwe_id(ex) or "Unknown",
        cwe_name=ex.get("cwe_name") or "",
        vuln_window=vuln_window,
        fixed_window=fixed_window,
    )


def fix_fallback(ex):
    """Используем v3 difflib — он возвращает Fix-стиль текст (НЕ Cause)."""
    return _extract_fix_from_diff(ex.get("vulnerable_code"), ex.get("fixed_code"))


def _extract_fix_from_diff(vuln_code, fixed_code):
    """Из v3 (с минимальной чисткой)."""
    vuln_lines = (vuln_code or "").splitlines()
    fixed_lines = (fixed_code or "").splitlines()
    diff = list(difflib.unified_diff(vuln_lines, fixed_lines, lineterm=""))
    removed, added = [], []
    for line in diff:
        if line.startswith(("---", "+++", "@@")):
            continue
        content = line[1:].strip()
        if not content:
            continue
        if line.startswith("-"):
            removed.append(content)
        elif line.startswith("+"):
            added.append(content)
    parts = []
    if removed:
        parts.append(f"Remove or replace: {'; '.join(removed[:2])}")
    if added:
        parts.append(f"Add or update: {'; '.join(added[:2])}")
    text = (" ".join(parts) + ".") if parts else \
        "Apply the changes shown in the fixed code to remediate the vulnerability."
    # Если внутри HTML/version — заменяем на CWE-fallback
    if HTML_TAG_RE.search(text) or VERSION_RE.search(text):
        return "Apply the security check shown in the fixed code: validate the untrusted input and use the safe API for the operation."
    return text


def build_reason_user(ex):
    code_window = select_code_window(
        ex.get("vulnerable_code"), ex.get("fixed_code"), target="fixed"
    )
    if not code_window.strip():
        return None
    return REASON_USER_TEMPLATE.format(
        cwe_id=get_cwe_id(ex) or "Unknown",
        cwe_name=ex.get("cwe_name") or "",
        code_window=code_window,
    )


def reason_fallback(ex):
    """
    Generic fallback БЕЗ упоминания cwe_name — иначе попадает SQL Injection / XSS / etc.
    в текст и нарушает правило "Reason не должен называть класс уязвимости".
    """
    return "The post-fix snippet contains an explicit safety check or sanitization step on the relevant data path; no concrete evidence of an unsafe operation is visible in this snippet."


# --- High-level: DeepSeek pipeline для одного example ---

def deepseek_positive(cache, ex, client):
    cause = get_or_generate(
        cache, ex, "cause",
        builder=build_cause_user,
        filter_fn=cause_is_clean,
        fallback_fn=cause_fallback,
        client=client,
        max_tokens=180,
        system_msg=CAUSE_SYSTEM,
    )
    verif = get_or_generate(
        cache, ex, "verif",
        builder=build_verif_user,
        filter_fn=verif_filter,
        fallback_fn=verif_fallback,
        client=client,
        max_tokens=280,
        system_msg=VERIF_SYSTEM,
    )
    fix = get_or_generate(
        cache, ex, "fix",
        builder=build_fix_user,
        filter_fn=fix_is_clean,
        fallback_fn=fix_fallback,
        client=client,
        max_tokens=200,
        system_msg=FIX_SYSTEM,
    )
    return cause, verif, fix


def deepseek_negative(cache, ex, client):
    return get_or_generate(
        cache, ex, "reason",
        builder=build_reason_user,
        filter_fn=reason_is_clean,
        fallback_fn=reason_fallback,
        client=client,
        max_tokens=100,
        system_msg=REASON_SYSTEM,
    )


# --- Concurrent runner ---

import time
from concurrent.futures import ThreadPoolExecutor, as_completed


def run_concurrent(items, worker, concurrency=10, label=""):
    """
    items:    список входов
    worker:   callable(item) -> result, безопасный для thread-pool
    Возвращает list of results в исходном порядке.
    """
    results = [None] * len(items)
    done_count = [0]
    t0 = time.time()
    print(f"  [{label}] running {len(items)} tasks with concurrency={concurrency}")

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {pool.submit(worker, item): i for i, item in enumerate(items)}
        for fut in as_completed(futures):
            i = futures[fut]
            try:
                results[i] = fut.result()
            except Exception as e:
                print(f"  [{label}] task #{i} failed: {e}")
                results[i] = None
            done_count[0] += 1
            if done_count[0] % 50 == 0 or done_count[0] == len(items):
                elapsed = time.time() - t0
                rate = done_count[0] / elapsed if elapsed > 0 else 0
                eta = (len(items) - done_count[0]) / rate if rate > 0 else 0
                print(f"  [{label}] {done_count[0]}/{len(items)} done, {rate:.1f}/s, ETA {eta:.0f}s")
    return results


# --- Smoke-тесты для skeleton ---

def smoke_test_window():
    """Проверка: select_code_window для target='vuln' и 'fixed' даёт разные результаты."""
    vuln = "\n".join([f"line_{i}_VULN" for i in range(50)])
    fixed = "\n".join([f"line_{i}_VULN" if i != 25 else "line_25_FIXED" for i in range(50)])

    win_v = select_code_window(vuln, fixed, target="vuln")
    win_f = select_code_window(vuln, fixed, target="fixed")

    assert "line_25_VULN" in win_v, f"vuln window must contain line_25_VULN, got: {win_v[:200]}"
    assert "line_25_FIXED" in win_f, f"fixed window must contain line_25_FIXED, got: {win_f[:200]}"
    assert "line_25_VULN" not in win_f, "fixed window must NOT contain VULN line"
    assert "line_25_FIXED" not in win_v, "vuln window must NOT contain FIXED line"
    print("[smoke] select_code_window OK (vuln/fixed targets work)")


def smoke_test_dedup():
    """Проверка: код с trailing whitespace и пустыми строками дедупится; разный код — нет."""
    # ex1 и ex2 одинаковы по содержанию, отличаются trailing whitespace и пустыми строками
    ex1 = {
        "cve_id": "CVE-1",
        "vulnerable_code": "if x==1: pass\nfoo()",
        "fixed_code": "if x==2: pass\nfoo()",
    }
    ex2 = {
        "cve_id": "CVE-1",
        "vulnerable_code": "if x==1: pass   \n\n\nfoo()  \n",
        "fixed_code": "if x==2: pass   \n\nfoo()  \n",
    }
    assert dedup_key(ex1) == dedup_key(ex2), "trailing whitespace + empty lines should dedup"

    # Внутренние пробелы — это разный код, НЕ должны дедупиться
    ex3 = {"cve_id": "CVE-1", "vulnerable_code": "if x == 1: pass", "fixed_code": "x"}
    ex4 = {"cve_id": "CVE-1", "vulnerable_code": "if x==1: pass", "fixed_code": "x"}
    assert dedup_key(ex3) != dedup_key(ex4), "internal-whitespace differences must NOT dedup"

    # Разные cve_id — разные ключи
    ex5 = {"cve_id": "CVE-2", "vulnerable_code": "if x==1: pass\nfoo()", "fixed_code": "if x==2: pass\nfoo()"}
    assert dedup_key(ex1) != dedup_key(ex5), "different cve_id must not dedup"
    print("[smoke] dedup_key OK (trailing/empty insensitive, internal-whitespace sensitive)")


def smoke_test_language_hint():
    """language_hint НЕ должен зависеть от CWE."""
    php_code = "<?php echo $_GET['x']; ?>"
    py_code = "import os\ndef foo(x):\n    return os.system(x)"
    c_code = "#include <stdio.h>\nint main() { return 0; }"
    js_code = "function foo(x) { return x + 1; }"

    assert language_hint(php_code) == "PHP"
    assert language_hint(py_code) == "Python"
    assert language_hint(c_code) == "C/C++"
    assert language_hint(js_code) == "JavaScript"
    # критическое: пустой код не падает и возвращает Generic
    assert language_hint("") == "Generic"
    print("[smoke] language_hint OK (no CWE leakage)")


def smoke_test_filters():
    """Проверка постфильтров."""
    assert cause_is_clean("Query passes user input directly to cursor.execute without parameterization.")
    assert not cause_is_clean("Apache HTTP Server 2.4.10 is vulnerable.")
    assert not cause_is_clean("See https://example.com/cve")
    assert not cause_is_clean("Affects CVE-2023-12345.")
    assert not cause_is_clean("```python\ncode\n```")

    # CamelCase класс должен ПРОЙТИ (HtmlRenderer и подобное — это легитимно)
    assert cause_is_clean("HtmlRenderer.render() does not escape the input parameter.")

    # Reason — НЕ должен содержать названия классов уязвимостей
    assert reason_is_clean("Query uses parameterized cursor.execute(sql, (user_id,)).")
    assert not reason_is_clean("No concrete evidence of CWE-89 in this snippet.")
    assert not reason_is_clean("The code is protected against SQL injection.")
    # но "sql" как часть имени переменной — ок
    assert reason_is_clean("The sql_query variable is bound via prepared statement.")
    print("[smoke] cause/fix/reason filters OK")


def smoke_test_full_assistant_passes():
    """Критично: полный assistant-ответ для негатива не должен сам себя забанить."""
    full_neg = "Verdict: No vulnerability detected.\nReason: Query uses parameterized cursor.execute(sql, (user_id,))."
    # reason_is_clean применяется ТОЛЬКО к Reason-полю, не ко всему ответу.
    # Извлекаем Reason:
    m = re.search(r"^Reason:\s*(.+)$", full_neg, re.MULTILINE)
    assert m, "Reason field must be parseable"
    reason_text = m.group(1).strip()
    assert reason_is_clean(reason_text), f"reason should pass filter: {reason_text}"
    print("[smoke] negative assistant survives Reason filter")


def run_all_smoke_tests():
    print("=== SKELETON SMOKE TESTS ===")
    smoke_test_window()
    smoke_test_dedup()
    smoke_test_language_hint()
    smoke_test_filters()
    smoke_test_full_assistant_passes()
    print("=== ALL SMOKE TESTS PASSED ===\n")


# --- Main ---

def assign_split(entries, val_ratio=0.1, seed=42):
    rnd = random.Random(seed)
    shuffled = list(entries)
    rnd.shuffle(shuffled)
    n_val = max(1, int(len(shuffled) * val_ratio))
    val = shuffled[:n_val]
    train = shuffled[n_val:]
    for e in train:
        e["metadata"]["split_group"] = "train"
    for e in val:
        e["metadata"]["split_group"] = "val"
    return train, val


def report_distribution(entries, label=""):
    by_label = Counter(e["metadata"]["label"] for e in entries)
    by_cwe_pos = Counter(
        e["metadata"]["cwe_id"] for e in entries if e["metadata"]["label"] == "vulnerable"
    )
    by_lang = Counter()
    for e in entries:
        user = e["messages"][1]["content"]
        m = re.search(r"Language/Context:\s*\n(.+)", user)
        if m:
            by_lang[m.group(1).strip()] += 1
    print(f"\n--- Distribution: {label} (n={len(entries)}) ---")
    print(f"label split: {dict(by_label)}")
    print(f"CWE in positives: {dict(by_cwe_pos.most_common())}")
    print(f"language_hint: {dict(by_lang.most_common())}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mini",  action="store_true", help="Skeleton (etap 1): placeholders, no DeepSeek")
    parser.add_argument("--smoke", action="store_true", help="Smoke (etap 2): 5 pos + 5 neg via DeepSeek")
    parser.add_argument("--full",  action="store_true", help="Full (etap 4): 1200 pos + 800 neg via DeepSeek")
    parser.add_argument("--out-prefix", default=None, help="Output file prefix")
    parser.add_argument("--concurrency", type=int, default=10, help="Parallel DeepSeek requests (default 10)")
    parser.add_argument("--source", choices=["v4_local", "hf"], default="v4_local",
                        help="v4_local: parse f:/diplom/train_data_v4.json (no HF needed); hf: load from HuggingFace")
    parser.add_argument("--balanced", action="store_true",
                        help="v5b: use balanced 50/50 caps (800 pos + 800 neg). Requires --full.")
    parser.add_argument("--exclude-eval", default=None,
                        help="Path to eval JSON to exclude from training pool (anti-leakage).")
    args = parser.parse_args()
    concurrency = args.concurrency

    modes = sum([args.mini, args.smoke, args.full])
    if modes != 1:
        print("Specify exactly one of --mini, --smoke, --full")
        return
    if args.balanced and not args.full:
        print("--balanced requires --full")
        return

    if args.mini:
        out_prefix = args.out_prefix or "train_data_v5_mini"
        pos_caps = MINI_POSITIVE_CAPS
        pos_total = MINI_POSITIVE_TOTAL
        neg_total = MINI_NEGATIVE_TOTAL
        use_deepseek = False
    elif args.smoke:
        out_prefix = args.out_prefix or "train_data_v5_smoke"
        # Caps на 5 позитивов: берём по 1 примеру топ-5 CWE
        pos_caps = {"CWE-79": 1, "CWE-89": 1, "CWE-22": 1, "CWE-787": 1, "CWE-94": 1}
        pos_total = 5
        neg_total = 5
        use_deepseek = True
    else:  # full — на v4_local источнике 1000 примеров → 600/400
        out_prefix = args.out_prefix or "train_data_v5"
        if args.balanced:
            # v5b: balanced 50/50 на полном HF-CVEfixes (800 pos + 800 neg).
            pos_caps = V5B_POSITIVE_CAPS
            pos_total = V5B_POSITIVE_TOTAL
            neg_total = V5B_NEGATIVE_TOTAL
        elif args.source == "v4_local":
            # 600 pos + 400 neg, балансировка на доступном объёме
            pos_caps = {"CWE-79": 150, "CWE-89": 72, "CWE-787": 66, "CWE-94": 66,
                        "CWE-22": 60, "CWE-352": 42, "CWE-918": 36, "CWE-434": 30,
                        "CWE-78": 30, "CWE-502": 18, "CWE-611": 12, "CWE-798": 12,
                        "CWE-285": 3, "CWE-306": 3}
            pos_total = sum(pos_caps.values())  # 600
            neg_total = 400
        else:
            pos_caps = FULL_POSITIVE_CAPS
            pos_total = FULL_POSITIVE_TOTAL
            neg_total = FULL_NEGATIVE_TOTAL
        use_deepseek = True

    # 1. Smoke-тесты
    run_all_smoke_tests()

    # 2. Загрузка датасета
    if args.source == "v4_local":
        print("Loading from local train_data_v4.json (parsed back to CVEfixes-like dicts)...")
        ds = parse_v4_local()
        print(f"Total parsed examples: {len(ds)}")
        if ds:
            print(f"Sample fields: {sorted(ds[0].keys())}")
    else:
        print("Loading hitoshura25/cvefixes from HuggingFace...")
        ds = load_dataset("hitoshura25/cvefixes", split="train")
        print(f"Total examples: {len(ds)}")
        if len(ds) > 0:
            print(f"Sample fields: {sorted(ds[0].keys())}")

    # 3. Фильтр + дедуп
    print("\nFiltering and deduplicating...")
    seen = set()
    filtered = []
    for ex in ds:
        if not is_valid(ex):
            continue
        k = dedup_key(ex)
        if k in seen:
            continue
        seen.add(k)
        filtered.append(ex)
    print(f"After is_valid + dedup: {len(filtered)}")

    # 3b. Anti-leakage: исключение примеров, пересекающихся с eval-сетом.
    if args.exclude_eval:
        eval_cve_ids, eval_hash_pairs = load_eval_exclusion(args.exclude_eval)
        print(f"\nLoaded eval exclusion from {args.exclude_eval}: "
              f"{len(eval_cve_ids)} cve_ids, {len(eval_hash_pairs)} hash pairs")
        before = len(filtered)
        filtered = [ex for ex in filtered if not matches_eval(ex, eval_cve_ids, eval_hash_pairs)]
        print(f"Excluded {before - len(filtered)} examples overlapping with eval. Remaining: {len(filtered)}")

    # 4. Стратифицированная выборка позитивов
    print(f"\nSampling positives (caps={pos_caps}, total target={pos_total})...")
    positives, pos_keys = stratified_sample(filtered, pos_caps)
    print(f"Selected positives: {len(positives)}")

    # 5. Негативы — из остатка (ключи не пересекаются)
    neg_pool = [ex for ex in filtered if dedup_key(ex) not in pos_keys]
    print(f"Negative pool (after exclude positives): {len(neg_pool)}")

    # Стратифицируем негативы по тому же распределению CWE (пропорционально)
    neg_caps = {c: max(1, pos_caps[c] * neg_total // pos_total) for c in pos_caps}
    negatives, _ = stratified_sample(neg_pool, neg_caps)
    print(f"Selected negatives: {len(negatives)}")

    # 6. Сборка entries — placeholders или DeepSeek
    if use_deepseek:
        total_requests = len(positives) * 3 + len(negatives)
        print(f"\nDeepSeek generation: {total_requests} requests via {DEEPSEEK_MODEL}")
        cache = load_cache()
        print(f"  loaded cache: {len(cache)} records (resume mode)")
        client = get_client()

        # Позитивы: 3 запроса на пример, идут параллельно через ThreadPool
        def pos_worker(ex):
            return ex, deepseek_positive(cache, ex, client)
        pos_results = run_concurrent(positives, pos_worker, concurrency=concurrency, label="pos")

        pos_entries = []
        for r in pos_results:
            if r is None:
                continue
            ex, (cause, verif, fix) = r
            pos_entries.append(build_positive_entry(ex, cause=cause, verif_steps=verif, fix_text=fix))

        # Негативы: 1 запрос на пример
        def neg_worker(ex):
            return ex, deepseek_negative(cache, ex, client)
        neg_results = run_concurrent(negatives, neg_worker, concurrency=concurrency, label="neg")

        neg_entries = []
        for r in neg_results:
            if r is None:
                continue
            ex, reason = r
            neg_entries.append(build_negative_entry(ex, reason=reason))

        # Cache stats
        statuses = Counter(rec.get("status") for rec in cache.values())
        print(f"  cache statuses: {dict(statuses)}")
    else:
        print("\nBuilding entries (with placeholders, no DeepSeek)...")
        pos_entries = [
            build_positive_entry(
                ex,
                cause=placeholder_cause(ex),
                verif_steps=placeholder_verif(ex),
                fix_text=placeholder_fix(ex),
            )
            for ex in positives
        ]
        neg_entries = [
            build_negative_entry(ex, reason=placeholder_reason(ex))
            for ex in negatives
        ]

    # 7. Cleanup
    all_entries = pos_entries + neg_entries
    print(f"Before cleanup: {len(all_entries)}")
    all_entries = cleanup_outliers(all_entries)
    print(f"After cleanup: {len(all_entries)}")

    # 8. Split train/val (с фиксированным seed)
    train, val = assign_split(all_entries, val_ratio=0.1, seed=42)

    # 9. Save
    train_path = f"{out_prefix}_train.json"
    val_path = f"{out_prefix}_val.json"
    with open(train_path, "w", encoding="utf-8") as f:
        json.dump(train, f, ensure_ascii=False, indent=2)
    with open(val_path, "w", encoding="utf-8") as f:
        json.dump(val, f, ensure_ascii=False, indent=2)
    print(f"\nSaved: {train_path} ({len(train)}), {val_path} ({len(val)})")

    # 10. Reports
    report_distribution(train, "TRAIN")
    report_distribution(val, "VAL")

    # 11. Eyeball samples
    print("\n--- EYEBALL POSITIVE #0 ---")
    if pos_entries:
        e = pos_entries[0]
        print(f"metadata: {e['metadata']}")
        print(f"USER:\n{e['messages'][1]['content'][:600]}\n...")
        print(f"ASSISTANT:\n{e['messages'][2]['content']}")

    print("\n--- EYEBALL NEGATIVE #0 ---")
    if neg_entries:
        e = neg_entries[0]
        print(f"metadata: {e['metadata']}")
        print(f"USER:\n{e['messages'][1]['content'][:600]}\n...")
        print(f"ASSISTANT:\n{e['messages'][2]['content']}")

    # 12. Sanity-check: позиции и негативы не пересекаются по dedup_key
    pos_meta_keys = set(
        (e["metadata"]["cve_id"], e["metadata"]["vuln_code_hash"], e["metadata"]["fixed_code_hash"])
        for e in pos_entries
    )
    neg_meta_keys = set(
        (e["metadata"]["cve_id"], e["metadata"]["vuln_code_hash"], e["metadata"]["fixed_code_hash"])
        for e in neg_entries
    )
    overlap = pos_meta_keys & neg_meta_keys
    if overlap:
        print(f"\n[WARN] {len(overlap)} positive/negative overlap by (cve_id, code_hash) -- fix sampling!")
    else:
        print(f"\n[OK] No overlap between positives and negatives (by cve_id+code_hash).")

    print("\n[skeleton OK] mini-dataset built. Next step: smoke DeepSeek 5+5, then full.")


if __name__ == "__main__":
    main()
