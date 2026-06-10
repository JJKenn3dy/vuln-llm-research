"""
Создаёт hold-out eval-сет для v5: 70 vuln + 30 safe = 100 примеров.

ИСТОЧНИКИ (--source):
  hf       — HuggingFace hitoshura25/cvefixes (полный, на кластере)
  v4_local — train_data_v4.json локально (degraded fallback, перекошен на CWE-79)

Исключения:
  - все ключи из train_data_v5_train.json + train_data_v5_val.json (наш train)
  - все ключи из train_data_v4.json (старый train, чтобы не пересекаться с v4)

Формат вывода: совпадает с train_data_v5_*.json (messages + metadata).
metadata.label определяет ground truth для метрик eval.
"""
import argparse
import hashlib
import json
import random
import re
from collections import Counter

# Импортируем функции из prepare_train_v5
import importlib.util
spec = importlib.util.spec_from_file_location("p5", "prepare_train_v5.py")
p5 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p5)

random.seed(123)

EVAL_VULN_TOTAL = 70
EVAL_SAFE_TOTAL = 30


def load_train_v5_keys():
    """Все dedup_key из train_v5 (исключаем из eval)."""
    keys = set()
    for path in ("train_data_v5_train.json", "train_data_v5_val.json"):
        try:
            with open(path, encoding="utf-8") as f:
                for entry in json.load(f):
                    md = entry["metadata"]
                    keys.add((md["cve_id"], md.get("repo", ""), md.get("file_path", ""),
                              md["vuln_code_hash"], md["fixed_code_hash"]))
        except FileNotFoundError:
            print(f"  [warn] {path} not found, skip")
    return keys


def load_v4_train_keys():
    """Ключи примеров которые попали в train_data_v4.json (если файл локально доступен)."""
    keys = set()
    try:
        v4_pool = p5.parse_v4_local("train_data_v4.json")
        for ex in v4_pool:
            keys.add(p5.dedup_key(ex))
        print(f"  loaded {len(keys)} v4 train keys")
    except FileNotFoundError:
        print(f"  [warn] train_data_v4.json not found, skip v4 exclusion")
    return keys


def stratified_softer(pool, total, cwe_cap_pct=50, rnd=None):
    """
    Берёт total примеров из pool с softer-balancing:
    CWE-79 ограничен cwe_cap_pct% от total, остальные CWE — равномерно.
    """
    rnd = rnd or random.Random(123)
    by_cwe = {}
    for ex in pool:
        c = p5.get_cwe_id(ex)
        by_cwe.setdefault(c, []).append(ex)

    selected = []
    used_keys = set()
    other_pool = []
    for c, items in by_cwe.items():
        if c == "CWE-79":
            continue
        rnd.shuffle(items)
        other_pool.extend(items)
    rnd.shuffle(other_pool)

    # 1) Сначала берём из не-CWE-79
    other_target = total - (total * cwe_cap_pct // 100)
    for ex in other_pool:
        if len(selected) >= other_target:
            break
        k = p5.dedup_key(ex)
        if k in used_keys:
            continue
        selected.append(ex)
        used_keys.add(k)

    # 2) Добиваем из CWE-79
    cwe79 = list(by_cwe.get("CWE-79", []))
    rnd.shuffle(cwe79)
    for ex in cwe79:
        if len(selected) >= total:
            break
        k = p5.dedup_key(ex)
        if k in used_keys:
            continue
        selected.append(ex)
        used_keys.add(k)

    # 3) Если ещё не добрали (мало CWE-79) — берём ещё из других
    if len(selected) < total:
        for ex in other_pool:
            if len(selected) >= total:
                break
            k = p5.dedup_key(ex)
            if k in used_keys:
                continue
            selected.append(ex)
            used_keys.add(k)

    return selected, used_keys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", choices=["hf", "v4_local"], default="hf",
                        help="Source dataset: hf (CVEfixes from HuggingFace) or v4_local")
    parser.add_argument("--out", default="eval_v5_inputs.json")
    args = parser.parse_args()

    if args.source == "hf":
        print("Loading hitoshura25/cvefixes from HuggingFace...")
        from datasets import load_dataset
        ds = load_dataset("hitoshura25/cvefixes", split="train")
        pool = list(ds)
        print(f"Total HF: {len(pool)}")
    else:
        print("Loading train_data_v4.json (parsed)...")
        pool = p5.parse_v4_local("train_data_v4.json")
        print(f"Total v4_local: {len(pool)}")

    # Filter + dedup
    seen = set()
    filtered = []
    for ex in pool:
        if not p5.is_valid(ex):
            continue
        k = p5.dedup_key(ex)
        if k in seen:
            continue
        seen.add(k)
        filtered.append(ex)
    print(f"After is_valid + dedup: {len(filtered)}")

    # Exclude train_v5 + (если HF) v4 train keys
    train_v5_keys = load_train_v5_keys()
    print(f"Train v5 keys to exclude: {len(train_v5_keys)}")

    excluded_keys = set(train_v5_keys)
    if args.source == "hf":
        v4_keys = load_v4_train_keys()
        excluded_keys |= v4_keys
        print(f"+ v4 train keys: {len(v4_keys)} → total excluded: {len(excluded_keys)}")

    eval_pool = [ex for ex in filtered if p5.dedup_key(ex) not in excluded_keys]
    print(f"Eval pool: {len(eval_pool)}")

    # Распределение в pool
    by_cwe = Counter(p5.get_cwe_id(ex) for ex in eval_pool)
    print(f"\nEval pool by CWE:")
    for c, n in by_cwe.most_common(15):
        print(f"  {c}: {n}")

    # Sampling vuln
    print(f"\nSampling {EVAL_VULN_TOTAL} vulnerable (CWE-79 cap = 50%)...")
    rnd = random.Random(123)
    vuln_examples, vuln_keys = stratified_softer(eval_pool, EVAL_VULN_TOTAL, cwe_cap_pct=50, rnd=rnd)
    print(f"  vuln: {len(vuln_examples)}")

    # Safe из остатка
    safe_pool = [ex for ex in eval_pool if p5.dedup_key(ex) not in vuln_keys]
    safe_examples, _ = stratified_softer(safe_pool, EVAL_SAFE_TOTAL, cwe_cap_pct=50, rnd=rnd)
    print(f"  safe: {len(safe_examples)}")

    # Build entries (assistant placeholder — не используется при inference)
    eval_entries = []
    for ex in vuln_examples:
        entry = p5.build_positive_entry(ex, cause="N/A", verif_steps="N/A", fix_text="N/A")
        eval_entries.append(entry)
    for ex in safe_examples:
        entry = p5.build_negative_entry(ex, reason="N/A")
        eval_entries.append(entry)

    rnd.shuffle(eval_entries)

    # Stats
    labels = Counter(e["metadata"]["label"] for e in eval_entries)
    cwe_v = Counter(e["metadata"]["cwe_id"] for e in eval_entries if e["metadata"]["label"] == "vulnerable")
    cwe_s = Counter(e["metadata"]["cwe_id"] for e in eval_entries if e["metadata"]["label"] == "safe")
    print(f"\n=== EVAL FINAL: {len(eval_entries)} ===")
    print(f"  labels: {dict(labels)}")
    print(f"  vuln CWE: {dict(cwe_v.most_common())}")
    print(f"  safe CWE: {dict(cwe_s.most_common())}")

    # Sanity overlap check
    overlaps = 0
    for e in eval_entries:
        md = e["metadata"]
        k = (md["cve_id"], md.get("repo", ""), md.get("file_path", ""),
             md["vuln_code_hash"], md["fixed_code_hash"])
        if k in train_v5_keys:
            overlaps += 1
    print(f"  overlap with train_v5: {overlaps} (must be 0)")

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(eval_entries, f, ensure_ascii=False, indent=2)
    print(f"\nSaved -> {args.out}")


if __name__ == "__main__":
    main()
