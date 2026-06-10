"""Sanity-check: does shallow code structure predict TP vs FP in the v8.2 train set?

Lesson 0 from v8.1: the model learned the surface stylistic discriminator
(rich varied TP reasoning vs templated FP reasoning), not the semantic pre/post
difference. SastBench's Appendix B reports their best non-contextual MLP gets
F1 = 0.36, confirming their data has no exploitable shortcuts.

This script does the same check on our generated triage train set. Features
are intentionally SHALLOW: character counts, comment density, keyword counts.
A real triage signal should be invisible to such features, so the MLP should
score ~0.5 F1 on a 50/50 balanced label.

Decision gates:
    F1 < 0.40   no shortcut signal; safe to train v8.2
    F1 0.40-0.60 mild shortcut; inspect TP/FP length distributions
    F1 > 0.60   data has structural leakage; v8.2 will collapse like v8.1

Usage:
    python scripts/shortcut_check.py \\
        --train data/train/triage_v8_2/triage_train.json \\
        --output runs/shortcut_check.json
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
from collections import Counter
from datetime import datetime
from pathlib import Path


KEYWORDS = ["if", "else", "for", "while", "return", "def", "function",
            "class", "import", "from", "try", "except", "throw",
            "public", "private", "static"]
SPECIALS = "$@%#?!;{}[]()"


def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def extract_code(user_message: str) -> str:
    m = re.search(r"Code:\s*\n(.*?)$", user_message, re.DOTALL)
    return m.group(1).strip() if m else user_message


def featurise(code: str) -> list[float]:
    lines = code.splitlines() or [""]
    line_lens = [len(l) for l in lines]
    nonblank = [l for l in lines if l.strip()]
    comment_lines = sum(1 for l in lines if l.strip().startswith(("//", "#", "/*", "*", "--", "<!--")))
    feats = [
        len(code),                          # 0  total chars
        len(lines),                         # 1  line count
        len(nonblank),                      # 2  non-blank lines
        statistics.mean(line_lens) if line_lens else 0,  # 3  avg line length
        max(line_lens) if line_lens else 0, # 4  max line length
        comment_lines,                      # 5  comment lines
        comment_lines / max(1, len(lines)), # 6  comment ratio
        code.count("\n\n"),                 # 7  paragraph breaks
        sum(1 for c in code if c.isspace()) / max(1, len(code)),  # 8  whitespace ratio
    ]
    text = " " + code.lower() + " "
    for kw in KEYWORDS:
        feats.append(text.count(f" {kw} ") + text.count(f" {kw}(") + text.count(f"\n{kw} "))
    for ch in SPECIALS:
        feats.append(code.count(ch))
    return feats


def train_and_eval(X, y, seed: int = 42) -> dict:
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler
    from sklearn.neural_network import MLPClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import f1_score, balanced_accuracy_score, classification_report, confusion_matrix

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=seed, stratify=y,
    )

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    results = {}
    for name, clf in [
        ("mlp", MLPClassifier(hidden_layer_sizes=(64, 32), max_iter=300, random_state=seed)),
        ("logreg", LogisticRegression(max_iter=500, random_state=seed)),
    ]:
        clf.fit(X_train_s, y_train)
        pred = clf.predict(X_test_s)
        f1 = f1_score(y_test, pred, pos_label=1)
        ba = balanced_accuracy_score(y_test, pred)
        cm = confusion_matrix(y_test, pred).tolist()
        results[name] = {
            "f1": round(f1, 4),
            "balanced_accuracy": round(ba, 4),
            "confusion_matrix": cm,  # [[TN, FP], [FN, TP]] with pos_label=1
        }
    return results


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Check for shortcut features in triage training set")
    p.add_argument("--train", required=True, help="Path to triage_train.json")
    p.add_argument("--output", default="runs/shortcut_check.json")
    p.add_argument("--seed", type=int, default=42)
    return p.parse_args()


def main() -> None:
    args = parse_args()
    with open(args.train, encoding="utf-8") as f:
        data = json.load(f)

    X: list[list[float]] = []
    y: list[int] = []
    cwes: list[str] = []
    langs: list[str] = []
    for entry in data:
        md = entry.get("metadata", {})
        user_msg = entry["messages"][1]["content"]
        code = extract_code(user_msg)
        X.append(featurise(code))
        y.append(1 if md.get("verdict") == "TRUE_POSITIVE" else 0)
        cwes.append(md.get("claimed_cwe", "?"))
        langs.append(md.get("language", "?"))

    log(f"Loaded {len(X)} examples; verdicts: TP={sum(y)}, FP={len(y) - sum(y)}")

    n_features = len(X[0])
    feature_names = (
        ["chars", "lines", "nonblank", "avg_line_len", "max_line_len",
         "comment_lines", "comment_ratio", "para_breaks", "ws_ratio"]
        + [f"kw_{k}" for k in KEYWORDS]
        + [f"sp_{c}" for c in SPECIALS]
    )
    assert len(feature_names) == n_features, (len(feature_names), n_features)
    log(f"Features ({n_features}): {feature_names[:6]} ... {feature_names[-3:]}")

    results = train_and_eval(X, y, seed=args.seed)
    log(f"MLP f1={results['mlp']['f1']}, balanced_acc={results['mlp']['balanced_accuracy']}")
    log(f"LogReg f1={results['logreg']['f1']}, balanced_acc={results['logreg']['balanced_accuracy']}")

    f1 = max(results["mlp"]["f1"], results["logreg"]["f1"])
    if f1 < 0.40:
        verdict = "PASS: no exploitable shortcut found, safe to train v8.2"
    elif f1 < 0.60:
        verdict = "WARN: mild shortcut signal, inspect TP vs FP length/keyword distributions"
    else:
        verdict = "FAIL: shortcut signal too strong, v8.2 will collapse like v8.1"
    log(f"==> {verdict}")

    tp_chars = [X[i][0] for i in range(len(X)) if y[i] == 1]
    fp_chars = [X[i][0] for i in range(len(X)) if y[i] == 0]
    log(f"Char length TP: mean={statistics.mean(tp_chars):.0f}  median={statistics.median(tp_chars):.0f}")
    log(f"Char length FP: mean={statistics.mean(fp_chars):.0f}  median={statistics.median(fp_chars):.0f}")
    log(f"Lang dist TP: {dict(Counter(l for i, l in enumerate(langs) if y[i] == 1).most_common(5))}")
    log(f"Lang dist FP: {dict(Counter(l for i, l in enumerate(langs) if y[i] == 0).most_common(5))}")

    report = {
        "n_examples": len(X),
        "n_features": n_features,
        "feature_names": feature_names,
        "verdict": verdict,
        "max_f1": round(f1, 4),
        "results": results,
        "tp_char_stats": {"mean": statistics.mean(tp_chars), "median": statistics.median(tp_chars)},
        "fp_char_stats": {"mean": statistics.mean(fp_chars), "median": statistics.median(fp_chars)},
    }
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    log(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
