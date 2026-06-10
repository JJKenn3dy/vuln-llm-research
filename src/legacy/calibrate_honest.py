"""
"Честная" калибровка для sweep: подбираем threshold на NON-OVERLAP CrossVul-300
(195 records, гарантированно новые для модели), применяем к test-100,
отдельно смотрим OVERLAP и NON-OVERLAP test метрики.

Это даёт более реалистичную оценку OOD generalization.
"""
import sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import json
import numpy as np
from pathlib import Path

EXPERIMENTS = [
    "v7lite",
    "v7lite_1ep", "v7lite_1.5ep", "v7lite_2ep", "v7lite_2.5ep",
    "v7lite_r8", "v7lite_lowlr",
]

# Build overlap project set from train_v7lite
def project_id(pid):
    return pid.split("_")[0] if pid else ""

train_v7 = json.load(open("f:/diplom/train_data_v7lite_train.json", encoding="utf-8"))
TRAIN_PROJ_V7 = {project_id(ex["metadata"].get("file_pair_id", "")) for ex in train_v7
                 if ex["metadata"].get("source") == "crossvul"}
TRAIN_PROJ_V7.discard("")

train_v6 = json.load(open("f:/diplom/_backup_v6/train_data_v6_train.json", encoding="utf-8"))
TRAIN_PROJ_V6 = {project_id(ex["metadata"].get("file_pair_id", "")) for ex in train_v6
                 if ex["metadata"].get("source") == "crossvul"}
TRAIN_PROJ_V6.discard("")

val300 = json.load(open("f:/diplom/eval_crossvul_inputs_300.json", encoding="utf-8"))
test100 = json.load(open("f:/diplom/eval_crossvul_inputs_100.json", encoding="utf-8"))


def split_by_overlap(records, source_records, train_projects):
    """Возвращает (overlap, non-overlap) records list."""
    ov, nov = [], []
    for i, src in enumerate(source_records):
        proj = project_id(src["metadata"].get("file_pair_id", ""))
        if proj in train_projects:
            ov.append(records[i])
        else:
            nov.append(records[i])
    return ov, nov


def metrics_at_threshold(records, t):
    tp = sum(1 for r in records if r["true_label"] == "vulnerable" and r["p_vuln"] >= t)
    fn = sum(1 for r in records if r["true_label"] == "vulnerable" and r["p_vuln"] < t)
    tn = sum(1 for r in records if r["true_label"] == "safe" and r["p_vuln"] < t)
    fp = sum(1 for r in records if r["true_label"] == "safe" and r["p_vuln"] >= t)
    nv, ns = tp + fn, tn + fp
    dr = tp / nv if nv else 0
    far = fp / ns if ns else 0
    prec = tp / (tp + fp) if (tp + fp) else 0
    f1 = (2 * prec * dr / (prec + dr)) if (prec + dr) else 0
    ba = (dr + (1 - far)) / 2
    return {"threshold": float(t), "TP": tp, "FN": fn, "TN": tn, "FP": fp,
            "DR": dr, "FAR": far, "P": prec, "F1": f1, "BA": ba}


def best_threshold(records, by="BA"):
    sweep = [metrics_at_threshold(records, t) for t in np.arange(0.02, 0.99, 0.01)]
    return max(sweep, key=lambda m: m[by])


def median_gap(records):
    v = [r["p_vuln"] for r in records if r["true_label"] == "vulnerable"]
    s = [r["p_vuln"] for r in records if r["true_label"] == "safe"]
    if not v or not s:
        return None
    return float(np.median(v) - np.median(s))


def analyze_one(name, train_projects):
    val_path = Path(f"f:/diplom/{name}_logprobs_crossvul_val.json")
    test_path = Path(f"f:/diplom/{name}_logprobs_crossvul_test.json")
    if not val_path.exists() or not test_path.exists():
        return None

    val_lp = json.load(open(val_path, encoding="utf-8"))
    test_lp = json.load(open(test_path, encoding="utf-8"))

    # Split by overlap
    val_ov, val_nov = split_by_overlap(val_lp, val300, train_projects)
    test_ov, test_nov = split_by_overlap(test_lp, test100, train_projects)

    # Calibrate threshold on NON-OVERLAP CrossVul-300 VAL only
    # (это "честный" OOD val без projects-leakage)
    nov_best_ba = best_threshold(val_nov, by="BA")
    nov_best_f1 = best_threshold(val_nov, by="F1")

    # Apply to test (split by overlap)
    test_metrics = {
        "test_full_at_t_ba": metrics_at_threshold(test_lp, nov_best_ba["threshold"]),
        "test_ov_at_t_ba": metrics_at_threshold(test_ov, nov_best_ba["threshold"]),
        "test_nov_at_t_ba": metrics_at_threshold(test_nov, nov_best_ba["threshold"]),
        "test_full_at_t_f1": metrics_at_threshold(test_lp, nov_best_f1["threshold"]),
        "test_full_default_0.5": metrics_at_threshold(test_lp, 0.5),
    }

    return {
        "name": name,
        "val_nov_count": len(val_nov),
        "val_ov_count": len(val_ov),
        "test_nov_count": len(test_nov),
        "test_ov_count": len(test_ov),
        "val_nov_gap": median_gap(val_nov),
        "val_ov_gap": median_gap(val_ov),
        "test_nov_gap": median_gap(test_nov),
        "test_ov_gap": median_gap(test_ov),
        "calibrated_threshold_ba": nov_best_ba["threshold"],
        "calibrated_threshold_f1": nov_best_f1["threshold"],
        **test_metrics,
    }


print("=" * 100)
print("HONEST CALIBRATION: threshold подобран на NON-OVERLAP CrossVul-300 (честный OOD VAL)")
print("Применён к test-100 (full + OV / NOV split)")
print("=" * 100)

results = []
for name in EXPERIMENTS:
    r = analyze_one(name, TRAIN_PROJ_V7)
    if r is None:
        continue
    results.append(r)
    print(f"\n=== {name} ===")
    print(f"  VAL NOV (n={r['val_nov_count']}) gap={r['val_nov_gap']:+.3f}  "
          f"VAL OV (n={r['val_ov_count']}) gap={r['val_ov_gap']:+.3f}")
    print(f"  TEST NOV (n={r['test_nov_count']}) gap={r['test_nov_gap']:+.3f}  "
          f"TEST OV (n={r['test_ov_count']}) gap={r['test_ov_gap']:+.3f}")
    print(f"  Calibrated t_ba={r['calibrated_threshold_ba']:.2f}  t_f1={r['calibrated_threshold_f1']:.2f}")
    m = r['test_full_at_t_ba']
    mn = r['test_nov_at_t_ba']
    mo = r['test_ov_at_t_ba']
    md = r['test_full_default_0.5']
    print(f"  TEST default 0.50 (full):  DR={md['DR']*100:5.1f}%  FAR={md['FAR']*100:5.1f}%  F1={md['F1']:.3f}  BA={md['BA']:.3f}")
    print(f"  TEST @ t_ba (full):        DR={m['DR']*100:5.1f}%  FAR={m['FAR']*100:5.1f}%  F1={m['F1']:.3f}  BA={m['BA']:.3f}")
    print(f"  TEST @ t_ba (OV only):     DR={mo['DR']*100:5.1f}%  FAR={mo['FAR']*100:5.1f}%  F1={mo['F1']:.3f}  BA={mo['BA']:.3f}")
    print(f"  TEST @ t_ba (NOV only):    DR={mn['DR']*100:5.1f}%  FAR={mn['FAR']*100:5.1f}%  F1={mn['F1']:.3f}  BA={mn['BA']:.3f}")

print("\n" + "=" * 100)
print("HONEST SUMMARY: TEST NOV (новые проекты) — реальная OOD-метрика")
print("=" * 100)
print(f"{'name':<15} {'t_ba':>5} {'NOV F1':>7} {'NOV BA':>7} {'NOV FAR':>8} {'OV F1':>6} {'OV BA':>6} {'full F1':>8}")
for r in results:
    n = r['test_nov_at_t_ba']
    o = r['test_ov_at_t_ba']
    f = r['test_full_at_t_ba']
    print(f"{r['name']:<15} {r['calibrated_threshold_ba']:5.2f} "
          f"{n['F1']:7.3f} {n['BA']:7.3f} {n['FAR']*100:7.1f}% "
          f"{o['F1']:6.3f} {o['BA']:6.3f} {f['F1']:8.3f}")

# Winner
winner = max(results, key=lambda r: r['test_nov_at_t_ba']['BA'])
print(f"\nWINNER by NOV BA: {winner['name']} (BA={winner['test_nov_at_t_ba']['BA']:.3f}, F1={winner['test_nov_at_t_ba']['F1']:.3f})")

# Save
out = Path("f:/diplom/metrics_sweep_honest.json")
out.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"\nSAVED: {out}")
