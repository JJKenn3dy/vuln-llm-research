"""Blind re-label of v8.x triage train data with GPT-5.3-codex (Path C -> v8.4).

Why: train_merged.json verdicts are copied from CVEFixes unverified, and TP
reasoning is NVD-boilerplate ("cargo-cult"), with leaked git-svn-id cruft.
The blind protocol (validated on hand-label-100: GPT-5.3<->human 71.7%, noise
floor 12%; anchored mode FAILED the gate, cave 31.2%) fixes both:
  1. re-verify verdict from CODE ONLY (no shipped label shown)
  2. regenerate code-grounded reasoning

The user message in train_merged is ALREADY blind (presents code + claimed
CWE + finding, asks for a verdict; does NOT leak the shipped verdict), so we
send it as-is. The shipped verdict (metadata) is recorded only for post-hoc
comparison, never sent to the model.

Output: data/train/triage_v8_4_relabel/gpt53_blind.jsonl (one rec/row).
Decision policy (drop/flip/hybrid) is applied LATER by a separate merge step,
once the smoke shows the real disagreement rate.

Smoke: stratified across source x shipped_verdict. Partial every 10 rows.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

ROOT = Path("f:/vuln-llm-research")
TRAIN = ROOT / "data/train/triage_v8_3_1/train_merged.json"
OUTDIR = ROOT / "data/train/triage_v8_4_relabel"
OUT = OUTDIR / "gpt53_blind.jsonl"
PARTIAL = OUTDIR / "gpt53_blind.partial.jsonl"
SEED = 20260613

import json as _json
import time as _time
import urllib.error
import urllib.request

sys.path.insert(0, str(ROOT / "scripts"))
from gpt53_relabel_handlabel100 import MODEL, OR_ENDPOINT, find_token  # noqa: E402


def call_model(token, system, user, max_tokens=4000, retry=3, base_delay=2.0):
    body = _json.dumps({
        "model": MODEL,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "max_tokens": max_tokens, "temperature": 0.0,
    }).encode("utf-8")
    req = urllib.request.Request(OR_ENDPOINT, data=body, headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/JJKenn3dy/vuln-llm-research",
        "X-Title": "vuln-llm-research v8.4 blind relabel"}, method="POST")
    last = None
    for a in range(retry):
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return _json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            msg = (e.read()[:400].decode("utf-8", "replace")) if hasattr(e, "read") else ""
            last = f"HTTP {e.code}: {msg}"
            if e.code in (429, 500, 502, 503, 504):
                _time.sleep(base_delay * (2 ** a)); continue
            raise RuntimeError(last)
        except Exception as e:
            last = str(e); _time.sleep(base_delay * (2 ** a))
    raise RuntimeError(f"failed after {retry}: {last}")

# train_merged user message already carries the full instruction + output
# format, so we send it verbatim. A light system primer keeps GPT-5.3 in the
# "label auditor" frame without showing any shipped verdict.
SYSTEM = (
    "You are an experienced application-security engineer triaging static-analysis "
    "findings. Judge ONLY from the code shown. Decide TRUE_POSITIVE (real exploitable "
    "bug in this code) vs FALSE_POSITIVE (noise: safe, wrong CWE, sink unreachable, "
    "defense in place). Base the reasoning on the specific code elements you see, not "
    "on any external CVE description. Follow the output format in the user message exactly."
)

V_RE = re.compile(r"Verdict:\s*(TRUE_POSITIVE|FALSE_POSITIVE|TP|FP)", re.I)
C_RE = re.compile(r"Confidence:\s*(HIGH|MEDIUM|LOW)", re.I)
R_RE = re.compile(r"Reasoning:\s*(.+?)(?:\n(?:RealCWE|SuggestedFix|Confidence|Verdict):|\Z)", re.I | re.S)
RC_RE = re.compile(r"RealCWE:\s*(.+?)(?:\n(?:SuggestedFix|Reasoning):|\Z)", re.I | re.S)
SF_RE = re.compile(r"SuggestedFix:\s*(.+?)(?:\n[A-Z][a-z]+:|\Z)", re.I | re.S)


def norm(v):
    if v is None:
        return None
    v = str(v).strip().upper()
    return "TP" if v in ("TP", "TRUE_POSITIVE") else "FP" if v in ("FP", "FALSE_POSITIVE") else None


def parse(raw: str) -> dict:
    v = V_RE.search(raw)
    verdict = v.group(1).upper() if v else "?"
    verdict = {"TP": "TRUE_POSITIVE", "FP": "FALSE_POSITIVE"}.get(verdict, verdict)
    c = C_RE.search(raw); r = R_RE.search(raw); rc = RC_RE.search(raw); sf = SF_RE.search(raw)
    return {
        "verdict": verdict,
        "confidence": c.group(1).upper() if c else "?",
        "reasoning": r.group(1).strip() if r else "",
        "real_cwe": rc.group(1).strip() if rc else "",
        "suggested_fix": sf.group(1).strip() if sf else "",
    }


def stratified_idx(rows, per_cell):
    cells = {}
    for i, row in enumerate(rows):
        m = row["metadata"]
        key = (m.get("source", "?"), norm(m.get("verdict")))
        cells.setdefault(key, []).append(i)
    pick = []
    # deterministic: stride through each cell, no RNG (Math.random-style avoided)
    for key in sorted(cells, key=lambda k: (str(k[0]), str(k[1]))):
        idxs = cells[key]
        step = max(1, len(idxs) // per_cell)
        pick.extend(idxs[::step][:per_cell])
    return sorted(pick), cells


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--smoke-per-cell", type=int, default=0, help="N per source x verdict cell, then stop")
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--end", type=int, default=10**9)
    args = ap.parse_args()

    OUTDIR.mkdir(parents=True, exist_ok=True)
    token = find_token()
    rows = json.loads(TRAIN.read_text(encoding="utf-8"))

    if args.smoke_per_cell:
        idxs, cells = stratified_idx(rows, args.smoke_per_cell)
        print("cells (source,verdict):", {str(k): len(v) for k, v in cells.items()})
        print(f"smoke: {len(idxs)} rows, {args.smoke_per_cell}/cell\n")
    else:
        idxs = list(range(args.start, min(args.end, len(rows))))

    done = set()
    if PARTIAL.exists():
        for line in PARTIAL.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    done.add(json.loads(line)["row_idx"])
                except Exception:
                    pass
        print(f"resume: {len(done)} rows already done")

    results = []
    tin = tout = 0
    t0 = time.time()
    for i in idxs:
        if i in done:
            continue
        row = rows[i]
        m = row["metadata"]
        user = [x for x in row["messages"] if x["role"] == "user"][0]["content"]
        shipped = norm(m.get("verdict"))
        try:
            resp = call_model(token, SYSTEM, user)
        except Exception as e:
            print(f"  {i:>4d}: ERROR {e}")
            continue
        msg = resp["choices"][0]["message"]
        rawtxt = (msg.get("content") or msg.get("reasoning") or "").strip()
        if not rawtxt:
            print(f"  {i:>4d}: EMPTY (finish={resp['choices'][0].get('finish_reason')})")
            continue
        u = resp.get("usage", {})
        tin += u.get("prompt_tokens", 0); tout += u.get("completion_tokens", 0)
        p = parse(rawtxt)
        new_v = norm(p["verdict"])
        agree = (new_v == shipped) if new_v else None
        rec = {
            "row_idx": i, "case_id": m.get("case_id"), "source": m.get("source"),
            "claimed_cwe": m.get("claimed_cwe"), "language": m.get("language"),
            "shipped_verdict": shipped, "blind_verdict": new_v, "agree": agree,
            "confidence": p["confidence"], "reasoning": p["reasoning"],
            "real_cwe": p["real_cwe"], "suggested_fix": p["suggested_fix"], "raw": rawtxt,
        }
        results.append(rec)
        with PARTIAL.open("a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        flag = "OK " if agree else "DIFF" if agree is not None else "??? "
        print(f"  {i:>4d} {m.get('source','?')[:8]:<8} ship={shipped} blind={new_v} [{flag}] "
              f"{p['confidence']:<6} ({(time.time()-t0)/max(len(results),1):.1f}s/row)")

    if not args.smoke_per_cell and PARTIAL.exists():
        recs = [json.loads(l) for l in PARTIAL.read_text(encoding="utf-8").splitlines() if l.strip()]
        with OUT.open("w", encoding="utf-8", newline="\n") as f:
            for r in recs:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"\nwrote {len(recs)} -> {OUT}")

    # smoke summary
    if results:
        n = len(results)
        agr = sum(1 for r in results if r["agree"])
        print(f"\n--- smoke summary n={n} ---")
        print(f"agree with shipped: {agr}/{n} = {agr/n:.0%}  (disagreement {1-agr/n:.0%})")
        from collections import Counter
        for src in sorted(set(r["source"] for r in results)):
            sr = [r for r in results if r["source"] == src]
            a = sum(1 for r in sr if r["agree"])
            print(f"  {src:<14} agree {a}/{len(sr)} = {a/len(sr):.0%}")
        disc = [r for r in results if r["agree"] is False]
        if disc:
            print(f"disagreement by confidence: {dict(Counter(r['confidence'] for r in disc))}")
    cost = tin * 1.75e-6 + tout * 14e-6
    print(f"tokens in={tin} out={tout}  est cost ${cost:.3f}")


if __name__ == "__main__":
    main()
