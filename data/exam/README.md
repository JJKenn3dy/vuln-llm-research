# Exam carve 2026-06-10

Source: `data/eval/sastbench_v01_val558.json` (n=558)
Seed: 42

## Splits

| File | n | Sampling | Verdict dist | Lock |
|---|---|---|---|---|
| exam_a_in_scope_300.json | 300 | proportional | {'FALSE_POSITIVE': 261, 'TRUE_POSITIVE': 39} | YES until v8.3 final |
| hand_label_scaffold.json | 50 | balanced 25+25 | {'FALSE_POSITIVE': 25, 'TRUE_POSITIVE': 25} | NO (researcher reads) |
| val_working_remainder.json | 208 | the rest | {'FALSE_POSITIVE': 200, 'TRUE_POSITIVE': 8} | NO |
| exam_b_finding_ids.json | {'web_lang_nonweb_cwe': 1476, 'nonweb_lang_web_cwe': 123} | filter rule | n/a | YES until v8.3 final |

## Two-pass labeling

1. **Pass 1** (snippet only, do NOT open repo): fill `solvable_from_snippet`
   and `your_verdict_snippet_only` for ALL 50 cases.
2. **Pass 2** (full repo, per case): fill `your_verdict_with_full_context`,
   `evidence_packet` per `EVIDENCE_PACKET_PROTOCOL.md`,
   `evidence_packet_protocol_compliance`, and if FP also `fp_cause_taxonomy`.

`your_verdict_snippet_only` is the **human-on-snippet baseline** for the
sufficiency probe — a sixth arm that costs zero API calls.

## Researcher discipline

Before opening `exam_a_*.json` or `exam_b_*.json` in code, ask:
"is this final v8.3 evaluation, or am I about to leak the exam?"
Default = leak; only open for final pass.

Full lock policy: `manifest.json`.
