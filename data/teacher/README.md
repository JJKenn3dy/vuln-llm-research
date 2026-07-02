# data/teacher — оплаченные teacher-разметки (бэкап 2026-07-03)

Артефакты дистилляционной разметки exp5-exp7. Раньше жили только в git-ignored `runs/` на локальной машине; перенесены в git как невоспроизводимый бесплатно актив (OpenRouter-кредиты потрачены, версии учителей со временем уедут).

## exp5: dual-teacher consensus (2026-06-29)

Учителя: `openai/gpt-5.5` + `z-ai/glm-5.2` через OpenRouter, blind-протокол (метка не показывалась). В train шли только строки с консенсусом обоих учителей.

- `exp5_dual_train.json` — 236 consensus-строк (вход build_v8_4_exp5_train.py)
- `exp5_dual_quarantine.json` — строки без консенсуса (карантин)
- `exp5_dual_raw.partial.jsonl` — сырые ответы учителей (partial dump; прогон оборван на 277/970 пула, кончились кредиты)
- `exp5_dual_audit.json` — агрегаты: agreement 85%, 36% флипов исходных меток

## exp5 smoke (2026-06-24/26)

- `exp5_smoke_blind.json` / `exp5_smoke_key.json` — blind-смоук Opus-as-teacher (verdict-agreement 83%)
- `exp5_teacher_smoke_train.json` / `exp5_teacher_smoke_audit.json` — смоук-срез платного teacher-прогона

## exp6/exp7: GLM-solo relabel (2026-07-01)

Учитель: `z-ai/glm-5.2` соло, fp4 pinned, blind.

- `exp6_glm_train.json` — 951 строка relabel (вход exp6/exp7/exp8/exp9 build-скриптов)
- `exp6_glm_train.partial.jsonl` — partial dump прогона
- `exp6_glm_audit.json` — агрегаты

## Незакрытый долг

Dual-teacher покрыл только 277/970 строк пула (29%). Дозакрытие оставшихся ~693 строк = шаг 2 плана улучшения (см. docs/AUDIT_FULL_2026-07-02.md).

Версии учителей НЕ запинены на снапшот (OpenRouter не даёт), поэтому эти файлы фактически единственная фиксация того, что именно сказали учителя в июне-июле 2026.
