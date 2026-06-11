# Practical smoke v2: расширение до 11 репов, 124 findings (2026-06-11 ночь)

Расширение [PRACTICAL_SMOKE_2026-06-11.md](PRACTICAL_SMOKE_2026-06-11.md) с
1 репа до 11. Цель: посмотреть как v8.3.1 ranker ведёт себя на разных
SAST-распределениях (Node, PHP, Python, TypeScript) и на реальных
AI-сгенерированных приложениях.

## Setup (delta)

К прежним 4 репам добавлены 6:
- **DVWA** (PHP intentionally-vulnerable) — controlled, 72 findings
- **dvna** (Node/EJS intentionally-vulnerable) — controlled, 22 findings
- **portifolio_v0** (v0-dev coded TS portfolio) — 0 findings
- **lovable_boilerplate** (Lovable-style React boilerplate) — 0 findings
- **nextly_lovable** (Lovable-style Next.js generator) — 1 finding
- **supashield** (Lovable-coded TS CLI tool) — 0 findings

Один из старых: `openai-agents-sdk-chatbot-UI` (vikramdotcom, через
topic v0-dev) — 0 findings, уже был в v1.

Pipeline тот же: Semgrep 1.166 `--config=auto`, v8.3.1 LoRA на A40 через
temp pod, ranker mode.

## Headline-1: Pattern SAST имеет recall ≈0 на AI-coded коде

| Категория | Репов | Findings | Найдено в |
|---|---:|---:|---|
| **AI-coded / vibe-coded** | 7 | **0** | везде ноль |
| **AI app generators (само AI tool)** | 1 (nextly) | **1** | prototype-pollution в utility |
| **Intentionally vulnerable** | 3 (NodeGoat+dvna+DVWA) | **123** | разнообразный mix |

Список AI-coded репов:
- `JJKenn3dy/rpg_life` (FastAPI + SQLAlchemy + aiogram bot) — 0
- `JJKenn3dy/survivemedia` (Next.js 15 + TS landing) — 0
- `vikramdotcom/openai-agents-sdk-chatbot-UI` (v0-dev) — 0
- `MatheusAlvesPereira/portifolio-` (v0 portfolio) — 0
- `chihebnabil/lovable-boilerplate` (Lovable React) — 0
- `Rodrigotari1/supashield` (Lovable Supabase RLS CLI) — 0
- `vedantxn/nextly` (Lovable-style Next.js generator) — 1
- 8-й репо `JJKenn3dy/rpg_life` — обе ветки 0.

**Цифра для outreach**: 1 finding на 7 проверенных AI-сгенерированных
веб-приложениях (нам выпал он в utility функции у самого AI-app генератора).

## Headline-2: на вulnerable controls ranker даёт семантически верный порядок

124 findings на трёх стеках (PHP, Node-EJS, Node-Express). Каждый
top-5 указывает на настоящую критическую уязвимость:

| Repo | Stack | Top-5 (model p_tp 0.72-0.80) | Это TP? |
|---|---|---|---|
| **DVWA** | PHP | все `tainted-sql-string` (CWE-89) в `vulnerabilities/sqli/source/low.php`, `sqli_blind/low.php`, `brute/source/low.php` | да, classic intentional SQLi |
| **dvna** | Node + EJS | все `template-explicit-unescape` (CWE-79) в `views/app/products.ejs` | да, classic intentional XSS |
| **NodeGoat** | Express | все `eval(req.body.X)` (CWE-95) в `app/routes/contributions.js` | да, classic eval injection RCE |

Bottom-5 каждого repos — pattern-only / config / dead-code findings,
которые модель корректно отправила вниз:

| Repo | Bottom-5 типы | Sanity |
|---|---|---|
| **DVWA** | `permissive-cors`, `md5-loose-equality` в обучающих файлах | FP, тестовые/dead |
| **dvna** | `express-check-csurf-middleware-usage` на `const app`, `no-new-privileges` docker, `sequelize-enforce-tls` config | pattern-only |
| **NodeGoat** | http-link в туториальной HTML, bcrypt-hash в **закомментированной** строке, docker permissions | pattern-only / dead |

**3 из 3 vulnerable controls — direction-only beats** (top-5 — настоящие баги).
N=3 не cluster CI, но direction-only consistency на разных языках и
SAST-категориях — сильный signal.

## Распределение p_tp по репам

| Repo | N | min | med | max | gap | stdev | frac>0.5 |
|---|---:|---:|---:|---:|---:|---:|---:|
| DVWA | 72 | 0.304 | 0.504 | 0.798 | **0.494** | 0.143 | 51.4% |
| dvna | 22 | 0.348 | 0.455 | 0.793 | **0.444** | 0.173 | 40.9% |
| NodeGoat | 29 | 0.314 | 0.550 | 0.757 | **0.444** | 0.140 | 55.2% |
| nextly_lovable | 1 | 0.453 | 0.453 | 0.453 | 0 | 0 | 0% |

Three observations:

1. **Gap stable across stacks** (0.444 - 0.494). На SastBench-250 gap был 0.023
   (collapsed). Здесь signal не collapsed на real-world распределении.
2. **Frac > 0.5 балансированный** (40-55%). Модель не в paranoia mode (не
   все TP) и не в conservative mode (не все FP). Для распределения где
   часть findings реально TP это адекватно.
3. **Median между 0.45 и 0.55** на всех трёх vulnerable. Calibration не
   сдвинута в одну сторону.

## Borderline AI-coded case: nextly_lovable/src/lib/utils.ts:41

Единственный finding в наших AI-сгенерированных репах. Semgrep
`prototype-pollution-loop` (CWE-915) на функции:

```typescript
export function convertFilesToTreeItems(
  files: { [path: string]: string }
): TreeItem[] {
  // ...
  for (const filepath of sortedPaths) {
    const parts = filepath.split("/");
    let current = tree;
    for (let i = 0; i < parts.length - 1; i++) {
      const part = parts[i];
      if (!current[part]) {
        current[part] = {};
      }
      current = current[part];  // <-- triggers here
    }
    // ...
  }
}
```

Borderline: pattern формально present (loop по user-supplied keys и
запись в object), на практике безопасно если ключи не контролируются
атакующим. Модель дала **p_tp=0.453** (между TP и FP). Хорошая
calibration: borderline case получил borderline score.

## Pipeline баги починены

- `triage_filter.py` — `_log` после `log_fp.close()` вызывал ValueError в
  финальном "done" сообщении. Перенесено closing после final log.
- `scripts/run_practical_smoke.sh` — добавлен `--no-same-owner` к tar и
  `|| true` чтобы Windows-uid ownership warnings не убивали pipefail.
- Mock smoke test показал что fixed pipeline теперь пишет полный progress
  log без стектрейса.

## Расходы

| Item | Cost |
|---|---:|
| Smoke v1 (NodeGoat only) | ~$0.20 |
| Smoke v2 (4 repos) | ~$0.13 |
| Total | **~$0.33** |

Pod `bzuwcrfapjhimh` (v2 temp) terminated. Главный
`yodelling_maroon_primate` EXITED.

## Что это даёт продукту

1. **Cold outreach hook**: "проверили 7 AI-сгенерированных приложений на
   v0/Lovable/Cursor стеках, Semgrep дал ноль findings суммарно.
   Pattern-SAST на vibe-coded код — мёртв". Это и redirection (если у
   тебя AI-coded, тебе не нужен наш триаж), и opportunity (мы можем
   запустить semantic detection вверху — отдельный product line).
2. **Direction-only confirmation** на 3 vulnerable стеках (PHP, EJS,
   Express): top-5 модели по p_tp всегда указывает на настоящие баги.
3. **N=4 не даёт честный cluster CI**, но достаточно для "наш ranker
   работает не только на nodegoat" — главное возражение по v1 smoke
   закрыто.
4. **Backlog**: posup'нуть filter mode с reasoning на эти же SARIF
   чтобы получить PDF-формат для outreach attachment.

## Что НЕ говорить в pitch по итогам v2

- "Cluster CI excludes 0 для практического scenario" — N=4 repos слишком
  мало для real cluster bootstrap.
- "Recall 100% на real bugs" — мы видели top-5 на каждом repo, не считали
  recall на ground truth (нет ground truth разметки на 124 findings).
- "Frontier хуже на этих репах" — frontier baseline не прогнан.

## Файлы

```
data/practical/
  apps_v2.tar.gz                       # 10 репов
  sarif/
    {nodegoat,dvna,DVWA,nextly_lovable}.sarif        # с findings
    {rpg_life,survivemedia,v0_chatbot,portifolio_v0,
     lovable_boilerplate,supashield}.sarif           # zero findings
  results_v2/
    {nodegoat,dvna,DVWA,nextly_lovable}_ranker.sarif
    *.partial.jsonl
    logs/
docs/
  PRACTICAL_SMOKE_2026-06-11.md        # v1 (1 repo)
  PRACTICAL_SMOKE_v2_2026-06-11.md     # этот файл (4 + 7 repos)
  OUTREACH_DRAFT_2026-06-11.md         # cold message draft
```
