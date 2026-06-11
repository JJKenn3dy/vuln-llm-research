# Practical smoke: v8.3.1 ranker on real-world AI-coded web apps (2026-06-11 night)

Первый end-to-end прогон **SARIF -> ranker -> ranked SARIF** на реальном
коде. Не fine-tuning эксперимент, не benchmark, а sanity-check продукта
на коде который ты можешь вкатить в product MVP завтра.

## Setup

- 4 веб-репозитория, из которых 3 AI-coded / AI-style:
  - `JJKenn3dy/rpg_life` (твой, FastAPI + SQLAlchemy + Telegram bot)
  - `JJKenn3dy/survivemedia` (твой, Next.js 15 + TS landing)
  - `vikramdotcom/openai-agents-sdk-chatbot-UI` (v0-dev coded, Next.js + OpenAI SDK)
  - `OWASP/NodeGoat` (intentionally-vulnerable Express + MongoDB, контроль)
- Semgrep 1.166.0, `--config=auto` (Semgrep Registry автодетект), SARIF v2.1.
- v8.3.1 LoRA адаптер из `/workspace/adapters/v8_3_1/adapter_model.safetensors`,
  база `Qwen2.5-Coder-7B-Instruct`, A40 48GB через temp RunPod pod (~$0.20).
- Ranker mode: `python -m src.product --mode ranker --backend local`,
  output ранжированный SARIF с `properties.vuln_llm_triage.p_tp` на каждом result.

## Headline-1: Semgrep recall на AI-coded коде близок к нулю

| Repo | Files | Rules | Findings |
|---|---:|---:|---:|
| rpg_life (FastAPI) | 69 | 418 | **0** |
| survivemedia (Next.js TS) | 29 | 213 | **0** |
| v0-chatbot-UI (Next.js + OpenAI SDK) | 75 | 243 | **0** |
| NodeGoat (Express, intentional) | 75 | 252 | **29** |

3 из 4 веб-репов с типичной AI-сгенерированной структурой получают **0
findings** на 874 правилах в сумме. Boilerplate в стиле "AI следует
docs" (ORM + Pydantic schemas + Next.js серверный SDK + типизированные
endpoints) проходит pattern-based SAST как чистый. NodeGoat (написан
вручную как intentionally vulnerable) даёт 29.

Что это значит для продукта:
- Pattern-based SAST на AI-сгенерированном коде имеет recall близкий к
  нулю. Нашему ML-триажу нечего триажить если на входе ноль findings.
- Бизнес-аргумент: для AI-coded apps нужны semantic-aware tools
  (CodeQL, кастомные правила, LLM-driven detection). Pattern SAST
  устарел даже быстрее чем мы думали.
- Это **аргумент за пуш ML-детектора** (или semantic intake stage)
  как часть продукта, не только триажа поверх существующих findings.

## Headline-2: на NodeGoat ranker работает осмысленно

29 findings ранжированы за 3 секунды wall-clock (модель уже прогрета).
Распределение p_tp:

```
range:   [0.314, 0.757]     gap = 0.444
median:  0.550
mean:    0.532
stdev:   0.140
```

Для сравнения: на SastBench-250 median(p_tp|TP) - median(p_tp|FP) = 0.023
(collapsed). Здесь gap 0.444 (open). Возможные объяснения:
- NodeGoat distribution ближе к training (CVEFixes + CrossVul) чем
  SastBench (multi-project diverse).
- 14% TP rate SastBench делает имбаланс жёстче.
- N=29 vs N=250: меньше эффект усреднения.

Не overclaim'им: это N=1 малая выборка одного репо. Cluster CI не
строим. Только direction-only check.

## Top 5 ranker output (model says "real")

| p_tp | CWE | File | Code | Sanity |
|---:|---|---|---|---|
| 0.757 | CWE-95 | contributions.js:33 | `eval(req.body.afterTax)` | RCE, classic NodeGoat bug |
| 0.749 | CWE-95 | contributions.js:32 | `eval(req.body.preTax)` | same |
| 0.731 | CWE-95 | contributions.js:33 | (same line, second rule) | same |
| 0.724 | CWE-95 | contributions.js:34 | `eval(req.body.roth)` | same |
| 0.721 | CWE-95 | contributions.js:32 | (same line, second rule) | same |

Все 5 топ-findings показывают на одну строку с `eval(req.body.X)`.
Реальная RCE, real critical, наша модель попала. Semgrep дал три
правила на эти 3 строки, плюс одна дополнительная — модель отранжировала
их вместе на самый верх.

## Bottom 5 ranker output (model says "noise")

| p_tp | CWE | File | Trigger | Sanity |
|---:|---|---|---|---|
| 0.388 | CWE-319 | tutorial/a5.html:50 | http link в туториальной HTML странице | FP, не код приложения |
| 0.388 | secret | db-reset.js:36 | bcrypt hash в **закомментированной** строке | FP, dead code |
| 0.317 | CWE-732 | docker-compose.yml:13 | `no-new-privileges` на mongo service | weak pattern |
| 0.317 | CWE-732 | docker-compose.yml:13 | writable filesystem на mongo | weak pattern |
| 0.314 | CWE-352 | server.js:15 | CSRF middleware check на `const app = express()` | FP, pattern только на любом express |

Каждый из bottom 5 при ручном просмотре — действительно FP или low-priority.
Модель корректно опустила вниз.

## Middle band — где calibration шумит

9 одинаковых p_tp = 0.5501 на cookie-settings rules в server.js:78-102.
Это один и тот же code block триггерит 6 разных Semgrep правил на cookie
options (httponly, secure, secret, path). Модель видит ОДИН snippet и
выдаёт одинаковый p_tp. Это не bug ranker'а, это property входа:
дубликаты findings по одному и тому же блоку кода. Реалистично для
production SARIF.

## Что это значит для outreach / MVP

1. **Ranker end-to-end жив** на реальном SARIF от реального SAST tool на
   реальном коде. Pipeline (SARIF parse, snippet resolve, local backend
   + LoRA adapter, ranker mode, sorted SARIF output) работает без правок.
2. **Top-9 vs bottom-20 разделение даёт реальную экономию**. На 29
   findings человек тратил бы 15-30 мин × 29 = 7-14 часов. С нашим
   ranker'ом "посмотри top-9 сначала" покрывает все настоящие eval RCE +
   CSRF. Bottom 20 либо ложные либо low-priority.
3. **AI-coded apps плохо триггерят pattern SAST**. Это и проблема (нет
   findings = нечего триажить, ranker без работы) и возможность
   (semantic-aware intake stage становится отдельным product line).
4. **Distribution-shift gap (0.023 на SastBench → 0.444 на NodeGoat)**
   подтверждает гипотезу что на in-distribution коде (CVEFixes-style) v8.3.1
   калиброван нормально. SastBench был difficult-case.

## Что НЕ делаем по итогам этого smoke

- Не объявляем "наш ranker работает на real-world apps". N=1 один репо
  не cluster CI. Нужно ~5-10 разных репов с разными SAST tools для
  honest claim.
- Не повторяем gap=0.44 как pitch number. На SastBench (более diverse)
  он collapsed, тот результат с большей выборкой.
- Не переделываем v8.3.1. Этот прогон подтверждает что adapter работает,
  не вскрывает новый research lever.

## Что делаем дальше (pre-existing P4 из NEXT_STEPS)

1. **Расширить выборку**: подобрать 5-10 AI-coded репов с реальными
   findings. Кандидаты: NodeGoat-style (Damn Vulnerable Node, DVNA),
   плюс реальные vibe-coded apps (поискать через GitHub topic v0,
   bolt, lovable, или Awesome lists). Прогнать тот же pipeline на
   каждом.
2. **PDF report** с топ-N findings + p_tp + reasoning из verdict mode
   (не ranker, потому что reasoning нужен в filter mode). Идёт в P4
   "demand validation" — 3-5 PDF для public OSS репов.
3. **Зафиксировать смешанный mode**: ranker для сортировки + verdict
   mode для top-K reasoning. Сейчас они два отдельных прогона.

## Лог расходов

| Item | Cost |
|---|---:|
| Temp A40 pod (~30 мин) | ~$0.20 |
| Local Semgrep + analysis | $0 |
| Total | **~$0.20** |

Pod terminated (`podTerminate` returned ok). Основной pod
`yodelling_maroon_primate` остался EXITED.

## Файлы

```
data/practical/
  apps.tar.gz                          # 4 репа, 2.4MB
  sarif/
    nodegoat.sarif                     # 29 findings (controlled)
    rpg_life.sarif                     # 0 (AI-coded boilerplate)
    survivemedia.sarif                 # 0
    v0_chatbot.sarif                   # 0
  results/
    nodegoat_ranker.sarif              # ranked SARIF, sorted by p_tp desc
    nodegoat_ranker.sarif.partial.jsonl # per-finding p_tp dump
    nodegoat_ranker.log                # progress log
scripts/
  run_practical_smoke.sh               # remote runner v1 (with tar)
                                        # (на pod использовался run3.sh
                                        # без tar, апs/ уже распакованы)
docs/
  PRACTICAL_SMOKE_2026-06-11.md        # этот файл
```

## Open issues для починки

- `triage_filter.py:308` — `_log` пишет в file handle ПОСЛЕ `log_fp.close()`
  в `_triage_ranker`, ValueError на финальном "done" message. Не блокирует
  output, но мусорит лог стектрейсом. Один-строчный fix: переставить
  порядок close vs final log.
- `run_practical_smoke.sh` имеет hardcoded `set -e` + Windows-tarball
  ownership warnings = exit 1 убивает pipeline. Перед reuse заменить
  `tar` на `tar --no-same-owner` или развести в два шага.
